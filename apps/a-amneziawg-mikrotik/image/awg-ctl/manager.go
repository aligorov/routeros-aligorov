package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultCmdTimeout  = 25 * time.Second
	defaultShowTimeout = 5 * time.Second
	defaultIPTimeout   = 10 * time.Second
)

var validConfNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}\.conf$`)

type PeerStatus struct {
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint"`
	AllowedIPs          string `json:"allowed_ips"`
	LatestHandshakeUnix int64  `json:"latest_handshake_unix"`
	HandshakeAgeSec     int64  `json:"handshake_age_sec"`
	RxBytes             uint64 `json:"rx_bytes"`
	TxBytes             uint64 `json:"tx_bytes"`
	PersistentKeepalive string `json:"persistent_keepalive"`
}

type InterfaceStatus struct {
	Name       string       `json:"name"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	Jc         string       `json:"jc"`
	Jmin       string       `json:"jmin"`
	Jmax       string       `json:"jmax"`
	S1         string       `json:"s1"`
	S2         string       `json:"s2"`
	H1         string       `json:"h1"`
	H2         string       `json:"h2"`
	H3         string       `json:"h3"`
	H4         string       `json:"h4"`
	Peers      []PeerStatus `json:"peers"`
}

type ConfigMeta struct {
	Name       string   `json:"name"`
	Interface  string   `json:"interface"`
	Active     bool     `json:"active"`
	Selected   bool     `json:"selected"`
	Primary    bool     `json:"primary"`
	Enabled    bool     `json:"enabled"`
	Disabled   bool     `json:"disabled,omitempty"`
	Priority   int      `json:"priority"`
	Table      string   `json:"table,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	ListenPort string   `json:"listen_port,omitempty"`
	Address    string   `json:"address,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	HasPostUp  bool     `json:"has_postup"`
	HasTable   bool     `json:"has_table"`
	StartError string   `json:"start_error,omitempty"`
}

type TunnelManager struct {
	mu          sync.Mutex
	opMu        sync.Mutex
	srcDir      string
	runDir      string
	lanIface    string
	autoRoute   bool
	killSwitch  bool
	multiTunnel bool
	allowHooks  bool
	order       []string
	disabled    map[string]bool
	started     []string
	primaryCfg  string
	ifaceTable  map[string]string
	ifaceMark   map[string]int
	startedAt   map[string]time.Time
	startErrors map[string]string
	applying    bool
	applyingOp  string
	logger      *RingLogger
	onChange    func()
	ipCmdFn     func(args ...string) error
	runCmdFn    func(ctx context.Context, name string, args ...string) (string, error)
	cmdTimeout  time.Duration

	epMu            sync.Mutex
	cachedEndpoints []string
	endpointsAt     time.Time
}

func NewTunnelManager(srcDir, runDir, lanIface string, autoRoute, killSwitch bool, logger *RingLogger) *TunnelManager {
	return &TunnelManager{
		srcDir:      srcDir,
		runDir:      runDir,
		lanIface:    lanIface,
		autoRoute:   autoRoute,
		killSwitch:  killSwitch,
		multiTunnel: envOr("AWG_MULTI_TUNNEL", "off") == "on",
		allowHooks:  envOr("AWG_ALLOW_HOOKS", "off") == "on",
		disabled:    map[string]bool{},
		ifaceTable:  map[string]string{},
		ifaceMark:   map[string]int{},
		startedAt:   map[string]time.Time{},
		startErrors: map[string]string{},
		logger:      logger,
		cmdTimeout:  defaultCmdTimeout,
		runCmdFn:    defaultRunCmdFn,
		ipCmdFn: func(args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), defaultIPTimeout)
			defer cancel()
			out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
			if err != nil {
				msg := strings.TrimSpace(string(out))
				if msg != "" {
					return fmt.Errorf("ip %s: %s (%w)", strings.Join(args, " "), msg, err)
				}
				return fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
			}
			return nil
		},
	}
}

func (m *TunnelManager) LanIface() string {
	return m.lanIface
}

func (m *TunnelManager) SetRuntimeOptions(autoRoute, killSwitch, multiTunnel bool) {
	m.mu.Lock()
	m.autoRoute = autoRoute
	m.killSwitch = killSwitch
	m.multiTunnel = multiTunnel
	m.mu.Unlock()
}

// SetAllowHooks updates whether .conf uploads with PreUp/PostUp/PreDown/PostDown are allowed.
func (m *TunnelManager) SetAllowHooks(allow bool) {
	m.mu.Lock()
	m.allowHooks = allow
	m.mu.Unlock()
}

func (m *TunnelManager) SetTunnelPlan(order, disabled []string) {
	m.mu.Lock()
	m.order = append([]string(nil), order...)
	dis := make(map[string]bool, len(disabled))
	for _, n := range disabled {
		n = strings.TrimSpace(n)
		if n != "" {
			dis[n] = true
		}
	}
	m.disabled = dis
	m.mu.Unlock()
}

// SeedFromEnv writes AWG_CONF_B64 or AWG_CONF if no *.conf exists in srcDir yet.
func (m *TunnelManager) SeedFromEnv() error {
	existing, _ := m.ListConfigs()
	if len(existing) > 0 {
		return nil
	}
	iface := envOr("AWG_IFACE", "awg0")
	if !validConfNameRe.MatchString(iface + ".conf") {
		iface = "awg0"
	}

	var content string
	if b64 := strings.TrimSpace(os.Getenv("AWG_CONF_B64")); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("invalid AWG_CONF_B64: %w", err)
		}
		content = string(raw)
	} else if raw := os.Getenv("AWG_CONF"); strings.TrimSpace(raw) != "" {
		content = strings.ReplaceAll(raw, `\n`, "\n")
	} else {
		return nil
	}

	content = normalizeLF(content)
	if err := os.MkdirAll(m.srcDir, 0o700); err == nil {
		dst := filepath.Join(m.srcDir, iface+".conf")
		if err := os.WriteFile(dst, []byte(content), 0o600); err != nil {
			m.logger.Logf("WARN: cannot persist env config to %s (%v), using %s", dst, err, m.runDir)
			if err2 := os.MkdirAll(m.runDir, 0o700); err2 != nil {
				return err2
			}
			return os.WriteFile(filepath.Join(m.runDir, iface+".conf"), []byte(content), 0o600)
		}
		m.logger.Logf("Seeded %s from environment", dst)
	}
	return nil
}

func normalizeLF(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

var interfaceOnlyKeys = map[string]bool{
	"privatekey": true, "listenport": true, "fwmark": true,
	"address": true, "dns": true, "mtu": true, "table": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true,
	"jc":         true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

// normalizeConfigSections moves [Interface]-only directives (such as PostUp,
// PostDown, Table, Address, DNS, MTU) back into [Interface] if they were pasted
// after a [Peer] header, preventing awg-quick from forwarding them to awg setconf.
func normalizeConfigSections(text string) string {
	lines := strings.Split(strings.TrimSuffix(normalizeLF(text), "\n"), "\n")
	var ifaceLines, restLines, misplaced []string
	section := ""
	seenIface := false

	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			lowSec := strings.ToLower(trimmed)
			if lowSec == "[interface]" {
				if !seenIface {
					seenIface = true
					section = "interface"
					ifaceLines = append(ifaceLines, l)
					continue
				}
				section = "interface"
				continue
			}
			section = "other"
			restLines = append(restLines, l)
			continue
		}

		if section != "interface" && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			if k, _, ok := strings.Cut(trimmed, "="); ok {
				key := strings.ToLower(strings.TrimSpace(k))
				if interfaceOnlyKeys[key] {
					misplaced = append(misplaced, l)
					continue
				}
			}
		}

		if section == "interface" {
			ifaceLines = append(ifaceLines, l)
		} else {
			restLines = append(restLines, l)
		}
	}

	if !seenIface {
		return normalizeLF(text)
	}
	var out []string
	out = append(out, ifaceLines...)
	out = append(out, misplaced...)
	out = append(out, restLines...)
	return normalizeLF(strings.Join(out, "\n"))
}

func (m *TunnelManager) ListConfigs() ([]ConfigMeta, error) {
	entries, err := os.ReadDir(m.srcDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	activeSet := map[string]bool{}
	if ifaces, err := m.ShowInterfaces(); err == nil {
		for _, i := range ifaces {
			activeSet[i.Name] = true
		}
	}

	m.mu.Lock()
	order := append([]string(nil), m.order...)
	disabled := make(map[string]bool, len(m.disabled))
	for k, v := range m.disabled {
		disabled[k] = v
	}
	primaryCfg := m.primaryCfg
	ifaceTable := make(map[string]string, len(m.ifaceTable))
	for k, v := range m.ifaceTable {
		ifaceTable[k] = v
	}
	startErrors := make(map[string]string, len(m.startErrors))
	for k, v := range m.startErrors {
		startErrors[k] = v
	}
	m.mu.Unlock()

	rank := make(map[string]int, len(order))
	for i, n := range order {
		rank[n] = i
	}

	activeName := m.GetActiveConfig()
	var out []ConfigMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.srcDir, e.Name()))
		if err != nil {
			continue
		}
		text := string(b)
		if !strings.Contains(text, "[Interface]") {
			continue
		}
		meta := parseConfigMeta(e.Name(), text)
		meta.Active = activeSet[meta.Interface]
		meta.Selected = (e.Name() == activeName)
		meta.Disabled = disabled[e.Name()]
		meta.Enabled = !meta.Disabled
		meta.Table = ifaceTable[meta.Interface]
		meta.StartError = startErrors[e.Name()]
		if primaryCfg != "" {
			meta.Primary = (e.Name() == primaryCfg) && meta.Active
		} else {
			meta.Primary = meta.Selected && meta.Active
		}
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, oki := rank[out[i].Name]
		rj, okj := rank[out[j].Name]
		if oki && okj && ri != rj {
			return ri < rj
		}
		if oki != okj {
			return oki
		}
		return out[i].Name < out[j].Name
	})
	prio := 1
	for idx := range out {
		if out[idx].Enabled {
			out[idx].Priority = prio
			prio++
		}
	}
	if activeName == "" && len(out) > 0 {
		out[0].Selected = true
	}
	return out, nil
}

// selectStartConfigs: by default only ONE profile runs (the selected/first enabled one).
// In Multi-Tunnel mode, all enabled configs start, with the selected active config placed FIRST (Primary -> table awg).
func selectStartConfigs(cfgs []ConfigMeta, active string, multi bool) []ConfigMeta {
	if len(cfgs) == 0 {
		return cfgs
	}
	enabled := make([]ConfigMeta, 0, len(cfgs))
	for _, c := range cfgs {
		if !c.Disabled {
			enabled = append(enabled, c)
		}
	}
	if !multi {
		for _, c := range cfgs {
			if c.Name == active {
				return []ConfigMeta{c}
			}
		}
		if len(enabled) > 0 {
			return enabled[:1]
		}
		return cfgs[:1]
	}
	if len(enabled) == 0 {
		enabled = cfgs
	}
	var ordered []ConfigMeta
	for _, c := range enabled {
		if c.Name == active {
			ordered = append(ordered, c)
		}
	}
	for _, c := range enabled {
		if c.Name != active {
			ordered = append(ordered, c)
		}
	}
	return ordered
}

func (m *TunnelManager) activeFilePath() string {
	return filepath.Join(m.srcDir, ".active")
}

func (m *TunnelManager) GetActiveConfig() string {
	b, err := os.ReadFile(m.activeFilePath())
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(b))
	if !validConfNameRe.MatchString(name) {
		return ""
	}
	if _, err := os.Stat(filepath.Join(m.srcDir, name)); err != nil {
		return ""
	}
	return name
}

func (m *TunnelManager) SetActiveConfig(name string) error {
	if !validConfNameRe.MatchString(name) {
		return fmt.Errorf("invalid config filename %q", name)
	}
	if _, err := os.Stat(filepath.Join(m.srcDir, name)); err != nil {
		return fmt.Errorf("config %s not found", name)
	}
	return os.WriteFile(m.activeFilePath(), []byte(name+"\n"), 0o600)
}

func (m *TunnelManager) setApplying(active bool, op string) {
	m.mu.Lock()
	m.applying = active
	m.applyingOp = op
	m.mu.Unlock()
}

// ApplyingState reports whether a tunnel lifecycle operation (start/stop/restart/switch)
// is currently in progress, along with its human-readable label.
func (m *TunnelManager) ApplyingState() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applying, m.applyingOp
}

func (m *TunnelManager) invalidateEndpointsCache() {
	m.epMu.Lock()
	m.endpointsAt = time.Time{}
	m.epMu.Unlock()
}

func (m *TunnelManager) ActivateConfig(name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.activateConfigOp(name)
}

func (m *TunnelManager) activateConfigOp(name string) error {
	if err := m.SetActiveConfig(name); err != nil {
		return err
	}
	m.logger.Logf("Switched active profile to %s", name)
	// Fast hot-switch in Multi-Tunnel mode when target interface is already UP
	m.mu.Lock()
	multi := m.multiTunnel
	hasStarted := len(m.started) > 0
	m.mu.Unlock()
	if multi && hasStarted {
		targetIface := strings.TrimSuffix(name, ".conf")
		if ifaces, err := m.ShowInterfaces(); err == nil {
			for _, ifc := range ifaces {
				if ifc.Name == targetIface {
					if err := m.switchPrimaryFastOp(name); err == nil {
						return nil
					}
					break
				}
			}
		}
	}
	return m.restartAllOp()
}

// ApplySavedConfig sets name as active and reloads tunnels so edits in the saved .conf
// (such as Endpoint, keys, or AllowedIPs) take effect immediately.
func (m *TunnelManager) ApplySavedConfig(name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if err := m.SetActiveConfig(name); err != nil {
		return err
	}
	m.logger.Logf("Applying saved profile %s", name)
	return m.restartAllOp()
}

// ApplySyncedConfig reloads tunnels after a subscription sync without stealing Primary
// from an already-selected active profile when Multi-Tunnel mode is enabled.
func (m *TunnelManager) ApplySyncedConfig(name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	multi := m.multiTunnel
	m.mu.Unlock()
	if !multi || m.GetActiveConfig() == "" {
		if err := m.SetActiveConfig(name); err != nil {
			return err
		}
	}
	m.logger.Logf("Applying synced profile %s (active=%s)", name, m.GetActiveConfig())
	return m.restartAllOp()
}

// SwitchPrimaryFast switches Primary routing (table awg -> new interface) in <100ms
// without tearing down running tunnels in Multi-Tunnel / Hot-Standby mode.
func (m *TunnelManager) SwitchPrimaryFast(name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.switchPrimaryFastOp(name)
}

func (m *TunnelManager) switchPrimaryFastOp(name string) error {
	if err := m.SetActiveConfig(name); err != nil {
		return err
	}
	targetIface := strings.TrimSuffix(name, ".conf")
	m.mu.Lock()
	autoRoute := m.autoRoute
	killSwitch := m.killSwitch
	lanIface := m.lanIface
	ipCmd := m.ipCmdFn
	prevPrimary := m.primaryCfg
	m.primaryCfg = name
	if m.ifaceTable == nil {
		m.ifaceTable = map[string]string{}
	}
	for k, v := range m.ifaceTable {
		if v == "awg" && k != targetIface {
			// Clear stale "awg" label from previous primary; its own probe table remains active
			delete(m.ifaceTable, k)
		}
	}
	m.ifaceTable[targetIface] = "awg"
	m.mu.Unlock()

	if autoRoute && ipCmd != nil {
		if err := ipCmd("route", "replace", "default", "dev", targetIface, "table", "awg"); err != nil {
			m.mu.Lock()
			m.primaryCfg = prevPrimary
			m.mu.Unlock()
			return err
		}
		if killSwitch {
			_ = ipCmd("route", "replace", "blackhole", "default", "table", "awg", "metric", "254")
		}
		if lanIface != "" {
			_ = ipCmd("rule", "del", "priority", "300")
			_ = ipCmd("rule", "add", "priority", "300", "from", "all", "iif", lanIface, "lookup", "awg")
		}
	}
	m.logger.Logf("Primary tunnel fast-switched to %s (iface=%s)", name, targetIface)
	if m.onChange != nil {
		go m.onChange()
	}
	return nil
}

func (m *TunnelManager) PrimaryInterface() string {
	ifaces, err := m.ShowInterfaces()
	if err != nil || len(ifaces) == 0 {
		return ""
	}
	up := make(map[string]bool, len(ifaces))
	for _, i := range ifaces {
		up[i.Name] = true
	}
	m.mu.Lock()
	pcfg := m.primaryCfg
	m.mu.Unlock()
	if pcfg != "" {
		pifc := strings.TrimSuffix(pcfg, ".conf")
		if up[pifc] {
			return pifc
		}
	}
	if active := m.GetActiveConfig(); active != "" {
		aifc := strings.TrimSuffix(active, ".conf")
		if up[aifc] {
			return aifc
		}
	}
	return ifaces[0].Name
}

func (m *TunnelManager) ProbeMarkForInterface(iface string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mk := m.ifaceMark[iface]; mk != 0 {
		return mk
	}
	if tbl := m.ifaceTable[iface]; tbl == "awg" {
		return ProxyDNSFwmark
	}
	return 0
}

func (m *TunnelManager) InterfaceStartedAt(iface string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startedAt[iface]
}

func (m *TunnelManager) DetectConflicts(cfgs []ConfigMeta) []string {
	var warnings []string
	ports := map[string]string{}
	addrs := map[string]string{}
	eps := map[string]string{}
	for _, c := range cfgs {
		if c.Disabled {
			continue
		}
		if c.ListenPort != "" && c.ListenPort != "0" {
			if prev, ok := ports[c.ListenPort]; ok {
				warnings = append(warnings, fmt.Sprintf("Одинаковый ListenPort %s в %s и %s — в Multi-Tunnel один не запустится", c.ListenPort, prev, c.Name))
			} else {
				ports[c.ListenPort] = c.Name
			}
		}
		if c.Address != "" {
			ipOnly := strings.Split(strings.TrimSpace(c.Address), ",")[0]
			if prev, ok := addrs[ipOnly]; ok {
				warnings = append(warnings, fmt.Sprintf("Совпадает локальный Address (%s) у %s и %s", ipOnly, prev, c.Name))
			} else {
				addrs[ipOnly] = c.Name
			}
		}
		if c.Endpoint != "" {
			if prev, ok := eps[c.Endpoint]; ok {
				warnings = append(warnings, fmt.Sprintf("Одинаковый Endpoint %s в %s и %s (если отказ провайдера/сервера, упадут оба)", c.Endpoint, prev, c.Name))
			} else {
				eps[c.Endpoint] = c.Name
			}
		}
	}
	return warnings
}

func parseConfigMeta(name, text string) ConfigMeta {
	meta := ConfigMeta{
		Name:      name,
		Interface: strings.TrimSuffix(name, ".conf"),
		Enabled:   true,
	}
	for _, line := range strings.Split(normalizeLF(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "address":
			meta.Address = val
		case "listenport":
			meta.ListenPort = val
		case "endpoint":
			meta.Endpoint = val
		case "dns":
			for _, part := range strings.Split(val, ",") {
				p := strings.TrimSpace(part)
				if p != "" {
					meta.DNS = append(meta.DNS, p)
				}
			}
		case "allowedips":
			for _, part := range strings.Split(val, ",") {
				p := strings.TrimSpace(part)
				if p != "" {
					meta.AllowedIPs = append(meta.AllowedIPs, p)
				}
			}
		case "postup":
			meta.HasPostUp = true
		case "table":
			meta.HasTable = true
		}
	}
	return meta
}

func (m *TunnelManager) ReadConfig(name string) (string, error) {
	if !validConfNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid config filename %q (allowed: [a-zA-Z0-9_-]{1,15}.conf)", name)
	}
	b, err := os.ReadFile(filepath.Join(m.srcDir, name))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ExtractConfigHooks returns unique awg-quick/wg-quick lifecycle hook keys found in a config.
func ExtractConfigHooks(content string) []string {
	seen := map[string]bool{}
	var found []string
	for _, rawLine := range strings.Split(normalizeLF(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		lower := strings.ToLower(key)
		switch lower {
		case "preup", "postup", "predown", "postdown":
			if !seen[lower] {
				seen[lower] = true
				found = append(found, key)
			}
		}
	}
	return found
}

// ValidateConfig performs fast structural validation on a WireGuard/AmneziaWG .conf
// before saving so malformed entries (such as Endpoint = ip:port:port) fail immediately
// instead of hanging awg-quick/awg setconf DNS retries.
func ValidateConfig(content string) error {
	clean := normalizeLF(content)
	hasInterface := false
	for i, rawLine := range strings.Split(clean, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if end := strings.IndexByte(line, ']'); end > 1 {
				if strings.EqualFold(strings.TrimSpace(line[1:end]), "Interface") {
					hasInterface = true
				}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		ln := i + 1
		switch key {
		case "endpoint":
			if err := validateEndpoint(val); err != nil {
				return fmt.Errorf("line %d: %w", ln, err)
			}
		case "listenport", "mtu":
			if val != "" {
				minVal := 1
				if key == "mtu" {
					minVal = 68
				}
				n, err := strconv.Atoi(val)
				if err != nil || n < minVal || n > 65535 {
					return fmt.Errorf("line %d: invalid %s %q (must be %d..65535)", ln, strings.TrimSpace(k), val, minVal)
				}
			}
		case "address", "allowedips":
			if val != "" {
				if err := validateCIDRList(strings.TrimSpace(k), val); err != nil {
					return fmt.Errorf("line %d: %w", ln, err)
				}
			}
		}
	}
	if !hasInterface {
		return fmt.Errorf("config must contain [Interface] section")
	}
	return nil
}

func validateEndpoint(val string) error {
	if val == "" {
		return fmt.Errorf("Endpoint must not be empty")
	}
	if strings.ContainsAny(val, " \t") {
		return fmt.Errorf("invalid Endpoint %q: unexpected whitespace", val)
	}
	host, portStr, err := net.SplitHostPort(val)
	if err != nil || host == "" {
		return fmt.Errorf("invalid Endpoint %q: expected host:port or [ipv6]:port (e.g. 1.2.3.4:51820)", val)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid Endpoint %q: port %q must be 1..65535", val, portStr)
	}
	return nil
}

func validateCIDRList(field, val string) error {
	for _, p := range strings.Split(val, ",") {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		if _, err := netip.ParsePrefix(item); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(item); err == nil {
			continue
		}
		return fmt.Errorf("invalid %s entry %q (expected IP or CIDR)", field, item)
	}
	return nil
}

func (m *TunnelManager) SaveConfig(name, content string) error {
	if !validConfNameRe.MatchString(name) {
		return fmt.Errorf("invalid config filename %q (allowed: [a-zA-Z0-9_-]{1,15}.conf)", name)
	}
	clean := normalizeLF(content)
	if err := ValidateConfig(clean); err != nil {
		return err
	}
	if hooks := ExtractConfigHooks(clean); len(hooks) > 0 {
		m.mu.Lock()
		allowHooks := m.allowHooks
		m.mu.Unlock()
		if !allowHooks {
			return fmt.Errorf("shell hooks (%s) in .conf are disabled by security policy (enable allow_config_hooks in Settings or AWG_ALLOW_HOOKS=on)", strings.Join(hooks, ", "))
		}
	}
	if err := os.MkdirAll(m.srcDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.srcDir, name), []byte(clean), 0o600); err != nil {
		return err
	}
	m.invalidateEndpointsCache()
	return nil
}

func (m *TunnelManager) DeleteConfig(name string) error {
	if !validConfNameRe.MatchString(name) {
		return fmt.Errorf("invalid config filename %q", name)
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.setApplying(true, "Удаление "+name)
	defer m.setApplying(false, "")

	runPath := filepath.Join(m.runDir, name)
	if _, err := os.Stat(runPath); err == nil {
		_ = m.runCmd("/usr/bin/awg-quick", "down", runPath)
		_ = os.Remove(runPath)
	}
	iface := strings.TrimSuffix(name, ".conf")
	m.mu.Lock()
	filtered := m.started[:0]
	for _, p := range m.started {
		if p != runPath {
			filtered = append(filtered, p)
		}
	}
	m.started = filtered
	if m.primaryCfg == name {
		m.primaryCfg = ""
	}
	delete(m.startedAt, iface)
	delete(m.ifaceTable, iface)
	delete(m.ifaceMark, iface)
	delete(m.startErrors, name)
	m.mu.Unlock()

	err := os.Remove(filepath.Join(m.srcDir, name))
	m.invalidateEndpointsCache()
	if m.onChange != nil {
		go m.onChange()
	}
	return err
}

func (m *TunnelManager) injectAutoRoute(text string, table string, primary bool) string {
	text = normalizeConfigSections(text)
	if !m.autoRoute || m.lanIface == "" {
		return text
	}
	meta := parseConfigMeta("tmp.conf", text)
	if meta.HasTable {
		return text
	}

	var lines []string
	lines = append(lines,
		"PostUp = iptables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %i -j MASQUERADE",
		"PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE || true",
		"PostUp = iptables -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true",
		"PostUp = ip6tables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o %i -j MASQUERADE 2>/dev/null || true",
		"PostDown = ip6tables -t nat -D POSTROUTING -o %i -j MASQUERADE 2>/dev/null || true",
		"PostUp = ip6tables -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
		"PostDown = ip6tables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
	)
	if table != "" {
		lines = append(lines, "Table = "+table)
	}
	if primary {
		lines = append(lines,
			fmt.Sprintf("PostUp = ip rule add priority 300 from all iif %s lookup %s || true", m.lanIface, table),
			fmt.Sprintf("PostDown = ip rule del priority 300 from all iif %s lookup %s || true", m.lanIface, table),
			fmt.Sprintf("PostUp = ip -6 rule add priority 300 from all iif %s lookup %s 2>/dev/null || true", m.lanIface, table),
			fmt.Sprintf("PostDown = ip -6 rule del priority 300 from all iif %s lookup %s 2>/dev/null || true", m.lanIface, table),
		)
		if m.killSwitch {
			lines = append(lines,
				fmt.Sprintf("PostUp = ip route show table %s | grep -q \"blackhole\" || ip route add blackhole default table %s metric 254 || true", table, table),
				fmt.Sprintf("PostUp = ip -6 route show table %s 2>/dev/null | grep -q \"blackhole\" || ip -6 route add blackhole default table %s metric 254 2>/dev/null || true", table, table),
			)
		}
	}

	block := strings.Join(lines, "\n")
	rawLines := strings.Split(normalizeLF(text), "\n")
	var out []string
	inserted := false
	for _, l := range rawLines {
		out = append(out, l)
		if !inserted && strings.TrimSpace(l) == "[Interface]" {
			out = append(out, block)
			inserted = true
		}
	}
	return strings.Join(out, "\n")
}

func (m *TunnelManager) StartAll() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.startAllOp()
}

func (m *TunnelManager) startAllOp() error {
	m.setApplying(true, "Запуск профилей")
	defer m.setApplying(false, "")

	if err := os.MkdirAll(m.runDir, 0o700); err != nil {
		return err
	}
	// Clean stale runtime files
	if old, err := os.ReadDir(m.runDir); err == nil {
		for _, e := range old {
			if strings.HasSuffix(e.Name(), ".conf") {
				_ = os.Remove(filepath.Join(m.runDir, e.Name()))
			}
		}
	}

	configs, err := m.ListConfigs()
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		m.logger.Logf("No *.conf found in %s; waiting for config via WebUI or AWG_CONF_B64", m.srcDir)
		return nil
	}

	m.mu.Lock()
	multi := m.multiTunnel
	autoRoute := m.autoRoute
	ipCmd := m.ipCmdFn
	m.started = nil
	m.primaryCfg = ""
	m.ifaceTable = map[string]string{}
	m.ifaceMark = map[string]int{}
	m.startedAt = map[string]time.Time{}
	m.startErrors = map[string]string{}
	m.mu.Unlock()

	target := selectStartConfigs(configs, m.GetActiveConfig(), multi)
	var firstErr error
	startedCount := 0
	for _, cfg := range target {
		m.setApplying(true, "Запуск "+cfg.Name)
		srcBytes, err := os.ReadFile(filepath.Join(m.srcDir, cfg.Name))
		if err != nil {
			m.mu.Lock()
			m.startErrors[cfg.Name] = err.Error()
			m.mu.Unlock()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		isPrimary := (startedCount == 0)
		probeNum := 201 + startedCount
		table := "awg"
		if !isPrimary {
			table = strconv.Itoa(probeNum)
		}
		prepared := m.injectAutoRoute(normalizeLF(string(srcBytes)), table, isPrimary)
		runPath := filepath.Join(m.runDir, cfg.Name)
		if err := os.WriteFile(runPath, []byte(prepared), 0o600); err != nil {
			m.mu.Lock()
			m.startErrors[cfg.Name] = err.Error()
			m.mu.Unlock()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if autoRoute && ipCmd != nil {
			_ = ipCmd("route", "flush", "table", table)
			_ = ipCmd("-6", "route", "flush", "table", table)
		}
		m.logger.Logf("Starting %s (table=%s, primary=%v)...", cfg.Name, table, isPrimary)
		if err := m.runCmd("/usr/bin/awg-quick", "up", runPath); err != nil {
			m.mu.Lock()
			m.startErrors[cfg.Name] = err.Error()
			m.mu.Unlock()
			m.logger.Logf("ERROR starting %s: %v", cfg.Name, err)
			_ = m.runCmd("/usr/bin/awg-quick", "down", runPath)
			if firstErr == nil {
				firstErr = fmt.Errorf("awg-quick up %s: %w", cfg.Name, err)
			}
			if !multi {
				m.stopStartedOp()
				return firstErr
			}
			continue
		}
		now := time.Now()
		var probeTbl, markHex string
		var probeMark int
		m.mu.Lock()
		m.started = append(m.started, runPath)
		m.startedAt[cfg.Interface] = now
		m.ifaceTable[cfg.Interface] = table
		if isPrimary {
			m.primaryCfg = cfg.Name
		}
		// Install dedicated per-tunnel probe table + fwmark (0x201, 0x202, ...) when Multi-Tunnel is active
		// so health probes always traverse THAT exact tunnel even if table "awg" swaps to another primary.
		if multi && ipCmd != nil {
			probeTbl = strconv.Itoa(probeNum)
			probeMark = 0x201 + startedCount
			m.ifaceMark[cfg.Interface] = probeMark
			markHex = fmt.Sprintf("0x%x", probeMark)
		}
		m.mu.Unlock()
		if probeMark != 0 && ipCmd != nil {
			_ = ipCmd("route", "replace", "default", "dev", cfg.Interface, "table", probeTbl)
			_ = ipCmd("rule", "del", "priority", "241", "from", "all", "fwmark", markHex, "lookup", probeTbl)
			_ = ipCmd("rule", "add", "priority", "241", "from", "all", "fwmark", markHex, "lookup", probeTbl)
		}
		startedCount++
	}

	if startedCount == 0 && firstErr != nil {
		return firstErr
	}
	if m.onChange != nil {
		go m.onChange()
	}
	return nil
}

func (m *TunnelManager) StopAll() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stopStartedOp()
	if m.onChange != nil {
		go m.onChange()
	}
}

func (m *TunnelManager) stopStartedOp() {
	m.setApplying(true, "Остановка туннелей")
	defer m.setApplying(false, "")

	m.mu.Lock()
	ipCmd := m.ipCmdFn
	marks := make(map[string]int, len(m.ifaceMark))
	for k, v := range m.ifaceMark {
		marks[k] = v
	}
	started := append([]string(nil), m.started...)
	m.ifaceMark = map[string]int{}
	m.started = nil
	m.primaryCfg = ""
	m.ifaceTable = map[string]string{}
	m.startedAt = map[string]time.Time{}
	m.mu.Unlock()

	for _, mk := range marks {
		if ipCmd != nil && mk >= 0x201 {
			tbl := strconv.Itoa(mk - 0x200 + 200)
			_ = ipCmd("rule", "del", "priority", "241", "from", "all", "fwmark", fmt.Sprintf("0x%x", mk), "lookup", tbl)
			_ = ipCmd("route", "flush", "table", tbl)
		}
	}
	for i := len(started) - 1; i >= 0; i-- {
		p := started[i]
		m.logger.Logf("Stopping %s...", p)
		if err := m.runCmd("/usr/bin/awg-quick", "down", p); err != nil {
			m.logger.Logf("WARN: awg-quick down %s: %v", p, err)
		}
	}
}

func (m *TunnelManager) RestartAll() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.restartAllOp()
}

func (m *TunnelManager) restartAllOp() error {
	m.stopStartedOp()
	err := m.startAllOp()
	if err != nil && m.onChange != nil {
		go m.onChange()
	}
	return err
}

func (m *TunnelManager) runCmd(name string, args ...string) error {
	timeout := m.cmdTimeout
	if timeout <= 0 {
		timeout = defaultCmdTimeout
	}
	runner := m.runCmdFn
	if runner == nil {
		runner = defaultRunCmdFn
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := runner(ctx, name, args...)
	if trimmed := strings.TrimSpace(out); trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			m.logger.Logf("%s: %s", filepath.Base(name), line)
		}
	}
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s %s timed out after %s: %w", filepath.Base(name), strings.Join(args, " "), timeout, ctx.Err())
	}
	return err
}

func defaultRunCmdFn(ctx context.Context, name string, args ...string) (string, error) {
	// Write output to a regular file instead of a Go pipe so backgrounded
	// amneziawg-go daemons inheriting stdout/stderr do not block cmd.Run().
	logFile, err := os.CreateTemp("", "awg-cmd-*.log")
	if err != nil {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return "", cmd.Run()
	}
	logPath := logFile.Name()
	defer os.Remove(logPath)

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Kill the whole process group only if ctx timed out / canceled mid-command.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	runErr := cmd.Run()
	_ = logFile.Close()

	if data, readErr := os.ReadFile(logPath); readErr == nil {
		return string(data), runErr
	}
	return "", runErr
}

func (m *TunnelManager) ShowInterfaces() ([]InterfaceStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultShowTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/awg", "show", "all", "dump").Output()
	if err != nil {
		return nil, err
	}
	return parseAwgDump(string(out), time.Now().Unix()), nil
}

func parseAwgDump(raw string, nowUnix int64) []InterfaceStatus {
	byName := map[string]*InterfaceStatus{}
	var order []string

	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 15 {
			name := fields[0]
			port, _ := strconv.Atoi(fields[3])
			st := &InterfaceStatus{
				Name:       name,
				PublicKey:  fields[2],
				ListenPort: port,
				Jc:         fields[4],
				Jmin:       fields[5],
				Jmax:       fields[6],
				S1:         fields[7],
				S2:         fields[8],
				H1:         fields[11],
				H2:         fields[12],
				H3:         fields[13],
				H4:         fields[14],
			}
			byName[name] = st
			order = append(order, name)
		} else if len(fields) == 9 {
			name := fields[0]
			st, ok := byName[name]
			if !ok {
				continue
			}
			hs, _ := strconv.ParseInt(fields[5], 10, 64)
			rx, _ := strconv.ParseUint(fields[6], 10, 64)
			tx, _ := strconv.ParseUint(fields[7], 10, 64)
			var age int64 = -1
			if hs > 0 && nowUnix >= hs {
				age = nowUnix - hs
			}
			st.Peers = append(st.Peers, PeerStatus{
				PublicKey:           fields[1],
				Endpoint:            fields[3],
				AllowedIPs:          fields[4],
				LatestHandshakeUnix: hs,
				HandshakeAgeSec:     age,
				RxBytes:             rx,
				TxBytes:             tx,
				PersistentKeepalive: fields[8],
			})
		}
	}

	out := make([]InterfaceStatus, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out
}

func (m *TunnelManager) ActiveDNSServers() []string {
	cfgs, err := m.ListConfigs()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	addFrom := func(c ConfigMeta) {
		for _, d := range c.DNS {
			host := d
			if _, _, err := net.SplitHostPort(d); err != nil {
				host = net.JoinHostPort(d, "53")
			}
			if !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	for _, c := range cfgs {
		if c.Primary || (c.Selected && c.Active) {
			addFrom(c)
		}
	}
	for _, c := range cfgs {
		if c.Active {
			addFrom(c)
		}
	}
	if len(out) == 0 {
		for _, c := range cfgs {
			if c.Selected {
				addFrom(c)
			}
		}
	}
	return out
}

func (m *TunnelManager) AllNonDefaultAllowedIPs() map[string][]string {
	cfgs, err := m.ListConfigs()
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, c := range cfgs {
		if !c.Active {
			continue
		}
		var cidrs []string
		for _, cidr := range c.AllowedIPs {
			if cidr == "0.0.0.0/0" || cidr == "::/0" || cidr == "0.0.0.0/1" || cidr == "128.0.0.0/1" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				cidrs = append(cidrs, cidr)
			}
		}
		if len(cidrs) > 0 {
			out[c.Interface] = cidrs
		}
	}
	return out
}

// AllEndpoints returns cached WireGuard peer Endpoint strings across all configured tunnels.
func (m *TunnelManager) AllEndpoints() []string {
	m.epMu.Lock()
	if time.Since(m.endpointsAt) < 30*time.Second && m.endpointsAt != (time.Time{}) {
		out := append([]string(nil), m.cachedEndpoints...)
		m.epMu.Unlock()
		return out
	}
	m.epMu.Unlock()

	cfgs, err := m.ListConfigs()
	if err != nil {
		return nil
	}
	var eps []string
	seen := make(map[string]struct{}, len(cfgs))
	for _, c := range cfgs {
		ep := strings.TrimSpace(c.Endpoint)
		if ep == "" {
			continue
		}
		if _, ok := seen[ep]; ok {
			continue
		}
		seen[ep] = struct{}{}
		eps = append(eps, ep)
	}

	m.epMu.Lock()
	m.cachedEndpoints = eps
	m.endpointsAt = time.Now()
	out := append([]string(nil), eps...)
	m.epMu.Unlock()
	return out
}

func GenerateKeypair() (priv, pub, psk string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultIPTimeout)
	defer cancel()
	privB, err := exec.CommandContext(ctx, "/usr/bin/awg", "genkey").Output()
	if err != nil {
		return "", "", "", err
	}
	priv = strings.TrimSpace(string(privB))

	cmd := exec.CommandContext(ctx, "/usr/bin/awg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	pubB, err := cmd.Output()
	if err != nil {
		return "", "", "", err
	}
	pub = strings.TrimSpace(string(pubB))

	pskB, err := exec.CommandContext(ctx, "/usr/bin/awg", "genpsk").Output()
	if err != nil {
		return "", "", "", err
	}
	psk = strings.TrimSpace(string(pskB))
	return priv, pub, psk, nil
}

func randRange(min, max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return min
	}
	return min + n.Int64()
}

type AwgParams struct {
	Jc   int64 `json:"jc"`
	Jmin int64 `json:"jmin"`
	Jmax int64 `json:"jmax"`
	S1   int64 `json:"s1"`
	S2   int64 `json:"s2"`
	H1   int64 `json:"h1"`
	H2   int64 `json:"h2"`
	H3   int64 `json:"h3"`
	H4   int64 `json:"h4"`
}

func RandomAwgParams() AwgParams {
	s1 := randRange(15, 150)
	s2 := randRange(15, 150)
	// Ensure S1+56 != S2 (AmneziaWG requirement)
	if s1+56 == s2 {
		s2 += 1
	}
	return AwgParams{
		Jc:   randRange(4, 8),
		Jmin: 50,
		Jmax: 1000,
		S1:   s1,
		S2:   s2,
		H1:   randRange(100000000, 2147483000),
		H2:   randRange(100000000, 2147483000),
		H3:   randRange(100000000, 2147483000),
		H4:   randRange(100000000, 2147483000),
	}
}
