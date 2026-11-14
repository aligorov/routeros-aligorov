package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	ListenPort string   `json:"listen_port,omitempty"`
	Address    string   `json:"address,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	HasPostUp  bool     `json:"has_postup"`
	HasTable   bool     `json:"has_table"`
}

type TunnelManager struct {
	mu         sync.Mutex
	srcDir     string
	runDir     string
	lanIface   string
	autoRoute  bool
	killSwitch bool
	started    []string
	logger     *RingLogger
	onChange   func()
}

func NewTunnelManager(srcDir, runDir, lanIface string, autoRoute, killSwitch bool, logger *RingLogger) *TunnelManager {
	return &TunnelManager{
		srcDir:     srcDir,
		runDir:     runDir,
		lanIface:   lanIface,
		autoRoute:  autoRoute,
		killSwitch: killSwitch,
		logger:     logger,
	}
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
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
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
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if activeName == "" && len(out) > 0 {
		out[0].Selected = true
	}
	return out, nil
}

// selectStartConfigs: by default only ONE profile runs (the selected one).
// AWG_MULTI_TUNNEL=on keeps legacy behaviour (all *.conf up, first is primary).
func selectStartConfigs(cfgs []ConfigMeta, active string, multi bool) []ConfigMeta {
	if multi || len(cfgs) == 0 {
		return cfgs
	}
	for _, c := range cfgs {
		if c.Name == active {
			return []ConfigMeta{c}
		}
	}
	return cfgs[:1]
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

func (m *TunnelManager) ActivateConfig(name string) error {
	if err := m.SetActiveConfig(name); err != nil {
		return err
	}
	m.logger.Logf("Switched active profile to %s", name)
	return m.RestartAll()
}

func parseConfigMeta(name, text string) ConfigMeta {
	meta := ConfigMeta{
		Name:      name,
		Interface: strings.TrimSuffix(name, ".conf"),
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

func (m *TunnelManager) SaveConfig(name, content string) error {
	if !validConfNameRe.MatchString(name) {
		return fmt.Errorf("invalid config filename %q (allowed: [a-zA-Z0-9_-]{1,15}.conf)", name)
	}
	clean := normalizeLF(content)
	if !strings.Contains(clean, "[Interface]") {
		return fmt.Errorf("config must contain [Interface] section")
	}
	if err := os.MkdirAll(m.srcDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.srcDir, name), []byte(clean), 0o600)
}

func (m *TunnelManager) DeleteConfig(name string) error {
	if !validConfNameRe.MatchString(name) {
		return fmt.Errorf("invalid config filename %q", name)
	}
	m.mu.Lock()
	runPath := filepath.Join(m.runDir, name)
	if _, err := os.Stat(runPath); err == nil {
		_ = m.runCmd("/usr/bin/awg-quick", "down", runPath)
		_ = os.Remove(runPath)
	}
	m.mu.Unlock()
	err := os.Remove(filepath.Join(m.srcDir, name))
	if m.onChange != nil {
		m.onChange()
	}
	return err
}

func (m *TunnelManager) injectAutoRoute(text string, table string, primary bool) string {
	if !m.autoRoute || m.lanIface == "" {
		return text
	}
	meta := parseConfigMeta("tmp.conf", text)
	if meta.HasPostUp || meta.HasTable {
		return text
	}

	var lines []string
	lines = append(lines,
		"PostUp = iptables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %i -j MASQUERADE",
		"PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE || true",
		"PostUp = iptables -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true",
	)
	if table != "" {
		lines = append(lines, "Table = "+table)
	}
	if primary {
		lines = append(lines,
			fmt.Sprintf("PostUp = ip rule add priority 300 from all iif %s lookup %s || true", m.lanIface, table),
			fmt.Sprintf("PostDown = ip rule del priority 300 from all iif %s lookup %s || true", m.lanIface, table),
		)
		if m.killSwitch {
			lines = append(lines,
				fmt.Sprintf("PostUp = ip route show table %s | grep -q \"blackhole\" || ip route add blackhole default table %s metric 254 || true", table, table),
				fmt.Sprintf("PostUp = iptables -C FORWARD -i %s ! -o %%i -j DROP 2>/dev/null || iptables -A FORWARD -i %s ! -o %%i -j DROP", m.lanIface, m.lanIface),
				fmt.Sprintf("PostDown = iptables -D FORWARD -i %s ! -o %%i -j DROP || true", m.lanIface),
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
	m.mu.Lock()
	defer m.mu.Unlock()

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

	target := selectStartConfigs(configs, m.GetActiveConfig(), envOr("AWG_MULTI_TUNNEL", "off") == "on")
	m.started = nil
	for idx, cfg := range target {
		srcBytes, err := os.ReadFile(filepath.Join(m.srcDir, cfg.Name))
		if err != nil {
			return err
		}
		table := "awg"
		if idx > 0 {
			table = strconv.Itoa(200 + idx)
		}
		prepared := m.injectAutoRoute(normalizeLF(string(srcBytes)), table, idx == 0)
		runPath := filepath.Join(m.runDir, cfg.Name)
		if err := os.WriteFile(runPath, []byte(prepared), 0o600); err != nil {
			return err
		}
		m.logger.Logf("Starting %s (table=%s, primary=%v)...", cfg.Name, table, idx == 0)
		if err := m.runCmd("/usr/bin/awg-quick", "up", runPath); err != nil {
			m.stopStartedLocked()
			return fmt.Errorf("awg-quick up %s: %w", cfg.Name, err)
		}
		m.started = append(m.started, runPath)
	}
	if m.onChange != nil {
		go m.onChange()
	}
	return nil
}

func (m *TunnelManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopStartedLocked()
	if m.onChange != nil {
		go m.onChange()
	}
}

func (m *TunnelManager) stopStartedLocked() {
	for i := len(m.started) - 1; i >= 0; i-- {
		p := m.started[i]
		m.logger.Logf("Stopping %s...", p)
		if err := m.runCmd("/usr/bin/awg-quick", "down", p); err != nil {
			m.logger.Logf("WARN: awg-quick down %s: %v", p, err)
		}
	}
	m.started = nil
}

func (m *TunnelManager) RestartAll() error {
	m.StopAll()
	return m.StartAll()
}

func (m *TunnelManager) runCmd(name string, args ...string) error {
	// Write output to a regular file instead of a Go pipe so backgrounded
	// amneziawg-go daemons inheriting stdout/stderr do not block cmd.Run().
	logFile, err := os.CreateTemp("", "awg-cmd-*.log")
	if err != nil {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	logPath := logFile.Name()
	defer os.Remove(logPath)

	cmd := exec.Command(name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	runErr := cmd.Run()
	_ = logFile.Close()

	if data, readErr := os.ReadFile(logPath); readErr == nil {
		if out := strings.TrimSpace(string(data)); out != "" {
			for _, line := range strings.Split(out, "\n") {
				m.logger.Logf("%s: %s", filepath.Base(name), line)
			}
		}
	}
	return runErr
}

func (m *TunnelManager) ShowInterfaces() ([]InterfaceStatus, error) {
	out, err := exec.Command("/usr/bin/awg", "show", "all", "dump").Output()
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
	for _, c := range cfgs {
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

func GenerateKeypair() (priv, pub, psk string, err error) {
	privB, err := exec.Command("/usr/bin/awg", "genkey").Output()
	if err != nil {
		return "", "", "", err
	}
	priv = strings.TrimSpace(string(privB))

	cmd := exec.Command("/usr/bin/awg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	pubB, err := cmd.Output()
	if err != nil {
		return "", "", "", err
	}
	pub = strings.TrimSpace(string(pubB))

	pskB, err := exec.Command("/usr/bin/awg", "genpsk").Output()
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
