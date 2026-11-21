package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PolicyTableID      = "210"
	PolicyRulePriority = "250"
	FwmarkRulePriority = "240"
	ProxyDNSFwmark     = 0x200
)

type PolicyAction string

const (
	ActionProxy  PolicyAction = "PROXY"
	ActionDirect PolicyAction = "DIRECT"
	ActionDrop   PolicyAction = "DROP"
)

type RuleKind string

const (
	RuleGeoSite RuleKind = "geosite"
	RuleGeoIP   RuleKind = "geoip"
	RuleDomain  RuleKind = "domain"
	RuleFull    RuleKind = "full"
	RuleKeyword RuleKind = "keyword"
	RuleCIDR    RuleKind = "cidr"
)

type PolicyRule struct {
	LineNo  int          `json:"line"`
	Raw     string       `json:"raw"`
	Action  PolicyAction `json:"action"`
	Target  string       `json:"target,omitempty"` // optional tunnel iface for PROXY:<iface>
	Kind    RuleKind     `json:"kind"`
	Value   string       `json:"value"`
	Comment string       `json:"comment,omitempty"`
	Prefix  netip.Prefix `json:"-"`
}

type PolicyStats struct {
	DefaultPolicy string `json:"default_policy"`
	RulesCount    int    `json:"rules_count"`
	StaticRoutes  int    `json:"static_routes"`
	LearnedIPs    int    `json:"learned_ips"`
	QueriesTotal  uint64 `json:"queries_total"`
	MatchedProxy  uint64 `json:"matched_proxy"`
	MatchedDirect uint64 `json:"matched_direct"`
	MatchedDrop   uint64 `json:"matched_drop"`
	LastApplyErr  string `json:"last_apply_error,omitempty"`
}

type MatchResult struct {
	Query     string       `json:"query"`
	Action    PolicyAction `json:"action"`
	Target    string       `json:"target,omitempty"`
	MatchedBy string       `json:"matched_by"`
	Kind      string       `json:"kind"`
}

type learnedEntry struct {
	Action    PolicyAction
	TargetTun string // optional explicit tunnel iface (for PROXY:<iface>)
	Rule      string
	Domain    string
	Target    string // resolved route spec e.g. "dev:awg0" or "via:"+gw
}

const maxRecentDNSEntries = 1024

type recentDNSEntry struct {
	IPs       []netip.Addr
	UpdatedAt time.Time
}

type BackfillDomainIPs struct {
	Domain string
	Rule   string
	IPs    []netip.Addr
}

type PolicyEngine struct {
	rulesPath string
	settings  *SettingsStore
	geo       *GeoStore
	mgr       *TunnelManager
	logger    *RingLogger

	mu           sync.RWMutex
	rawText      string
	rules        []PolicyRule
	learned      map[netip.Addr]learnedEntry
	learnedOrder []netip.Addr
	recentDNS    map[string]recentDNSEntry
	recentOrder  []string
	lastGateway   string
	lastTunIface  string
	staticCount   int
	lastApplyErr  string
	appliedValid  bool
	appliedRoutes map[string]string

	queriesTotal  atomic.Uint64
	matchedProxy  atomic.Uint64
	matchedDirect atomic.Uint64
	matchedDrop   atomic.Uint64

	// Injectable hooks for tests
	detectRouteFn func(lanIface string) (gw string, connected []netip.Prefix)
	runBatchFn    func(script string) error
	runCmdFn      func(name string, args ...string) error
	activeTunFn   func() string
}

const defaultRulesTemplate = `# Правила маршрутизации AmneziaWG (сверху вниз, первое совпадение побеждает)
# Формат: ACTION,MATCHER[,комментарий]
#   ACTION:  PROXY | DIRECT (или BYPASS) | DROP (или BLOCK)
#   MATCHER:
#     geosite:category-ads-all   (категория из geosite.dat)
#     geosite:ru                 (российские домены)
#     geoip:ru                   (российские IP-подсети)
#     geoip:private              (локальные подсети RFC1918)
#     domain:example.com         (домен и все поддомены)
#     full:sub.example.com       (точное имя домена)
#     keyword:ads                (подстрока в домене)
#     cidr:10.0.0.0/8            (IPv4-подсеть или IP)
`

func NewPolicyEngine(cfgDir string, settings *SettingsStore, geo *GeoStore, mgr *TunnelManager, logger *RingLogger) *PolicyEngine {
	pe := &PolicyEngine{
		rulesPath: filepath.Join(cfgDir, "rules.conf"),
		settings:  settings,
		geo:       geo,
		mgr:       mgr,
		logger:    logger,
		learned:   make(map[netip.Addr]learnedEntry),
		recentDNS: make(map[string]recentDNSEntry),
	}
	pe.detectRouteFn = defaultDetectRoute
	pe.runBatchFn = runIPBatch
	pe.runCmdFn = func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg != "" {
				return fmt.Errorf("%s %v: %s (%w)", name, args, msg, err)
			}
			return fmt.Errorf("%s %v: %w", name, args, err)
		}
		return nil
	}
	return pe
}

func (p *PolicyEngine) LoadAndInit() error {
	raw := defaultRulesTemplate
	if b, err := os.ReadFile(p.rulesPath); err == nil {
		raw = normalizeLF(string(b))
	} else if os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(p.rulesPath), 0o700)
		_ = os.WriteFile(p.rulesPath, []byte(raw), 0o600)
	} else {
		return err
	}
	rules := ParseRulesText(raw)
	p.mu.Lock()
	p.rawText = raw
	p.rules = rules
	p.mu.Unlock()

	needSites, needIPs := p.NeededGeoCategories()
	if err := p.geo.Reload(needSites, needIPs); err != nil {
		p.logger.Logf("WARN geo reload: %v", err)
	}
	return nil
}

func (p *PolicyEngine) NeededGeoCategories() (sites map[string]bool, ips map[string]bool) {
	sites = map[string]bool{}
	ips = map[string]bool{}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.rules {
		switch r.Kind {
		case RuleGeoSite:
			sites[r.Value] = true
		case RuleGeoIP:
			ips[r.Value] = true
		}
	}
	return sites, ips
}

func (p *PolicyEngine) RawAndRules() (string, []PolicyRule) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]PolicyRule, len(p.rules))
	copy(out, p.rules)
	return p.rawText, out
}

func (p *PolicyEngine) SaveRules(raw string) ([]PolicyRule, error) {
	norm := normalizeLF(raw)
	rules := ParseRulesText(norm)

	if err := os.MkdirAll(filepath.Dir(p.rulesPath), 0o700); err != nil {
		return nil, err
	}
	tmp := p.rulesPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(norm), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, p.rulesPath); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}

	p.mu.Lock()
	p.rawText = norm
	p.rules = rules
	p.learned = make(map[netip.Addr]learnedEntry)
	p.learnedOrder = nil
	p.mu.Unlock()

	needSites, needIPs := p.NeededGeoCategories()
	_ = p.geo.Reload(needSites, needIPs)
	if err := p.ApplyRouting(); err != nil {
		return rules, err
	}
	return rules, nil
}

func ParseRulesText(raw string) []PolicyRule {
	var out []PolicyRule
	for i, line := range strings.Split(normalizeLF(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if rule, ok := parsePolicyLine(i+1, line); ok {
			out = append(out, rule)
		}
	}
	return out
}

func parsePolicyLine(lineNo int, line string) (PolicyRule, bool) {
	var actionStr, matcher, comment string
	if strings.Contains(line, ",") {
		parts := strings.SplitN(line, ",", 3)
		actionStr = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			matcher = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			comment = strings.TrimSpace(parts[2])
		}
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return PolicyRule{}, false
		}
		actionStr = fields[0]
		matcher = fields[1]
		if len(fields) > 2 {
			comment = strings.Join(fields[2:], " ")
		}
	}

	action, targetTun, ok := normalizeActionTarget(actionStr)
	if !ok || matcher == "" {
		return PolicyRule{}, false
	}

	kind, val, prefix, valid := parseMatcher(matcher)
	if !valid {
		return PolicyRule{}, false
	}

	return PolicyRule{
		LineNo:  lineNo,
		Raw:     line,
		Action:  action,
		Target:  targetTun,
		Kind:    kind,
		Value:   val,
		Comment: comment,
		Prefix:  prefix,
	}, true
}

func normalizeAction(s string) (PolicyAction, bool) {
	act, _, ok := normalizeActionTarget(s)
	return act, ok
}

func normalizeActionTarget(s string) (PolicyAction, string, bool) {
	raw := strings.TrimSpace(s)
	head := raw
	target := ""
	if idx := strings.IndexAny(raw, ":@"); idx > 0 {
		head = strings.TrimSpace(raw[:idx])
		target = strings.TrimSpace(raw[idx+1:])
	}
	switch strings.ToUpper(head) {
	case "PROXY", "VPN", "TUNNEL", "TUN":
		if target != "" {
			if !validConfNameRe.MatchString(target+".conf") && !validConfNameRe.MatchString(target) {
				return "", "", false
			}
			target = strings.TrimSuffix(target, ".conf")
		}
		return ActionProxy, target, true
	case "DIRECT", "BYPASS", "PASS":
		return ActionDirect, "", true
	case "DROP", "BLOCK", "REJECT":
		return ActionDrop, "", true
	default:
		return "", "", false
	}
}

func parseMatcher(raw string) (RuleKind, string, netip.Prefix, bool) {
	m := strings.TrimSpace(raw)
	low := strings.ToLower(m)
	switch {
	case strings.HasPrefix(low, "geosite:"):
		v := strings.TrimSpace(low[len("geosite:"):])
		return RuleGeoSite, v, netip.Prefix{}, v != ""
	case strings.HasPrefix(low, "geoip:"):
		v := strings.TrimSpace(low[len("geoip:"):])
		return RuleGeoIP, v, netip.Prefix{}, v != ""
	case strings.HasPrefix(low, "full:"):
		v := normalizeDomain(low[len("full:"):])
		return RuleFull, v, netip.Prefix{}, v != ""
	case strings.HasPrefix(low, "domain:") || strings.HasPrefix(low, "domain-suffix:") || strings.HasPrefix(low, "suffix:"):
		idx := strings.IndexByte(low, ':')
		v := normalizeDomain(low[idx+1:])
		return RuleDomain, v, netip.Prefix{}, v != ""
	case strings.HasPrefix(low, "keyword:") || strings.HasPrefix(low, "domain-keyword:"):
		idx := strings.IndexByte(low, ':')
		v := strings.TrimSpace(low[idx+1:])
		return RuleKeyword, v, netip.Prefix{}, v != ""
	case strings.HasPrefix(low, "cidr:") || strings.HasPrefix(low, "ip-cidr:"):
		idx := strings.IndexByte(low, ':')
		v := strings.TrimSpace(low[idx+1:])
		if p, ok := parsePrefixOrAddr(v); ok {
			return RuleCIDR, p.String(), p, true
		}
		return "", "", netip.Prefix{}, false
	default:
		if p, ok := parsePrefixOrAddr(m); ok {
			return RuleCIDR, p.String(), p, true
		}
		v := normalizeDomain(low)
		return RuleDomain, v, netip.Prefix{}, v != ""
	}
}

func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	return d
}

func (p *PolicyEngine) DefaultAction() PolicyAction {
	if p.settings != nil && p.settings.Get().DefaultPolicy == "direct" {
		return ActionDirect
	}
	return ActionProxy
}

func (p *PolicyEngine) MatchDomain(rawHost string) (PolicyAction, string) {
	act, by, _ := p.MatchDomainTarget(rawHost)
	return act, by
}

func (p *PolicyEngine) MatchDomainTarget(rawHost string) (PolicyAction, string, string) {
	host := normalizeDomain(rawHost)
	if host == "" {
		return p.DefaultAction(), "default", ""
	}

	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()

	for _, r := range rules {
		switch r.Kind {
		case RuleFull:
			if host == r.Value {
				return r.Action, "full:" + r.Value, r.Target
			}
		case RuleDomain:
			if host == r.Value || strings.HasSuffix(host, "."+r.Value) {
				return r.Action, "domain:" + r.Value, r.Target
			}
		case RuleKeyword:
			if r.Value != "" && strings.Contains(host, r.Value) {
				return r.Action, "keyword:" + r.Value, r.Target
			}
		case RuleGeoSite:
			if p.geo != nil && p.geo.MatchSite(r.Value, host) {
				return r.Action, "geosite:" + r.Value, r.Target
			}
		}
	}
	return p.DefaultAction(), "default", ""
}

func (p *PolicyEngine) MatchStaticIP(addr netip.Addr) (PolicyAction, string, bool) {
	act, by, _, ok := p.MatchStaticIPTarget(addr)
	return act, by, ok
}

func (p *PolicyEngine) MatchStaticIPTarget(addr netip.Addr) (PolicyAction, string, string, bool) {
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()

	for _, r := range rules {
		switch r.Kind {
		case RuleCIDR:
			if r.Prefix.Contains(addr) {
				return r.Action, "cidr:" + r.Value, r.Target, true
			}
		case RuleGeoIP:
			if p.geo != nil && p.geo.MatchIP(r.Value, addr) {
				return r.Action, "geoip:" + r.Value, r.Target, true
			}
		}
	}
	return "", "", "", false
}

func (p *PolicyEngine) TestQuery(raw string) MatchResult {
	q := strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(q); err == nil {
		if act, by, tgt, ok := p.MatchStaticIPTarget(addr); ok {
			return MatchResult{Query: q, Action: act, Target: tgt, MatchedBy: by, Kind: "ip"}
		}
		p.mu.RLock()
		le, ok := p.learned[addr]
		p.mu.RUnlock()
		if ok {
			return MatchResult{Query: q, Action: le.Action, Target: le.TargetTun, MatchedBy: le.Rule + " (dns:" + le.Domain + ")", Kind: "ip"}
		}
		return MatchResult{Query: q, Action: p.DefaultAction(), MatchedBy: "default", Kind: "ip"}
	}
	act, by, tgt := p.MatchDomainTarget(q)
	return MatchResult{Query: q, Action: act, Target: tgt, MatchedBy: by, Kind: "domain"}
}

func (p *PolicyEngine) NoteDNSStats(action PolicyAction) {
	p.queriesTotal.Add(1)
	switch action {
	case ActionProxy:
		p.matchedProxy.Add(1)
	case ActionDirect:
		p.matchedDirect.Add(1)
	case ActionDrop:
		p.matchedDrop.Add(1)
	}
}

func (p *PolicyEngine) Stats() PolicyStats {
	p.mu.RLock()
	rulesCount := len(p.rules)
	learnedLen := len(p.learned)
	staticCount := p.staticCount
	lastErr := p.lastApplyErr
	p.mu.RUnlock()

	return PolicyStats{
		DefaultPolicy: strings.ToLower(string(p.DefaultAction())),
		RulesCount:    rulesCount,
		StaticRoutes:  staticCount,
		LearnedIPs:    learnedLen,
		QueriesTotal:  p.queriesTotal.Load(),
		MatchedProxy:  p.matchedProxy.Load(),
		MatchedDirect: p.matchedDirect.Load(),
		MatchedDrop:   p.matchedDrop.Load(),
		LastApplyErr:  lastErr,
	}
}

// RecordResolvedIPs updates table 210 synchronously for newly resolved A records
// matching domain rules (e.g. DIRECT or PROXY overrides via DNS).
func (p *PolicyEngine) RecordResolvedIPs(domain string, action PolicyAction, matchedRule string, addrs []netip.Addr) {
	p.RecordResolvedIPsForTarget(domain, action, matchedRule, "", addrs)
}

func (p *PolicyEngine) RecordResolvedIPsForTarget(domain string, action PolicyAction, matchedRule, targetTun string, addrs []netip.Addr) {
	if len(addrs) == 0 || action == ActionDrop {
		return
	}
	// Do not waste routes if matching default fallback unless an explicit opposite rule or default changed.
	lanIface := ""
	killSwitch := true
	if p.mgr != nil {
		lanIface = p.mgr.lanIface
		killSwitch = p.mgr.killSwitch
	}
	tunIface := p.activeTunnelIface()
	effectiveTun := tunIface
	if action == ActionProxy && targetTun != "" {
		upSet := p.activeIfaceSet()
		if upSet[targetTun] {
			effectiveTun = targetTun
		}
	}

	p.mu.Lock()
	gw := p.lastGateway
	target := ""
	var routeTarget string
	switch action {
	case ActionDirect:
		if gw != "" && lanIface != "" {
			target = "via:" + gw
			routeTarget = fmt.Sprintf("via %s dev %s", gw, lanIface)
		}
	case ActionProxy:
		if effectiveTun != "" {
			target = "dev:" + effectiveTun
			routeTarget = fmt.Sprintf("dev %s", effectiveTun)
		} else if killSwitch {
			target = "blackhole"
		}
	}

	var batchLines []string
	var newAppliedEntries [][2]string
	for _, addr := range addrs {
		if !addr.Is4() || addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
			continue
		}
		if _, _, isStatic := p.matchStaticIPLocked(addr); isStatic {
			continue
		}
		if cur, ok := p.learned[addr]; ok && cur.Action == action && cur.Target == target && cur.TargetTun == targetTun {
			continue
		}
		if _, exists := p.learned[addr]; !exists {
			if len(p.learnedOrder) >= 4096 {
				evict := p.learnedOrder[0]
				p.learnedOrder = p.learnedOrder[1:]
				delete(p.learned, evict)
			}
			p.learnedOrder = append(p.learnedOrder, addr)
		}
		p.learned[addr] = learnedEntry{
			Action:    action,
			TargetTun: targetTun,
			Rule:      matchedRule,
			Domain:    domain,
			Target:    target,
		}
		if lanIface != "" {
			if target == "blackhole" {
				line := fmt.Sprintf("route replace blackhole %s/32 metric 254 table %s", addr.String(), PolicyTableID)
				batchLines = append(batchLines, line)
				newAppliedEntries = append(newAppliedEntries, [2]string{"blackhole " + addr.String() + "/32 metric 254", line})
			} else if routeTarget != "" {
				line := fmt.Sprintf("route replace %s/32 %s table %s", addr.String(), routeTarget, PolicyTableID)
				batchLines = append(batchLines, line)
				newAppliedEntries = append(newAppliedEntries, [2]string{addr.String() + "/32", line})
			}
		}
	}
	p.mu.Unlock()

	if len(batchLines) > 0 && lanIface != "" {
		if err := p.runBatchFn(strings.Join(batchLines, "\n") + "\n"); err != nil {
			p.logger.Logf("WARN policy dynamic /32 batch: %v", err)
		} else {
			p.mu.Lock()
			if p.appliedValid && p.appliedRoutes != nil {
				for _, kv := range newAppliedEntries {
					p.appliedRoutes[kv[0]] = kv[1]
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *PolicyEngine) matchStaticIPLocked(addr netip.Addr) (PolicyAction, string, bool) {
	for _, r := range p.rules {
		switch r.Kind {
		case RuleCIDR:
			if r.Prefix.Contains(addr) {
				return r.Action, "cidr:" + r.Value, true
			}
		case RuleGeoIP:
			if p.geo != nil && p.geo.MatchIP(r.Value, addr) {
				return r.Action, "geoip:" + r.Value, true
			}
		}
	}
	return "", "", false
}

// PolicyRouterOSPlan describes the static IPv4 prefixes from explicit PROXY rules
// safe to synchronize to RouterOS (address-list or BGP) without overriding higher
// DIRECT/DROP rules or excluded host/management IPs.
type PolicyRouterOSPlan struct {
	Prefixes        []netip.Prefix
	TotalCandidates int
	ExcludedCount   int
	DroppedByLimit  int
	Limit           int
	SkippedRules    []string
}

type ipv4TrieNode struct {
	child    [2]int32
	terminal bool
}

type ipv4PrefixTrie struct {
	nodes []ipv4TrieNode
}

func newIPv4PrefixTrie() *ipv4PrefixTrie {
	return &ipv4PrefixTrie{nodes: make([]ipv4TrieNode, 1, 256)}
}

func prefixToUint32(p netip.Prefix) uint32 {
	b := p.Masked().Addr().As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToAddr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func (t *ipv4PrefixTrie) insert(p netip.Prefix) {
	if !p.IsValid() || !p.Addr().Is4() {
		return
	}
	ip := prefixToUint32(p)
	bits := p.Bits()
	node := int32(0)
	for i := 0; i < bits; i++ {
		if t.nodes[node].terminal {
			return // already covered by broader prefix
		}
		bit := (ip >> uint(31-i)) & 1
		next := t.nodes[node].child[bit]
		if next == 0 {
			next = int32(len(t.nodes))
			t.nodes = append(t.nodes, ipv4TrieNode{})
			t.nodes[node].child[bit] = next
		}
		node = next
	}
	t.nodes[node].terminal = true
}

func (t *ipv4PrefixTrie) isCovered(p netip.Prefix) bool {
	if t == nil || len(t.nodes) == 0 || !p.IsValid() || !p.Addr().Is4() {
		return false
	}
	ip := prefixToUint32(p)
	bits := p.Bits()
	node := int32(0)
	for i := 0; i < bits; i++ {
		if t.nodes[node].terminal {
			return true
		}
		bit := (ip >> uint(31-i)) & 1
		next := t.nodes[node].child[bit]
		if next == 0 {
			return false
		}
		node = next
	}
	return t.nodes[node].terminal
}

func (t *ipv4PrefixTrie) hasOverlap(p netip.Prefix) bool {
	if t == nil || len(t.nodes) == 0 || !p.IsValid() || !p.Addr().Is4() {
		return false
	}
	ip := prefixToUint32(p)
	bits := p.Bits()
	node := int32(0)
	for i := 0; i < bits; i++ {
		if t.nodes[node].terminal {
			return true
		}
		bit := (ip >> uint(31-i)) & 1
		next := t.nodes[node].child[bit]
		if next == 0 {
			return false
		}
		node = next
	}
	return t.nodes[node].terminal || t.nodes[node].child[0] != 0 || t.nodes[node].child[1] != 0
}

func isSyncableIPv4Addr(a netip.Addr) bool {
	if !a.IsValid() || !a.Is4() {
		return false
	}
	if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func isSyncableIPv4Prefix(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	m := p.Masked()
	if !m.Addr().Is4() || m.Bits() <= 0 || m.Bits() > 32 {
		return false
	}
	a := m.Addr()
	if a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func prefixCoveredBy(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || !a.Addr().Is4() || !b.Addr().Is4() {
		return false
	}
	bm := b.Masked()
	am := a.Masked()
	return bm.Bits() <= am.Bits() && bm.Contains(am.Addr())
}

// subtractPrefix returns the sub-prefixes of p that do not overlap cut.
func subtractPrefix(p, cut netip.Prefix) []netip.Prefix {
	pm := p.Masked()
	cm := cut.Masked()
	if !pm.Overlaps(cm) {
		return []netip.Prefix{pm}
	}
	if cm.Bits() <= pm.Bits() {
		return nil
	}
	var out []netip.Prefix
	cur := pm
	cutIP := prefixToUint32(cm)
	for bitIdx := pm.Bits(); bitIdx < cm.Bits(); bitIdx++ {
		base := prefixToUint32(cur)
		maskBit := uint32(1) << uint(31-bitIdx)
		cutGoesRight := (cutIP & maskBit) != 0
		if cutGoesRight {
			// Sibling with bit=0 is disjoint from cut
			out = append(out, netip.PrefixFrom(uint32ToAddr4(base), bitIdx+1))
			cur = netip.PrefixFrom(uint32ToAddr4(base|maskBit), bitIdx+1)
		} else {
			// Sibling with bit=1 is disjoint from cut
			out = append(out, netip.PrefixFrom(uint32ToAddr4(base|maskBit), bitIdx+1))
			cur = netip.PrefixFrom(uint32ToAddr4(base), bitIdx+1)
		}
	}
	return out
}

func subtractCuts(p netip.Prefix, cuts []netip.Prefix) ([]netip.Prefix, int) {
	rem := []netip.Prefix{p.Masked()}
	excluded := 0
	for _, cut := range cuts {
		var next []netip.Prefix
		changed := false
		for _, item := range rem {
			if !item.Overlaps(cut) {
				next = append(next, item)
				continue
			}
			changed = true
			// Avoid exploding super-broad prefixes (e.g. /1.. /7) around tiny cuts.
			if item.Bits() < 8 && cut.Bits()-item.Bits() > 12 {
				continue
			}
			subs := subtractPrefix(item, cut)
			next = append(next, subs...)
		}
		if changed {
			excluded++
		}
		rem = next
		if len(rem) == 0 {
			break
		}
	}
	return rem, excluded
}

// ComputeRouterOSPrefixes builds the ordered deduplicated list of static IPv4 prefixes
// from explicit PROXY cidr:/geoip: rules, respecting earlier DIRECT/DROP rules and excluded host IPs.
func (p *PolicyEngine) ComputeRouterOSPrefixes(limit int, exclude ...netip.Addr) PolicyRouterOSPlan {
	p.mu.RLock()
	rules := append([]PolicyRule(nil), p.rules...)
	geo := p.geo
	p.mu.RUnlock()

	plan := PolicyRouterOSPlan{Limit: limit}

	var cuts []netip.Prefix
	for _, ex := range exclude {
		if isSyncableIPv4Addr(ex) {
			cuts = append(cuts, netip.PrefixFrom(ex, 32))
		}
	}

	blockTrie := newIPv4PrefixTrie()
	proxyTrie := newIPv4PrefixTrie()

	for _, r := range rules {
		switch r.Kind {
		case RuleCIDR:
			if !isSyncableIPv4Prefix(r.Prefix) {
				if r.Action == ActionProxy && r.Prefix.IsValid() && r.Prefix.Addr().Is4() {
					plan.SkippedRules = append(plan.SkippedRules, fmt.Sprintf("cidr:%s (non-routable or /0)", r.Value))
				}
				continue
			}
			m := r.Prefix.Masked()
			if r.Action == ActionDirect || r.Action == ActionDrop {
				if len(cuts) < 128 {
					cuts = append(cuts, m)
				} else {
					blockTrie.insert(m)
				}
				continue
			}
			if r.Action != ActionProxy {
				continue
			}
			plan.TotalCandidates++
			if blockTrie.hasOverlap(m) {
				plan.ExcludedCount++
				continue
			}
			pieces, _ := subtractCuts(m, cuts)
			if len(pieces) == 0 {
				plan.ExcludedCount++
				continue
			}
			for _, sub := range pieces {
				if blockTrie.hasOverlap(sub) {
					plan.ExcludedCount++
					continue
				}
				if proxyTrie.isCovered(sub) {
					continue
				}
				if limit > 0 && len(plan.Prefixes) >= limit {
					plan.DroppedByLimit++
					continue
				}
				proxyTrie.insert(sub)
				plan.Prefixes = append(plan.Prefixes, sub)
			}

		case RuleGeoIP:
			var cat *GeoIPCategory
			if geo != nil {
				cat = geo.CategoryIPs(r.Value)
			}
			if cat == nil {
				if r.Action == ActionProxy {
					plan.SkippedRules = append(plan.SkippedRules, fmt.Sprintf("geoip:%s (not loaded)", r.Value))
				}
				continue
			}
			if cat.InverseMatch {
				if r.Action == ActionProxy {
					plan.SkippedRules = append(plan.SkippedRules, fmt.Sprintf("geoip:%s (inverse unsupported)", r.Value))
				}
				continue
			}
			if r.Action == ActionDirect || r.Action == ActionDrop {
				for _, pfx := range cat.Prefixes {
					if isSyncableIPv4Prefix(pfx) {
						blockTrie.insert(pfx.Masked())
					}
				}
				continue
			}
			if r.Action != ActionProxy {
				continue
			}
			for _, pfx := range cat.Prefixes {
				if !isSyncableIPv4Prefix(pfx) {
					continue
				}
				m := pfx.Masked()
				plan.TotalCandidates++
				if blockTrie.hasOverlap(m) {
					plan.ExcludedCount++
					continue
				}
				pieces, _ := subtractCuts(m, cuts)
				if len(pieces) == 0 {
					plan.ExcludedCount++
					continue
				}
				for _, sub := range pieces {
					if blockTrie.hasOverlap(sub) {
						plan.ExcludedCount++
						continue
					}
					if proxyTrie.isCovered(sub) {
						continue
					}
					if limit > 0 && len(plan.Prefixes) >= limit {
						plan.DroppedByLimit++
						continue
					}
					proxyTrie.insert(sub)
					plan.Prefixes = append(plan.Prefixes, sub)
				}
			}
		}
	}

	return plan
}

// EvaluateForRouterOS decides whether resolved DNS IPv4 addresses for domain should be pushed
// to RouterOS based on explicit PROXY domain rules (never "default"), excluding any IPs matching
// DIRECT/DROP static rules or excluded host/gateway addresses.
func (p *PolicyEngine) EvaluateForRouterOS(domain string, addrs []netip.Addr, exclude ...netip.Addr) (bool, string, []netip.Addr) {
	act, matchedBy, _ := p.MatchDomainTarget(domain)
	if act != ActionProxy || matchedBy == "" || matchedBy == "default" {
		return false, "", nil
	}

	var out []netip.Addr
	seen := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		if !isSyncableIPv4Addr(a) {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		excluded := false
		for _, ex := range exclude {
			if ex.IsValid() && ex == a {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if ipAct, _, _, isStatic := p.MatchStaticIPTarget(a); isStatic {
			if ipAct == ActionDirect || ipAct == ActionDrop {
				continue
			}
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	if len(out) == 0 {
		return false, matchedBy, nil
	}
	return true, matchedBy, out
}

// RevalidateDynamicHostIP checks whether a previously cached domain->IP mapping is still
// permitted for RouterOS sync under current policy rules.
func (p *PolicyEngine) RevalidateDynamicHostIP(domain string, addr netip.Addr, exclude ...netip.Addr) (bool, string) {
	ok, matchedBy, kept := p.EvaluateForRouterOS(domain, []netip.Addr{addr}, exclude...)
	if !ok || len(kept) == 0 {
		return false, ""
	}
	return true, matchedBy
}

// RecordRecentDNS caches recent DNS IPv4 resolutions regardless of action so newly added
// PROXY rules can immediately backfill RouterOS address-list without waiting for client TTL expiry.
func (p *PolicyEngine) RecordRecentDNS(domain string, ips []netip.Addr) {
	if p == nil {
		return
	}
	host := normalizeDomain(domain)
	if host == "" || len(ips) == 0 {
		return
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	kept := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		if !isSyncableIPv4Addr(a) {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		kept = append(kept, a)
	}
	if len(kept) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recentDNS == nil {
		p.recentDNS = make(map[string]recentDNSEntry)
	}
	if _, exists := p.recentDNS[host]; !exists {
		if len(p.recentOrder) >= maxRecentDNSEntries {
			evict := p.recentOrder[0]
			p.recentOrder = p.recentOrder[1:]
			delete(p.recentDNS, evict)
		}
		p.recentOrder = append(p.recentOrder, host)
	}
	p.recentDNS[host] = recentDNSEntry{
		IPs:       kept,
		UpdatedAt: time.Now(),
	}
}

// ReevaluateRecentDNSForRouterOS re-evaluates recently resolved DNS answers against current
// rules and returns those that now qualify for dynamic RouterOS PROXY injection.
func (p *PolicyEngine) ReevaluateRecentDNSForRouterOS(maxAge time.Duration, exclude ...netip.Addr) []BackfillDomainIPs {
	if p == nil {
		return nil
	}
	if maxAge <= 0 {
		maxAge = 2 * time.Hour
	}
	cutoff := time.Now().Add(-maxAge)

	type snapItem struct {
		domain string
		ips    []netip.Addr
	}
	p.mu.RLock()
	items := make([]snapItem, 0, len(p.recentDNS))
	for dom, ent := range p.recentDNS {
		if ent.UpdatedAt.Before(cutoff) || len(ent.IPs) == 0 {
			continue
		}
		ipsCopy := make([]netip.Addr, len(ent.IPs))
		copy(ipsCopy, ent.IPs)
		items = append(items, snapItem{domain: dom, ips: ipsCopy})
	}
	p.mu.RUnlock()

	sort.Slice(items, func(i, j int) bool { return items[i].domain < items[j].domain })

	var out []BackfillDomainIPs
	for _, it := range items {
		ok, matchedBy, kept := p.EvaluateForRouterOS(it.domain, it.ips, exclude...)
		if !ok || len(kept) == 0 {
			continue
		}
		p.RecordResolvedIPsForTarget(it.domain, ActionProxy, matchedBy, "", kept)
		out = append(out, BackfillDomainIPs{
			Domain: it.domain,
			Rule:   matchedBy,
			IPs:    kept,
		})
	}
	return out
}

// RouterOSSeedDomains collects a bounded set of explicit PROXY domains and representative
// domains from PROXY geosite categories for proactive DNS seeding after rule changes.
func (p *PolicyEngine) RouterOSSeedDomains(maxTotal int) []string {
	if p == nil {
		return nil
	}
	if maxTotal <= 0 {
		maxTotal = 40
	}

	p.mu.RLock()
	rules := make([]PolicyRule, len(p.rules))
	copy(rules, p.rules)
	p.mu.RUnlock()

	seen := make(map[string]struct{}, maxTotal)
	out := make([]string, 0, maxTotal)
	tryAdd := func(raw string) bool {
		if len(out) >= maxTotal {
			return false
		}
		dom := normalizeDomain(raw)
		if dom == "" || !strings.Contains(dom, ".") {
			return false
		}
		if _, err := netip.ParseAddr(dom); err == nil {
			return false
		}
		if _, dup := seen[dom]; dup {
			return false
		}
		act, by, _ := p.MatchDomainTarget(dom)
		if act != ActionProxy || by == "default" {
			return false
		}
		seen[dom] = struct{}{}
		out = append(out, dom)
		return true
	}

	var geoCats []string
	seenCats := map[string]bool{}
	for _, r := range rules {
		if r.Action != ActionProxy {
			continue
		}
		switch r.Kind {
		case RuleFull, RuleDomain:
			tryAdd(r.Value)
		case RuleGeoSite:
			cat := strings.ToLower(strings.TrimSpace(r.Value))
			if cat != "" && !seenCats[cat] {
				seenCats[cat] = true
				geoCats = append(geoCats, cat)
			}
		}
	}

	if p.geo == nil || len(geoCats) == 0 || len(out) >= maxTotal {
		return out
	}

	perCatLimit := (maxTotal - len(out) + len(geoCats) - 1) / len(geoCats)
	if perCatLimit < 4 {
		perCatLimit = 4
	}
	if perCatLimit > 12 {
		perCatLimit = 12
	}

	catSamples := make([][]string, len(geoCats))
	for i, cat := range geoCats {
		catSamples[i] = p.geo.SiteSeedDomains(cat, perCatLimit)
	}

	// Round-robin across categories so newly appended geosite rules also get seeded.
	for round := 0; len(out) < maxTotal; round++ {
		progressed := false
		for i := range catSamples {
			if round < len(catSamples[i]) {
				progressed = true
				tryAdd(catSamples[i][round])
				if len(out) >= maxTotal {
					return out
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

func (p *PolicyEngine) activeTunnelIface() string {
	if p.activeTunFn != nil {
		return p.activeTunFn()
	}
	if p.mgr == nil {
		return ""
	}
	if pifc := p.mgr.PrimaryInterface(); pifc != "" {
		return pifc
	}
	ifaces, err := p.mgr.ShowInterfaces()
	if err != nil || len(ifaces) == 0 {
		return ""
	}
	return ifaces[0].Name
}

func (p *PolicyEngine) activeIfaceSet() map[string]bool {
	set := map[string]bool{}
	if p.mgr == nil {
		return set
	}
	if ifaces, err := p.mgr.ShowInterfaces(); err == nil {
		for _, i := range ifaces {
			set[i.Name] = true
		}
	}
	return set
}

func (p *PolicyEngine) ApplyRouting() error {
	if p.mgr == nil || p.mgr.lanIface == "" {
		return nil
	}
	lanIface := p.mgr.lanIface
	killSwitch := p.mgr.killSwitch
	defAction := p.DefaultAction()
	tunIface := p.activeTunnelIface()
	gw, connected := p.detectRouteFn(lanIface)

	p.mu.RLock()
	rules := append([]PolicyRule(nil), p.rules...)
	learnedSnap := make(map[netip.Addr]learnedEntry, len(p.learned))
	for k, v := range p.learned {
		learnedSnap[k] = v
	}
	prevValid := p.appliedValid
	prevRoutes := make(map[string]string, len(p.appliedRoutes))
	for k, v := range p.appliedRoutes {
		prevRoutes[k] = v
	}
	prevTun := p.lastTunIface
	p.mu.RUnlock()

	script, staticCount := p.BuildBatchScript(lanIface, gw, tunIface, defAction, killSwitch, connected, rules, learnedSnap)
	desiredOrder, desiredRoutes := parseBatchRouteMap(script)

	// Install table 210 routes (use incremental diff when table is already populated to avoid 13k+ flushes)
	var applyErr error
	usedDiff := false
	if prevValid && len(prevRoutes) > 0 {
		diffLines := buildDiffBatchLines(prevRoutes, desiredOrder, desiredRoutes, prevTun, tunIface, PolicyTableID)
		usedDiff = true
		if len(diffLines) > 0 {
			if err := p.runBatchFn(strings.Join(diffLines, "\n") + "\n"); err != nil {
				// Fallback to full table reset if incremental diff fails
				usedDiff = false
				prevValid = false
			}
		}
	}
	if !usedDiff {
		if err := p.runBatchFn(script); err != nil {
			applyErr = err
			p.logger.Logf("WARN policy batch error: %v", err)
		}
	}

	// Ensure ip rule priority 250 (iif <lanIface> lookup 210)
	_ = p.runCmdFn("ip", "rule", "del", "priority", PolicyRulePriority)
	if err := p.runCmdFn("ip", "rule", "add", "priority", PolicyRulePriority, "from", "all", "iif", lanIface, "lookup", PolicyTableID); err != nil && applyErr == nil {
		applyErr = err
	}

	// Ensure fwmark rule for Proxy DNS binding to table awg when active
	_ = p.runCmdFn("ip", "rule", "del", "priority", FwmarkRulePriority)
	if tunIface != "" {
		_ = p.runCmdFn("ip", "rule", "add", "priority", FwmarkRulePriority, "from", "all", "fwmark", fmt.Sprintf("0x%x", ProxyDNSFwmark), "lookup", "awg")
	}

	// Ensure MASQUERADE on lanIface for DIRECT hairpin traffic back to MikroTik
	if err := p.runCmdFn("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", lanIface, "-j", "MASQUERADE"); err != nil {
		if err2 := p.runCmdFn("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", lanIface, "-j", "MASQUERADE"); err2 != nil && applyErr == nil {
			applyErr = err2
		}
	}

	// Remove legacy catch-all FORWARD DROP if present (table 210 blackhole enforces kill-switch safely)
	if tunIface != "" {
		_ = p.runCmdFn("iptables", "-D", "FORWARD", "-i", lanIface, "!", "-o", tunIface, "-j", "DROP")
	}

	// Defense-in-depth IPv6 leak guard: unless AWG_ENABLE_IPV6=on (or an IPv6 tunnel is configured),
	// keep IPv6 forwarding disabled and default-drop IPv6 FORWARD chain. Best-effort on kernels without IPv6.
	if os.Getenv("AWG_ENABLE_IPV6") != "on" && !p.hasIPv6Config() {
		_ = p.runCmdFn("sysctl", "-w", "net.ipv6.conf.all.forwarding=0")
		_ = p.runCmdFn("ip6tables", "-P", "FORWARD", "DROP")
	}

	p.mu.Lock()
	p.lastGateway = gw
	p.lastTunIface = tunIface
	p.staticCount = staticCount
	if applyErr != nil {
		p.lastApplyErr = applyErr.Error()
		p.appliedValid = false
		p.appliedRoutes = nil
	} else {
		p.lastApplyErr = ""
		p.appliedValid = true
		p.appliedRoutes = desiredRoutes
	}
	p.mu.Unlock()

	if applyErr == nil {
		p.logger.Logf("Policy applied (default=%s, tun=%s, gw=%s, static_cidrs=%d)", defAction, tunIface, gw, staticCount)
	}
	return applyErr
}

func (p *PolicyEngine) BuildBatchScript(
	lanIface, gw, tunIface string,
	defAction PolicyAction,
	killSwitch bool,
	connected []netip.Prefix,
	rules []PolicyRule,
	learned map[netip.Addr]learnedEntry,
) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, "route flush table %s\n", PolicyTableID)

	for _, c := range connected {
		if c.Addr().Is4() && c.Bits() > 0 {
			fmt.Fprintf(&b, "route replace throw %s table %s\n", c.String(), PolicyTableID)
		}
	}

	upIfaces := p.activeIfaceSet()
	if tunIface != "" {
		upIfaces[tunIface] = true
	}
	resolveProxyIface := func(reqTarget string) string {
		if reqTarget != "" && upIfaces[reqTarget] {
			return reqTarget
		}
		return tunIface
	}

	seen := make(map[netip.Prefix]bool)
	staticCount := 0
	addPrefix := func(pfx netip.Prefix, act PolicyAction, reqTarget string) {
		if !pfx.Addr().Is4() || pfx.Bits() == 0 {
			return
		}
		pfx = pfx.Masked()
		if seen[pfx] {
			return
		}
		seen[pfx] = true
		switch act {
		case ActionDrop:
			fmt.Fprintf(&b, "route replace blackhole %s table %s\n", pfx.String(), PolicyTableID)
			staticCount++
		case ActionDirect:
			if gw != "" && lanIface != "" {
				fmt.Fprintf(&b, "route replace %s via %s dev %s table %s\n", pfx.String(), gw, lanIface, PolicyTableID)
				staticCount++
			}
		case ActionProxy:
			if ifc := resolveProxyIface(reqTarget); ifc != "" {
				fmt.Fprintf(&b, "route replace %s dev %s table %s\n", pfx.String(), ifc, PolicyTableID)
				staticCount++
			} else if killSwitch {
				fmt.Fprintf(&b, "route replace blackhole %s metric 254 table %s\n", pfx.String(), PolicyTableID)
				staticCount++
			}
		}
	}

	for _, r := range rules {
		switch r.Kind {
		case RuleCIDR:
			addPrefix(r.Prefix, r.Action, r.Target)
		case RuleGeoIP:
			if p.geo != nil {
				if cat := p.geo.CategoryIPs(r.Value); cat != nil && !cat.InverseMatch {
					for _, pfx := range cat.Prefixes {
						addPrefix(pfx, r.Action, r.Target)
					}
				}
			}
		}
	}

	for addr, le := range learned {
		if !addr.Is4() {
			continue
		}
		pfx := netip.PrefixFrom(addr, 32)
		if seen[pfx] {
			continue
		}
		switch le.Action {
		case ActionDirect:
			if gw != "" && lanIface != "" {
				fmt.Fprintf(&b, "route replace %s/32 via %s dev %s table %s\n", addr.String(), gw, lanIface, PolicyTableID)
			}
		case ActionProxy:
			if ifc := resolveProxyIface(le.TargetTun); ifc != "" {
				fmt.Fprintf(&b, "route replace %s/32 dev %s table %s\n", addr.String(), ifc, PolicyTableID)
			} else if killSwitch {
				fmt.Fprintf(&b, "route replace blackhole %s/32 metric 254 table %s\n", addr.String(), PolicyTableID)
			}
		}
	}

	if defAction == ActionDirect {
		if gw != "" && lanIface != "" {
			fmt.Fprintf(&b, "route replace default via %s dev %s metric 10 table %s\n", gw, lanIface, PolicyTableID)
		}
	} else {
		if tunIface != "" {
			fmt.Fprintf(&b, "route replace default dev %s metric 10 table %s\n", tunIface, PolicyTableID)
		}
		if killSwitch {
			fmt.Fprintf(&b, "route replace blackhole default metric 254 table %s\n", PolicyTableID)
		}
	}

	return b.String(), staticCount
}

const (
	ipBatchChunkLines       = 200
	ipDeleteBatchChunkLines = 150
)

func extractRouteKey(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	idx := 0
	var keyParts []string
	switch tokens[0] {
	case "blackhole", "unreachable", "prohibit", "throw":
		if len(tokens) < 2 {
			return ""
		}
		keyParts = append(keyParts, tokens[0], tokens[1])
		idx = 2
	default:
		keyParts = append(keyParts, tokens[0])
		idx = 1
	}
	for i := idx; i+1 < len(tokens); i++ {
		if tokens[i] == "metric" {
			keyParts = append(keyParts, "metric", tokens[i+1])
			break
		}
	}
	return strings.Join(keyParts, " ")
}

func parseBatchRouteMap(script string) ([]string, map[string]string) {
	var order []string
	routes := make(map[string]string)
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "route replace ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		key := extractRouteKey(fields[2:])
		if key == "" {
			continue
		}
		if _, exists := routes[key]; !exists {
			order = append(order, key)
		}
		routes[key] = line
	}
	return order, routes
}

func buildDiffBatchLines(prevRoutes map[string]string, desiredOrder []string, desiredRoutes map[string]string, prevTun, tunIface, tableID string) []string {
	var dels []string
	for k := range prevRoutes {
		if _, ok := desiredRoutes[k]; !ok {
			dels = append(dels, fmt.Sprintf("route del %s table %s", k, tableID))
		}
	}
	sort.Strings(dels)

	var adds []string
	for _, k := range desiredOrder {
		line := desiredRoutes[k]
		prevLine, existed := prevRoutes[k]
		// Always refresh default routes and routes bound to a tunnel device (kernel auto-deletes them if tun bounced)
		isTunBound := (tunIface != "" && strings.Contains(line, " dev "+tunIface+" ")) ||
			(prevTun != "" && prevTun != tunIface && strings.Contains(prevLine, " dev "+prevTun+" ")) ||
			strings.Contains(k, "default")
		if !existed || prevLine != line || isTunBound {
			adds = append(adds, line)
		}
	}
	return append(dels, adds...)
}

func buildDeleteCmdFromShowLine(showLine, tableID string) string {
	fields := strings.Fields(showLine)
	key := extractRouteKey(fields)
	if key == "" {
		return ""
	}
	return fmt.Sprintf("route del %s table %s", key, tableID)
}

func splitBatchChunks(script string, maxLines int) []string {
	if maxLines <= 0 {
		maxLines = ipBatchChunkLines
	}
	var nonEmpty []string
	for _, l := range strings.Split(script, "\n") {
		if strings.TrimSpace(l) != "" {
			nonEmpty = append(nonEmpty, l)
		}
	}
	if len(nonEmpty) == 0 {
		return nil
	}
	chunks := make([]string, 0, (len(nonEmpty)+maxLines-1)/maxLines)
	for i := 0; i < len(nonEmpty); i += maxLines {
		end := i + maxLines
		if end > len(nonEmpty) {
			end = len(nonEmpty)
		}
		chunks = append(chunks, strings.Join(nonEmpty[i:end], "\n")+"\n")
	}
	return chunks
}

func runIPBatch(script string) error {
	return runIPBatchWithHooks(script, defaultShowTableRoutes, runIPBatchChunk)
}

func flushTableSafe(tableID string, showFn func(string) (string, error), chunkFn func(string, bool) error) error {
	out, err := showFn(tableID)
	if err != nil {
		// Fallback to direct single flush if listing failed (e.g. small table / unsupported show)
		return chunkFn(fmt.Sprintf("route flush table %s\n", tableID), false)
	}
	var delLines []string
	for _, raw := range strings.Split(out, "\n") {
		if cmd := buildDeleteCmdFromShowLine(raw, tableID); cmd != "" {
			delLines = append(delLines, cmd)
		}
	}
	if len(delLines) == 0 {
		return nil
	}
	for _, chunk := range splitBatchChunks(strings.Join(delLines, "\n"), ipDeleteBatchChunkLines) {
		if err := chunkFn(chunk, true); err != nil {
			return err
		}
	}
	return nil
}

func runIPBatchWithHooks(script string, showFn func(string) (string, error), chunkFn func(string, bool) error) error {
	var flushTables []string
	var delLines []string
	var otherLines []string

	for _, raw := range strings.Split(script, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "route flush table ") {
			tbl := strings.TrimSpace(strings.TrimPrefix(l, "route flush table "))
			if tbl != "" {
				flushTables = append(flushTables, tbl)
				continue
			}
		}
		if strings.HasPrefix(l, "route del ") {
			delLines = append(delLines, l)
			continue
		}
		otherLines = append(otherLines, l)
	}

	for _, tbl := range flushTables {
		// Avoid iproute2 netlink ENOBUFS during large table flushes (>100 routes) by deleting in chunks;
		// for smaller batches try quick flush first and fall back to chunked delete on any error.
		if len(otherLines) > 100 {
			if err := flushTableSafe(tbl, showFn, chunkFn); err != nil {
				return err
			}
		} else {
			if err := chunkFn(fmt.Sprintf("route flush table %s\n", tbl), false); err != nil {
				if err2 := flushTableSafe(tbl, showFn, chunkFn); err2 != nil {
					return err
				}
			}
		}
	}

	if len(delLines) > 0 {
		for _, chunk := range splitBatchChunks(strings.Join(delLines, "\n"), ipDeleteBatchChunkLines) {
			if err := chunkFn(chunk, true); err != nil {
				return err
			}
		}
	}

	if len(otherLines) > 0 {
		for _, chunk := range splitBatchChunks(strings.Join(otherLines, "\n"), ipBatchChunkLines) {
			if err := chunkFn(chunk, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func defaultShowTableRoutes(tableID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-4", "-o", "route", "show", "table", tableID).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route show table %s: %s (%w)", tableID, strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

func runIPBatchChunk(script string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var args []string
	if force {
		args = []string{"-force", "-batch", "-"}
	} else {
		args = []string{"-batch", "-"}
	}
	cmd := exec.CommandContext(ctx, "ip", args...)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		return fmt.Errorf("ip -batch: %s (%w)", msg, err)
	}
	return nil
}

func defaultDetectRoute(lanIface string) (string, []netip.Prefix) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "table", "main").Output()
	if err != nil {
		return "", nil
	}
	var gw string
	var connected []netip.Prefix
	var buf bytes.Buffer
	buf.Write(out)
	for _, line := range strings.Split(buf.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "default" {
			var foundGW, foundDev string
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "via" {
					foundGW = fields[i+1]
				} else if fields[i] == "dev" {
					foundDev = fields[i+1]
				}
			}
			if foundGW != "" && (foundDev == lanIface || gw == "") {
				gw = foundGW
			}
			continue
		}
		if pfx, err := netip.ParsePrefix(fields[0]); err == nil {
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "dev" && fields[i+1] == lanIface {
					connected = append(connected, pfx.Masked())
					break
				}
			}
		}
	}
	return gw, connected
}

func (p *PolicyEngine) hasIPv6Config() bool {
	cfgDir := filepath.Dir(p.rulesPath)
	if cfgDir == "" || cfgDir == "." {
		return false
	}
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
			continue
		}
		if strings.EqualFold(e.Name(), "rules.conf") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(cfgDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
				continue
			}
			eq := strings.IndexByte(trim, '=')
			if eq <= 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(trim[:eq]))
			val := trim[eq+1:]
			if key == "address" && strings.Contains(val, ":") {
				return true
			}
		}
	}
	return false
}
