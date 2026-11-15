package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	lastGateway  string
	lastTunIface string
	staticCount  int
	lastApplyErr string

	queriesTotal  atomic.Uint64
	matchedProxy  atomic.Uint64
	matchedDirect atomic.Uint64
	matchedDrop   atomic.Uint64

	// Injectable hooks for tests
	detectRouteFn func(lanIface string) (gw string, connected []netip.Prefix)
	runBatchFn    func(script string) error
	runCmdFn      func(name string, args ...string) error
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
	}
	pe.detectRouteFn = defaultDetectRoute
	pe.runBatchFn = runIPBatch
	pe.runCmdFn = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
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
				batchLines = append(batchLines, fmt.Sprintf("route replace blackhole %s/32 metric 254 table %s", addr.String(), PolicyTableID))
			} else if routeTarget != "" {
				batchLines = append(batchLines, fmt.Sprintf("route replace %s/32 %s table %s", addr.String(), routeTarget, PolicyTableID))
			}
		}
	}
	p.mu.Unlock()

	if len(batchLines) > 0 && lanIface != "" {
		if err := p.runBatchFn(strings.Join(batchLines, "\n") + "\n"); err != nil {
			p.logger.Logf("WARN policy dynamic /32 batch: %v", err)
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

func (p *PolicyEngine) activeTunnelIface() string {
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
	p.mu.RUnlock()

	script, staticCount := p.BuildBatchScript(lanIface, gw, tunIface, defAction, killSwitch, connected, rules, learnedSnap)

	// Install table 210 routes
	var applyErr error
	if err := p.runBatchFn(script); err != nil {
		applyErr = err
		p.logger.Logf("WARN policy batch error: %v", err)
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

	p.mu.Lock()
	p.lastGateway = gw
	p.lastTunIface = tunIface
	p.staticCount = staticCount
	if applyErr != nil {
		p.lastApplyErr = applyErr.Error()
	} else {
		p.lastApplyErr = ""
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

func runIPBatch(script string) error {
	cmd := exec.Command("ip", "-batch", "-")
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
	out, err := exec.Command("ip", "-4", "route", "show", "table", "main").Output()
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
