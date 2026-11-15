package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	rosStaticComment      = "awg-ctl:static"
	rosDynCommentPrefix   = "awg-ctl:dyn:"
	rosStaticAddrTimeout  = "1d 00:00:00"
	maxDynStoreEntries    = 4096
	livePushTimeout       = 1500 * time.Millisecond
	liveBreakerCooldown   = 15 * time.Second
)

// DynEntry represents one DNS-learned IPv4 host persisted in ros-dynamic.json.
type DynEntry struct {
	Domain    string    `json:"domain"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DynIPStore persists dynamic DNS-learned IPv4 -> domain/rule entries for
// reboot recovery across address_list and bgp RouterOS modes.
type DynIPStore struct {
	path   string
	logger *RingLogger

	mu        sync.Mutex
	entries   map[string]DynEntry
	dirty     bool
	saveTimer *time.Timer
	closed    bool
}

func NewDynIPStore(path string, logger *RingLogger) *DynIPStore {
	s := &DynIPStore{
		path:    path,
		logger:  logger,
		entries: make(map[string]DynEntry),
	}
	s.load()
	return s
}

func (s *DynIPStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var loaded map[string]DynEntry
	if err := json.Unmarshal(raw, &loaded); err != nil {
		if s.logger != nil {
			s.logger.Logf("WARN load %s: %v", filepath.Base(s.path), err)
		}
		return
	}
	now := time.Now().UTC()
	for k, v := range loaded {
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(k))
		if parseErr != nil || !isSyncableIPv4Addr(addr) {
			continue
		}
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			continue
		}
		s.entries[addr.String()] = v
	}
}

func (s *DynIPStore) saveLocked() error {
	if s.path == "" {
		s.dirty = false
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.dirty = false
	return nil
}

func (s *DynIPStore) scheduleSaveLocked() {
	s.dirty = true
	if s.path == "" || s.closed {
		return
	}
	if s.saveTimer != nil {
		return
	}
	s.saveTimer = time.AfterFunc(2*time.Second, func() {
		s.mu.Lock()
		s.saveTimer = nil
		if s.dirty && !s.closed {
			if err := s.saveLocked(); err != nil && s.logger != nil {
				s.logger.Logf("WARN save %s: %v", filepath.Base(s.path), err)
			}
		}
		s.mu.Unlock()
	})
}

func (s *DynIPStore) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
		s.saveTimer = nil
	}
	if s.dirty {
		if err := s.saveLocked(); err != nil && s.logger != nil {
			s.logger.Logf("WARN flush %s: %v", filepath.Base(s.path), err)
		}
	}
}

func (s *DynIPStore) Close() {
	s.mu.Lock()
	s.closed = true
	if s.saveTimer != nil {
		s.saveTimer.Stop()
		s.saveTimer = nil
	}
	if s.dirty {
		_ = s.saveLocked()
	}
	s.mu.Unlock()
}

func (s *DynIPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return
	}
	s.entries = make(map[string]DynEntry)
	_ = s.saveLocked()
}

// Record stores or refreshes resolved IPv4 addresses and returns those that are new,
// changed rule, or past half their TTL (so RouterOS RAM timeouts stay fresh).
func (s *DynIPStore) Record(ips []netip.Addr, domain, rule string, ttl time.Duration) (toPush []netip.Addr, storeChanged bool) {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, e := range s.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(s.entries, k)
			s.dirty = true
			storeChanged = true
		}
	}

	for _, addr := range ips {
		if !isSyncableIPv4Addr(addr) {
			continue
		}
		key := addr.String()
		cur, exists := s.entries[key]
		needsPush := !exists || cur.Rule != rule || cur.Domain != domain
		if !needsPush && !cur.ExpiresAt.IsZero() && cur.ExpiresAt.Sub(now) < ttl/2 {
			needsPush = true
		}

		if !exists {
			if len(s.entries) >= maxDynStoreEntries {
				s.evictOldestLocked()
			}
			storeChanged = true
		}
		if needsPush {
			toPush = append(toPush, addr)
			s.entries[key] = DynEntry{
				Domain:    domain,
				Rule:      rule,
				ExpiresAt: exp,
				UpdatedAt: now,
			}
			storeChanged = true
		}
	}

	if storeChanged || s.dirty {
		s.scheduleSaveLocked()
	}
	return toPush, storeChanged
}

func (s *DynIPStore) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, v := range s.entries {
		if oldestKey == "" || v.UpdatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.UpdatedAt
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}

func (s *DynIPStore) Snapshot() map[netip.Addr]DynEntry {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[netip.Addr]DynEntry, len(s.entries))
	pruned := false
	for k, v := range s.entries {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(s.entries, k)
			pruned = true
			continue
		}
		if addr, err := netip.ParseAddr(k); err == nil && isSyncableIPv4Addr(addr) {
			out[addr] = v
		}
	}
	if pruned {
		s.scheduleSaveLocked()
	}
	return out
}

// Revalidate prunes expired entries and asks fn whether each entry still matches current rules.
func (s *DynIPStore) Revalidate(fn func(domain string, ip netip.Addr) (keep bool, newRule string)) (removed int) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	for k, v := range s.entries {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(s.entries, k)
			removed++
			changed = true
			continue
		}
		addr, err := netip.ParseAddr(k)
		if err != nil || !isSyncableIPv4Addr(addr) {
			delete(s.entries, k)
			removed++
			changed = true
			continue
		}
		if fn != nil {
			keep, newRule := fn(v.Domain, addr)
			if !keep {
				delete(s.entries, k)
				removed++
				changed = true
				continue
			}
			if newRule != "" && newRule != v.Rule {
				v.Rule = newRule
				s.entries[k] = v
				changed = true
			}
		}
	}
	if changed {
		s.scheduleSaveLocked()
	}
	return removed
}

func (s *DynIPStore) Prefixes() []netip.Prefix {
	snap := s.Snapshot()
	out := make([]netip.Prefix, 0, len(snap))
	for addr := range snap {
		out = append(out, netip.PrefixFrom(addr, 32))
	}
	sortPrefixes(out)
	return out
}

func (s *DynIPStore) Count() int {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	cnt := 0
	for _, v := range s.entries {
		if v.ExpiresAt.IsZero() || !now.After(v.ExpiresAt) {
			cnt++
		}
	}
	return cnt
}

// --- Address-List helpers & Binary/REST reconciliation ---

type addrListRow struct {
	ID       string
	List     string
	Address  string
	Comment  string
	Timeout  string
	Dynamic  bool
	Disabled bool
}

func isManagedROSComment(comment string) bool {
	c := strings.TrimSpace(comment)
	return c == "awg-ctl" || c == rosStaticComment || strings.HasPrefix(c, "awg-ctl:")
}

func formatDynComment(domain string) string {
	d := normalizeDomain(domain)
	d = strings.ReplaceAll(d, "\r", "")
	d = strings.ReplaceAll(d, "\n", "")
	if len(d) > 64 {
		d = d[:64]
	}
	if d == "" {
		return "awg-ctl:dyn"
	}
	return rosDynCommentPrefix + d
}

// normalizeAddrListKey converts prefixes to RouterOS canonical form:
// /32 hosts become bare IP strings ("1.2.3.4"), broader CIDRs stay masked ("1.2.3.0/24").
func normalizeAddrListKey(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		m := pfx.Masked()
		if m.Addr().Is4() && m.Bits() == 32 {
			return m.Addr().String()
		}
		return m.String()
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String()
	}
	return s
}

func normalizeAddrListPrefixKey(pfx netip.Prefix) string {
	m := pfx.Masked()
	if m.Addr().Is4() && m.Bits() == 32 {
		return m.Addr().String()
	}
	return m.String()
}

func rosExcludedHostAddrs(conn rosConnConfig, mgr *TunnelManager) []netip.Addr {
	var out []netip.Addr
	addStr := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			out = append(out, a)
		}
	}

	addStr(conn.gatewayIP)
	if conn.baseURL != "" {
		if u, err := url.Parse(conn.baseURL); err == nil && u.Hostname() != "" {
			addStr(u.Hostname())
		}
	}
	if conn.bgpPeerIP != "" {
		addStr(conn.bgpPeerIP)
	}
	if mgr != nil {
		for _, ep := range mgr.AllEndpoints() {
			addStr(ep)
		}
	}
	return out
}

func canUseBinAPI(conn rosConnConfig) (rosBinConfig, bool) {
	if !conn.useBinAPI || conn.binCfg.Addr == "" || conn.urlErr != "" {
		return rosBinConfig{}, false
	}
	return conn.binCfg, true
}

func isBinTransportFallbackErr(err error) bool {
	if err == nil {
		return false
	}
	var trap *rosBinTrapError
	if errors.As(err, &trap) {
		return false
	}
	return true
}

func (c *ROSClient) listAddressList(ctx context.Context, conn rosConnConfig, bin *ROSBinClient, listName string) ([]addrListRow, string, error) {
	if binCfg, ok := canUseBinAPI(conn); ok && bin != nil {
		rawRows, err := bin.Exec(
			ctx,
			binCfg,
			"/ip/firewall/address-list/print",
			"?list="+listName,
			"=.proplist=.id,list,address,comment,timeout,dynamic,disabled",
		)
		if err == nil {
			out := make([]addrListRow, 0, len(rawRows))
			for _, r := range rawRows {
				out = append(out, addrListRow{
					ID:       r[".id"],
					List:     r["list"],
					Address:  r["address"],
					Comment:  r["comment"],
					Timeout:  r["timeout"],
					Dynamic:  isTruthyROS(r["dynamic"]),
					Disabled: isTruthyROS(r["disabled"]),
				})
			}
			return out, "binapi", nil
		}
		if !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return nil, "binapi", err
		}
		if c.logger != nil {
			c.logger.Logf("ROS Binary API (%s) unavailable, using REST fallback: %v", binCfg.Addr, err)
		}
	}

	if conn.baseURL == "" {
		return nil, "", errors.New("RouterOS REST URL is not configured")
	}
	rawRows, err := c.listResources(
		conn,
		"/ip/firewall/address-list",
		[]string{".id", "list", "address", "comment", "timeout", "dynamic", "disabled"},
		[]string{"list=" + listName},
	)
	if err != nil {
		return nil, "rest", err
	}
	out := make([]addrListRow, 0, len(rawRows))
	for _, r := range rawRows {
		rowList := strField(r, "list")
		if rowList != "" && rowList != listName {
			continue
		}
		out = append(out, addrListRow{
			ID:       strField(r, ".id"),
			List:     rowList,
			Address:  strField(r, "address"),
			Comment:  strField(r, "comment"),
			Timeout:  strField(r, "timeout"),
			Dynamic:  isTruthyROS(r["dynamic"]),
			Disabled: isTruthyROS(r["disabled"]),
		})
	}
	return out, "rest", nil
}

func (c *ROSClient) findSingleAddressListRow(ctx context.Context, conn rosConnConfig, bin *ROSBinClient, listName, addrKey string, useBin bool) (*addrListRow, error) {
	if useBin {
		if binCfg, ok := canUseBinAPI(conn); ok && bin != nil {
			rows, err := bin.Exec(
				ctx,
				binCfg,
				"/ip/firewall/address-list/print",
				"?list="+listName,
				"?address="+addrKey,
				"=.proplist=.id,list,address,comment,timeout,dynamic,disabled",
			)
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if normalizeAddrListKey(r["address"]) == addrKey {
					return &addrListRow{
						ID:       r[".id"],
						List:     r["list"],
						Address:  r["address"],
						Comment:  r["comment"],
						Timeout:  r["timeout"],
						Dynamic:  isTruthyROS(r["dynamic"]),
						Disabled: isTruthyROS(r["disabled"]),
					}, nil
				}
			}
			return nil, nil
		}
	}

	if conn.baseURL == "" {
		return nil, nil
	}
	rows, err := c.listResources(
		conn,
		"/ip/firewall/address-list",
		[]string{".id", "list", "address", "comment", "timeout", "dynamic", "disabled"},
		[]string{"list=" + listName, "address=" + addrKey},
	)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		rowList := strField(r, "list")
		if rowList != "" && rowList != listName {
			continue
		}
		if normalizeAddrListKey(strField(r, "address")) == addrKey {
			return &addrListRow{
				ID:       strField(r, ".id"),
				List:     rowList,
				Address:  strField(r, "address"),
				Comment:  strField(r, "comment"),
				Timeout:  strField(r, "timeout"),
				Dynamic:  isTruthyROS(r["dynamic"]),
				Disabled: isTruthyROS(r["disabled"]),
			}, nil
		}
	}
	return nil, nil
}

func (c *ROSClient) upsertAddressListEntry(ctx context.Context, conn rosConnConfig, bin *ROSBinClient, listName, addrKey, comment, timeout string) (string, error) {
	if binCfg, ok := canUseBinAPI(conn); ok && bin != nil {
		args := []string{
			"=list=" + listName,
			"=address=" + addrKey,
			"=comment=" + comment,
		}
		if timeout != "" {
			args = append(args, "=timeout="+timeout)
		}
		_, err := bin.Exec(ctx, binCfg, "/ip/firewall/address-list/add", args...)
		if err == nil {
			return "binapi", nil
		}
		if isROSAlreadyExistsErr(err) {
			existing, fErr := c.findSingleAddressListRow(ctx, conn, bin, listName, addrKey, true)
			if fErr == nil && existing != nil {
				if !isManagedROSComment(existing.Comment) {
					// Preserve user's manual address-list entry untouched.
					return "binapi", nil
				}
				if existing.ID != "" {
					if uErr := c.updateAddressListEntry(ctx, conn, bin, existing.ID, comment, timeout, true); uErr == nil {
						return "binapi", nil
					}
				}
				return "binapi", nil
			}
			return "binapi", nil
		}
		if !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return "binapi", err
		}
	}

	if conn.baseURL == "" {
		return "", errors.New("RouterOS REST URL is not configured")
	}
	payload := map[string]any{
		"list":    listName,
		"address": addrKey,
		"comment": comment,
	}
	if timeout != "" {
		payload["timeout"] = timeout
	}
	_, status, err := c.doWithConn(conn, http.MethodPut, "/ip/firewall/address-list", payload)
	if err == nil {
		return "rest", nil
	}
	if status == http.StatusBadRequest && isROSAlreadyExistsErr(err) {
		existing, fErr := c.findSingleAddressListRow(ctx, conn, nil, listName, addrKey, false)
		if fErr == nil && existing != nil {
			if !isManagedROSComment(existing.Comment) {
				return "rest", nil
			}
			if existing.ID != "" {
				if uErr := c.updateAddressListEntry(ctx, conn, nil, existing.ID, comment, timeout, false); uErr == nil {
					return "rest", nil
				}
			}
		}
		return "rest", nil
	}
	return "rest", err
}

func (c *ROSClient) updateAddressListEntry(ctx context.Context, conn rosConnConfig, bin *ROSBinClient, id, comment, timeout string, preferBin bool) error {
	if preferBin {
		if binCfg, ok := canUseBinAPI(conn); ok && bin != nil {
			args := []string{
				"=.id=" + id,
				"=comment=" + comment,
				"=disabled=no",
			}
			if timeout != "" {
				args = append(args, "=timeout="+timeout)
			}
			_, err := bin.Exec(ctx, binCfg, "/ip/firewall/address-list/set", args...)
			if err == nil || !isBinTransportFallbackErr(err) || conn.baseURL == "" {
				return err
			}
		}
	}

	if conn.baseURL == "" {
		return errors.New("RouterOS REST URL is not configured")
	}
	patch := map[string]any{
		"comment":  comment,
		"disabled": "false",
	}
	if timeout != "" {
		patch["timeout"] = timeout
	}
	_, _, err := c.doWithConn(conn, http.MethodPatch, "/ip/firewall/address-list/"+id, patch)
	return err
}

func (c *ROSClient) removeAddressListEntry(ctx context.Context, conn rosConnConfig, bin *ROSBinClient, id string) error {
	if binCfg, ok := canUseBinAPI(conn); ok && bin != nil {
		_, err := bin.Exec(ctx, binCfg, "/ip/firewall/address-list/remove", "=.id="+id)
		if err == nil || !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return err
		}
	}
	if conn.baseURL == "" {
		return errors.New("RouterOS REST URL is not configured")
	}
	_, _, err := c.doWithConn(conn, http.MethodDelete, "/ip/firewall/address-list/"+id, nil)
	return err
}

func shouldRefreshTimeout(curTimeoutStr string, targetTTL time.Duration, hasDynamic bool) bool {
	if targetTTL <= 0 {
		return false
	}
	if !hasDynamic || strings.TrimSpace(curTimeoutStr) == "" {
		return true
	}
	rem, ok := parseROSDuration(curTimeoutStr)
	if !ok {
		return false
	}
	return rem < targetTTL/2
}

type addrListDesired struct {
	Key     string
	Comment string
	Timeout string
	TTL     time.Duration
	IsDyn   bool
}

func (c *ROSClient) buildDesiredAddressList(conn rosConnConfig, mgr *TunnelManager) (desired map[string]addrListDesired, staticCount, dynCount, droppedByLimit int) {
	desired = make(map[string]addrListDesired)

	c.mu.Lock()
	pol := c.policy
	dynStore := c.dynStore
	c.mu.Unlock()

	var exclude []netip.Addr
	if pol != nil {
		exclude = rosExcludedHostAddrs(conn, mgr)
	}

	if pol != nil && conn.syncPolicyCIDRs {
		plan := pol.ComputeRouterOSPrefixes(conn.staticPrefixLimit, exclude...)
		droppedByLimit = plan.DroppedByLimit
		staticTTL, _ := parseROSDuration(rosStaticAddrTimeout)
		for _, pfx := range plan.Prefixes {
			key := normalizeAddrListPrefixKey(pfx)
			if _, exists := desired[key]; exists {
				continue
			}
			desired[key] = addrListDesired{
				Key:     key,
				Comment: rosStaticComment,
				Timeout: rosStaticAddrTimeout,
				TTL:     staticTTL,
			}
			staticCount++
		}
	}

	if dynStore != nil {
		if pol != nil {
			dynStore.Revalidate(func(domain string, ip netip.Addr) (bool, string) {
				return pol.RevalidateDynamicHostIP(domain, ip, exclude...)
			})
		}
		dynTimeoutStr := normalizeROSDynamicTimeout(conn.dynamicTimeout)
		dynTTL, ok := parseROSDuration(dynTimeoutStr)
		if !ok {
			dynTimeoutStr = "12:00:00"
			dynTTL = 12 * time.Hour
		}
		snap := dynStore.Snapshot()
		for addr, entry := range snap {
			key := addr.String()
			if _, exists := desired[key]; exists {
				continue
			}
			desired[key] = addrListDesired{
				Key:     key,
				Comment: formatDynComment(entry.Domain),
				Timeout: dynTimeoutStr,
				TTL:     dynTTL,
				IsDyn:   true,
			}
			dynCount++
		}
	}

	return desired, staticCount, dynCount, droppedByLimit
}

func (c *ROSClient) syncPolicyAddressListWithConn(conn rosConnConfig, mgr *TunnelManager) (staticSynced, dynSynced, droppedByLimit int, transport string, err error) {
	listName := strings.TrimSpace(conn.addrList)
	if listName == "" {
		listName = "AmneziaWGRoS"
	}

	desired, staticCount, dynCount, droppedByLimit := c.buildDesiredAddressList(conn, mgr)
	_ = staticCount
	_ = dynCount

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	existing, transport, err := c.listAddressList(ctx, conn, c.binSync, listName)
	if err != nil {
		return 0, 0, droppedByLimit, transport, err
	}

	manualCovered := make(map[string]bool)
	kept := make(map[string]addrListDesired)

	for _, row := range existing {
		key := normalizeAddrListKey(row.Address)
		if key == "" {
			continue
		}
		if !isManagedROSComment(row.Comment) {
			if !row.Disabled {
				manualCovered[key] = true
			}
			continue
		}

		want, ok := desired[key]
		if ok && !manualCovered[key] {
			if _, alreadyKept := kept[key]; !alreadyKept {
				needsUpdate := row.Disabled || row.Comment != want.Comment || shouldRefreshTimeout(row.Timeout, want.TTL, row.Dynamic)
				if !needsUpdate {
					kept[key] = want
					continue
				}
				if row.ID != "" {
					if uErr := c.updateAddressListEntry(ctx, conn, c.binSync, row.ID, want.Comment, want.Timeout, transport == "binapi"); uErr == nil {
						kept[key] = want
						continue
					} else if !isROSAlreadyExistsErr(uErr) {
						return 0, 0, droppedByLimit, transport, uErr
					}
				}
			}
		}

		if row.ID != "" {
			if dErr := c.removeAddressListEntry(ctx, conn, c.binSync, row.ID); dErr != nil {
				return 0, 0, droppedByLimit, transport, dErr
			}
		}
	}

	keys := make([]string, 0, len(desired))
	for k := range desired {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if manualCovered[key] {
			continue
		}
		if _, ok := kept[key]; ok {
			continue
		}
		want := desired[key]
		usedTr, uErr := c.upsertAddressListEntry(ctx, conn, c.binSync, listName, want.Key, want.Comment, want.Timeout)
		if uErr != nil {
			return 0, 0, droppedByLimit, transport, uErr
		}
		if usedTr != "" {
			transport = usedTr
		}
		kept[key] = want
	}

	for _, w := range kept {
		if w.IsDyn {
			dynSynced++
		} else {
			staticSynced++
		}
	}
	return staticSynced, dynSynced, droppedByLimit, transport, nil
}

// EnsureDynamicIPs records resolved IPv4 addresses for an explicit PROXY domain rule and pushes
// any new or expiring IPs to RouterOS immediately using a lock-free fast path so DNS does not stall.
func (c *ROSClient) EnsureDynamicIPs(domain, matchedRule string, ips []netip.Addr) {
	if c == nil || len(ips) == 0 {
		return
	}
	c.mu.Lock()
	mode := c.rosMode
	enabled := c.baseURL != "" && c.user != "" && c.urlErr == ""
	dynStore := c.dynStore
	dynTimeoutStr := normalizeROSDynamicTimeout(c.dynamicTimeout)
	listName := strings.TrimSpace(c.addrList)
	c.mu.Unlock()

	if dynStore == nil {
		return
	}
	if mode != ROSModeAddressList && mode != ROSModeBGP {
		return
	}
	if listName == "" {
		listName = "AmneziaWGRoS"
	}

	dynTTL, ok := parseROSDuration(dynTimeoutStr)
	if !ok {
		dynTimeoutStr = "12:00:00"
		dynTTL = 12 * time.Hour
	}

	toPush, storeChanged := dynStore.Record(ips, domain, matchedRule, dynTTL)

	if mode == ROSModeBGP {
		if storeChanged || len(toPush) > 0 {
			c.refreshBGPDesiredPrefixes()
		}
		return
	}

	// address_list mode real-time injection
	if len(toPush) == 0 {
		return
	}
	conn := c.connSnapshot()
	if !enabled {
		return
	}

	c.liveBreakerMu.Lock()
	brokenUntil := c.liveBreakerUntil
	c.liveBreakerMu.Unlock()
	if time.Now().Before(brokenUntil) {
		return
	}

	comment := formatDynComment(domain)
	usedTransport := ""
	for _, addr := range toPush {
		ctx, cancel := context.WithTimeout(context.Background(), livePushTimeout)
		tr, err := c.upsertAddressListEntry(ctx, conn, c.binLive, listName, addr.String(), comment, dynTimeoutStr)
		cancel()
		if err != nil {
			c.liveBreakerMu.Lock()
			c.liveBreakerUntil = time.Now().Add(liveBreakerCooldown)
			c.liveBreakerMu.Unlock()
			if c.logger != nil {
				c.logger.Logf("WARN ROS live dynamic push (%s -> %s): %v", domain, addr, err)
			}
			return
		}
		if tr != "" {
			usedTransport = tr
		}
	}

	if usedTransport != "" {
		c.mu.Lock()
		c.status.Transport = usedTransport
		c.status.DynSynced = dynStore.Count()
		c.mu.Unlock()
	}
}

// PushDynamicFromDNS checks policy eligibility and forwards resolved IPv4 answers
// when operating in address_list or bgp RouterOS mode.
func (c *ROSClient) PushDynamicFromDNS(domain string, ips []netip.Addr) {
	if c == nil || len(ips) == 0 {
		return
	}
	c.mu.Lock()
	mode := c.rosMode
	pol := c.policy
	mgr := c.mgr
	c.mu.Unlock()

	if (mode != ROSModeAddressList && mode != ROSModeBGP) || pol == nil {
		return
	}
	conn := c.connSnapshot()
	exclude := rosExcludedHostAddrs(conn, mgr)
	okROS, rule, filtered := pol.EvaluateForRouterOS(domain, ips, exclude...)
	if !okROS || len(filtered) == 0 {
		return
	}
	c.EnsureDynamicIPs(domain, rule, filtered)
}
