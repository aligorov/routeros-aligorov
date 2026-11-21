package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tiny protobuf wire encoder helpers for constructing synthetic geosite.dat / geoip.dat in tests.
func pbVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func pbTagVarint(field int, v uint64) []byte {
	out := pbVarint(uint64(field<<3) | 0)
	return append(out, pbVarint(v)...)
}

func pbTagBytes(field int, b []byte) []byte {
	out := pbVarint(uint64(field<<3) | 2)
	out = append(out, pbVarint(uint64(len(b)))...)
	return append(out, b...)
}

func TestSettingsStorePersistenceAndPasswordMasking(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore: %v", err)
	}
	v := st.View()
	if v.DefaultPolicy != "proxy" || v.ROSPassSet {
		t.Fatalf("unexpected defaults: %+v", v)
	}

	cur := st.Get()
	cur.DefaultPolicy = "direct"
	cur.ROSURL = "https://172.18.0.1/"
	cur.ROSUser = "api"
	cur.ROSPass = "secret123"
	if _, err := st.Update(SettingsUpdate{AppSettings: cur}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	view := st.View()
	if view.ROSPass != "" || !view.ROSPassSet || view.ROSURL != "https://172.18.0.1" {
		t.Fatalf("expected masked ROSPass + set flag + trimmed URL, got %+v", view)
	}

	// Updating another setting with empty ROSPass must preserve secret123
	cur2 := view.AppSettings
	cur2.DirectDNS = "77.88.8.8:53"
	updated, err := st.Update(SettingsUpdate{AppSettings: cur2})
	if err != nil || updated.ROSPass != "secret123" || updated.DirectDNS != "77.88.8.8:53" {
		t.Fatalf("password lost or update failed: %+v, err=%v", updated, err)
	}

	// Re-open from disk
	st2, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if st2.Get().DefaultPolicy != "direct" || st2.Get().ROSPass != "secret123" {
		t.Fatalf("did not persist to disk: %+v", st2.Get())
	}

	// Clear password explicitly
	if _, err := st2.Update(SettingsUpdate{AppSettings: st2.View().AppSettings, ClearROSPass: true}); err != nil {
		t.Fatalf("clear pass: %v", err)
	}
	if st2.Get().ROSPass != "" || st2.View().ROSPassSet {
		t.Fatalf("password should be cleared: %+v", st2.View())
	}
}

func TestGeoProtobufAndTextParsing(t *testing.T) {
	// Construct GeoSiteList: "ru" (RootDomain yandex.ru, Full id.vk.com), "ads" (Plain tracker, Regex ^ad\.)
	dom := func(kind uint64, val string) []byte {
		var b []byte
		b = append(b, pbTagVarint(1, kind)...)
		b = append(b, pbTagBytes(2, []byte(val))...)
		return b
	}
	ruSite := append(pbTagBytes(1, []byte("RU")), pbTagBytes(2, dom(2, "yandex.ru"))...)
	ruSite = append(ruSite, pbTagBytes(2, dom(3, "id.vk.com"))...)
	adsSite := append(pbTagBytes(1, []byte("category-ads-all")), pbTagBytes(2, dom(0, "doubleclick"))...)
	adsSite = append(adsSite, pbTagBytes(2, dom(1, `^ad[0-9]*\.`))...)
	siteBlob := append(pbTagBytes(1, ruSite), pbTagBytes(1, adsSite)...)

	// Construct GeoIPList: "ru" (77.88.0.0/18 + ipv6), "unused" (1.2.3.0/24)
	cidr4 := pbTagBytes(1, []byte{77, 88, 0, 0})
	cidr4 = append(cidr4, pbTagVarint(2, 18)...)
	cidr6 := pbTagBytes(1, []byte{0x2a, 0x02, 0x06, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	cidr6 = append(cidr6, pbTagVarint(2, 32)...)
	ruIP := append(pbTagBytes(1, []byte("RU")), pbTagBytes(2, cidr4)...)
	ruIP = append(ruIP, pbTagBytes(2, cidr6)...)
	unIP := append(pbTagBytes(1, []byte("UNUSED")), pbTagBytes(2, append(pbTagBytes(1, []byte{1, 2, 3, 0}), pbTagVarint(2, 24)...))...)
	ipBlob := append(pbTagBytes(1, ruIP), pbTagBytes(1, unIP)...)

	dir := t.TempDir()
	logger := NewRingLogger(20)
	gs := NewGeoStore(dir, logger)
	if err := os.MkdirAll(filepath.Join(dir, "geo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gs.sitePath(), siteBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gs.ipPath(), ipBlob, 0o600); err != nil {
		t.Fatal(err)
	}

	// Selectively load only ru and category-ads-all (leave unused unmaterialized)
	if err := gs.Reload(map[string]bool{"ru": true, "category-ads-all": true}, map[string]bool{"ru": true}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	st := gs.Status()
	if !st.GeoSiteLoaded || !st.GeoIPLoaded || len(st.GeoSiteCategories) != 2 || len(st.GeoIPCategories) != 2 {
		t.Fatalf("unexpected geo status: %+v", st)
	}
	if !gs.MatchSite("ru", "mail.yandex.ru") || !gs.MatchSite("ru", "id.vk.com") || gs.MatchSite("ru", "sub.id.vk.com") {
		t.Fatalf("unexpected ru geosite match behavior")
	}
	if !gs.MatchSite("category-ads-all", "ad1.example.com") || !gs.MatchSite("category-ads-all", "g.doubleclick.net") {
		t.Fatalf("expected ads matches")
	}
	if !gs.MatchIP("ru", netip.MustParseAddr("77.88.8.8")) || gs.MatchIP("ru", netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("unexpected geoip match for ru")
	}
	if gs.CategoryIPs("unused") != nil {
		t.Fatalf("expected unreferenced geoip category to stay lazy/unloaded")
	}
}

func TestPolicyMatchingAndBatchScript(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(50)
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	gs := NewGeoStore(dir, logger)
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "veth0", true, true, logger)
	pe := NewPolicyEngine(dir, st, gs, mgr, logger)

	var recordedBatches []string
	var recordedCmds []string
	pe.detectRouteFn = func(lanIface string) (string, []netip.Prefix) {
		return "172.18.0.1", []netip.Prefix{netip.MustParsePrefix("172.18.0.0/24")}
	}
	pe.runBatchFn = func(script string) error {
		recordedBatches = append(recordedBatches, script)
		return nil
	}
	pe.runCmdFn = func(name string, args ...string) error {
		recordedCmds = append(recordedCmds, name+" "+strings.Join(args, " "))
		return nil
	}

	rulesRaw := `
# Test rules (first match wins)
DROP,keyword:tracker
DIRECT,domain:yandex.ru
PROXY,full:special.yandex.ru
DIRECT,10.0.0.0/8
DROP,8.8.8.8
`
	rules, err := pe.SaveRules(rulesRaw)
	if err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("expected 5 parsed rules, got %d", len(rules))
	}

	if act, _ := pe.MatchDomain("ad.tracker.net"); act != ActionDrop {
		t.Fatalf("expected DROP for tracker, got %s", act)
	}
	if act, _ := pe.MatchDomain("special.yandex.ru"); act != ActionDirect {
		// domain:yandex.ru appears BEFORE full:special.yandex.ru -> first match wins!
		t.Fatalf("expected DIRECT (first-match-wins), got %s", act)
	}
	if act, _ := pe.MatchDomain("youtube.com"); act != ActionProxy {
		t.Fatalf("expected default PROXY for youtube.com, got %s", act)
	}

	// Build batch script explicitly with awg0 UP and learned /32
	learned := map[netip.Addr]learnedEntry{
		netip.MustParseAddr("77.88.8.8"): {Action: ActionDirect, Domain: "yandex.ru", Rule: "domain:yandex.ru", Target: "via:172.18.0.1"},
	}
	script, staticCnt := pe.BuildBatchScript(
		"veth0", "172.18.0.1", "awg0", ActionProxy, true,
		[]netip.Prefix{netip.MustParsePrefix("172.18.0.0/24")},
		rules, learned,
	)
	if staticCnt != 2 {
		t.Fatalf("expected 2 static IP rules, got %d\n%s", staticCnt, script)
	}
	for _, must := range []string{
		"route flush table 210",
		"route replace throw 172.18.0.0/24 table 210",
		"route replace 10.0.0.0/8 via 172.18.0.1 dev veth0 table 210",
		"route replace blackhole 8.8.8.8/32 table 210",
		"route replace 77.88.8.8/32 via 172.18.0.1 dev veth0 table 210",
		"route replace default dev awg0 metric 10 table 210",
		"route replace blackhole default metric 254 table 210",
	} {
		if !strings.Contains(script, must) {
			t.Fatalf("missing %q in batch script:\n%s", must, script)
		}
	}

	// Verify RecordResolvedIPs deduplicates repeated /32 insertions and triggers batch once
	recordedBatches = nil
	pe.RecordResolvedIPs("yandex.ru", ActionDirect, "domain:yandex.ru", []netip.Addr{netip.MustParseAddr("5.255.255.77")})
	pe.RecordResolvedIPs("yandex.ru", ActionDirect, "domain:yandex.ru", []netip.Addr{netip.MustParseAddr("5.255.255.77")})
	if len(recordedBatches) != 1 || !strings.Contains(recordedBatches[0], "route replace 5.255.255.77/32 via 172.18.0.1 dev veth0 table 210") {
		t.Fatalf("unexpected dynamic batches: %#v", recordedBatches)
	}
	if len(recordedCmds) == 0 {
		t.Fatalf("expected ip rule / iptables setup commands on ApplyRouting")
	}
}

func TestDNSWireHelpers(t *testing.T) {
	// Build minimal DNS query for "ads.example.com" QTYPE=A
	q := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		3, 'a', 'd', 's',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	qname, qtype, qEnd, ok := parseDNSQuestion(q)
	if !ok || qname != "ads.example.com" || qtype != 1 || qEnd != len(q) {
		t.Fatalf("parseDNSQuestion failed: ok=%v qname=%q qtype=%d qEnd=%d", ok, qname, qtype, qEnd)
	}

	nxd := buildDNSReplyError(q, qEnd, 3)
	if len(nxd) != qEnd || nxd[0] != 0x12 || nxd[1] != 0x34 || (nxd[2]&0x80) == 0 || (nxd[3]&0x0f) != 3 {
		t.Fatalf("unexpected NXDOMAIN packet: %x", nxd)
	}

	// Build DNS response with compressed pointer answer (0xC0 0x0C) -> 93.184.216.34
	resp := append([]byte(nil), q...)
	resp[2] = 0x81
	resp[3] = 0x80
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT=1
	resp = append(resp,
		0xC0, 0x0C, // pointer to QNAME at offset 12
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLEN 4
		93, 184, 216, 34,
	)
	ips := extractDNSAnswerIPv4s(resp)
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("extractDNSAnswerIPv4s failed: %+v", ips)
	}
}

func TestWebHealthReadyVsTunnelHealth(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", true, true, logger)
	ws := NewWebServer(":8080", mgr, nil, nil, nil, nil, nil, logger)

	reqReady := httptest.NewRequest(http.MethodGet, "/health", nil)
	rwReady := httptest.NewRecorder()
	ws.handleReady(rwReady, reqReady)
	if rwReady.Code != http.StatusOK {
		t.Fatalf("expected /health 200 OK even without tunnels so RouterOS healthcheck passes, got %d: %s", rwReady.Code, rwReady.Body.String())
	}

	reqTun := httptest.NewRequest(http.MethodGet, "/health?tunnel=1", nil)
	rwTun := httptest.NewRecorder()
	ws.handleReady(rwTun, reqTun)
	if rwTun.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected /health?tunnel=1 503 when no awg interfaces are active, got %d", rwTun.Code)
	}
}

func TestRunIPBatchLargeTableSafeFlushAndDiffSync(t *testing.T) {
	// 1. Large script (>100 routes) must NOT emit "route flush table 210" directly;
	//    it must query `ip route show` and delete existing routes in <=150 chunks with force=true.
	var sb strings.Builder
	sb.WriteString("route flush table 210\n")
	var showOut strings.Builder
	for i := 0; i < 450; i++ {
		cidr := fmt.Sprintf("10.%d.%d.0/24", i/250, i%250)
		fmt.Fprintf(&sb, "route replace %s via 172.19.0.1 dev veth0 table 210\n", cidr)
		fmt.Fprintf(&showOut, "%s via 172.19.0.1 dev veth0 proto boot\n", cidr)
	}
	showOut.WriteString("blackhole default metric 254\n")

	type batchCall struct {
		script string
		force  bool
		lines  int
	}
	var calls []batchCall
	err := runIPBatchWithHooks(
		sb.String(),
		func(tableID string) (string, error) {
			if tableID != "210" {
				t.Fatalf("unexpected tableID %s", tableID)
			}
			return showOut.String(), nil
		},
		func(chunk string, force bool) error {
			if strings.Contains(chunk, "route flush ") {
				t.Fatalf("large flush should not send route flush command: %s", chunk)
			}
			lines := 0
			for _, l := range strings.Split(strings.TrimSpace(chunk), "\n") {
				if strings.TrimSpace(l) != "" {
					lines++
				}
			}
			calls = append(calls, batchCall{script: chunk, force: force, lines: lines})
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runIPBatchWithHooks large failed: %v", err)
	}
	if len(calls) < 6 {
		t.Fatalf("expected chunked deletes + chunked replaces, got %d calls", len(calls))
	}
	if !calls[0].force || !strings.Contains(calls[0].script, "route del 10.0.0.0/24 table 210") {
		t.Fatalf("expected first calls to force-delete existing routes, got force=%v: %s", calls[0].force, calls[0].script)
	}
	for _, c := range calls {
		if c.force && c.lines > ipDeleteBatchChunkLines {
			t.Fatalf("delete chunk exceeded limit: %d > %d", c.lines, ipDeleteBatchChunkLines)
		}
		if !c.force && c.lines > ipBatchChunkLines {
			t.Fatalf("replace chunk exceeded limit: %d > %d", c.lines, ipBatchChunkLines)
		}
	}

	// 2. Small script fallback if "route flush table 210" hits ENOBUFS
	var smallCalls []string
	err = runIPBatchWithHooks(
		"route flush table 210\nroute replace default dev awg0 metric 10 table 210\n",
		func(_ string) (string, error) {
			return "default dev oldwg scope link metric 10\n", nil
		},
		func(chunk string, force bool) error {
			if strings.Contains(chunk, "route flush ") {
				return fmt.Errorf("ip -batch: Failed to send flush request: No buffer space available")
			}
			smallCalls = append(smallCalls, fmt.Sprintf("force=%v:%s", force, strings.TrimSpace(chunk)))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("small fallback failed: %v", err)
	}
	if len(smallCalls) != 2 || !strings.Contains(smallCalls[0], "route del default metric 10 table 210") {
		t.Fatalf("unexpected fallback calls: %#v", smallCalls)
	}

	// 3. Diff-sync on ApplyRouting when switching tunnels avoids re-sending 300+ unchanged DIRECT routes
	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	gs := NewGeoStore(dir, NewRingLogger(20))
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "veth0", true, true, NewRingLogger(20))
	pe := NewPolicyEngine(dir, st, gs, mgr, NewRingLogger(20))

	var rulesTxt strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&rulesTxt, "DIRECT,10.%d.%d.0/24\n", i/200, i%200)
	}
	rulesTxt.WriteString("PROXY,1.1.1.0/24\n")
	pe.detectRouteFn = func(string) (string, []netip.Prefix) {
		return "172.19.0.1", nil
	}
	pe.runCmdFn = func(string, ...string) error { return nil }
	var appliedBatches []string
	pe.runBatchFn = func(script string) error {
		appliedBatches = append(appliedBatches, script)
		return nil
	}
	curTun := "awg0"
	pe.activeTunFn = func() string { return curTun }
	if _, err := pe.SaveRules(rulesTxt.String()); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	if len(appliedBatches) != 1 || !strings.Contains(appliedBatches[0], "route flush table 210") {
		t.Fatalf("first apply should send full script, got %d batches", len(appliedBatches))
	}

	// Switch tunnel awg0 -> awg1 and re-apply
	appliedBatches = nil
	curTun = "awg1"
	if err := pe.ApplyRouting(); err != nil {
		t.Fatalf("second ApplyRouting failed: %v", err)
	}
	if len(appliedBatches) != 1 {
		t.Fatalf("expected 1 diff batch, got %d", len(appliedBatches))
	}
	diffLines := strings.Count(strings.TrimSpace(appliedBatches[0]), "\n") + 1
	if diffLines > 5 {
		t.Fatalf("expected tiny diff batch (<=5 lines) instead of re-sending 300 routes, got %d lines:\n%s", diffLines, appliedBatches[0])
	}
	if !strings.Contains(appliedBatches[0], "route replace 1.1.1.0/24 dev awg1 table 210") ||
		!strings.Contains(appliedBatches[0], "route replace default dev awg1 metric 10 table 210") {
		t.Fatalf("diff batch missing updated awg1 routes:\n%s", appliedBatches[0])
	}
}
