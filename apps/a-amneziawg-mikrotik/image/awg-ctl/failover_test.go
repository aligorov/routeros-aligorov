package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestMultiTunnelPlanConflictsAndPerRuleTarget(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(50)
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewTunnelManager(dir, dir+"/run", "eth0", true, true, logger)
	_ = mgr.SaveConfig("a.conf", "[Interface]\nAddress = 10.0.0.2/32\nListenPort = 51820\nPrivateKey = k1=\n[Peer]\nEndpoint = 1.2.3.4:51820\nPublicKey = p1=\nAllowedIPs = 0.0.0.0/0\n")
	_ = mgr.SaveConfig("b.conf", "[Interface]\nAddress = 10.0.0.2/32\nListenPort = 51820\nPrivateKey = k2=\n[Peer]\nEndpoint = 1.2.3.4:51820\nPublicKey = p2=\nAllowedIPs = 0.0.0.0/0\n")
	_ = mgr.SaveConfig("c.conf", "[Interface]\nAddress = 10.0.0.3/32\nPrivateKey = k3=\n[Peer]\nEndpoint = 5.6.7.8:51820\nPublicKey = p3=\nAllowedIPs = 0.0.0.0/0\n")

	mgr.SetTunnelPlan([]string{"c.conf", "a.conf", "b.conf"}, []string{"b.conf"})
	cfgs, err := mgr.ListConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 3 || cfgs[0].Name != "c.conf" || cfgs[1].Name != "a.conf" || cfgs[2].Name != "b.conf" {
		t.Fatalf("unexpected tunnel order: %+v", cfgs)
	}
	if !cfgs[2].Disabled || cfgs[2].Priority != 0 || cfgs[0].Priority != 1 || cfgs[1].Priority != 2 {
		t.Fatalf("unexpected priorities/disabled flags: %+v", cfgs)
	}
	// Active b.conf disabled -> multi start selects c,a excluding b; active a.conf puts a first
	got := selectStartConfigs(cfgs, "a.conf", true)
	if len(got) != 2 || got[0].Name != "a.conf" || got[1].Name != "c.conf" {
		t.Fatalf("expected active a.conf first and disabled b.conf skipped, got %+v", got)
	}

	// Re-enable b.conf to check conflict detection
	mgr.SetTunnelPlan([]string{"a.conf", "b.conf", "c.conf"}, nil)
	cfgs2, _ := mgr.ListConfigs()
	conflicts := mgr.DetectConflicts(cfgs2)
	if len(conflicts) != 3 {
		t.Fatalf("expected 3 conflicts (ListenPort, Address, Endpoint), got %v", conflicts)
	}

	// Per-rule tunnel targeting (PROXY:c)
	geo := NewGeoStore(dir, logger)
	pe := NewPolicyEngine(dir, st, geo, mgr, logger)
	if _, err := pe.SaveRules("PROXY:c,cidr:198.51.100.0/24,openai\nPROXY:c,domain:openai.com,gpt\nDIRECT,cidr:77.88.8.0/24,ya\n"); err != nil && err.Error() != "" {
		// ApplyRouting may fail without root in sandbox, rule parsing still succeeds
	}
	act, by, tgt := pe.MatchDomainTarget("chat.openai.com")
	if act != ActionProxy || tgt != "c" || by != "domain:openai.com" {
		t.Fatalf("unexpected MatchDomainTarget: act=%s by=%s tgt=%s", act, by, tgt)
	}
	script, cnt := pe.BuildBatchScript("eth0", "172.18.0.1", "c", ActionProxy, true, nil, pe.rules, nil)
	if cnt != 2 || script == "" || !containsAll(script, []string{
		"route replace 198.51.100.0/24 dev c table 210",
		"route replace 77.88.8.0/24 via 172.18.0.1 dev eth0 table 210",
	}) {
		t.Fatalf("unexpected batch script:\n%s", script)
	}
	_ = st
	_ = netip.Prefix{}
}

func containsAll(hay string, needles []string) bool {
	for _, n := range needles {
		found := false
		for i := 0; i+len(n) <= len(hay); i++ {
			if hay[i:i+len(n)] == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestFailoverStandbySwitchAndFailback(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(50)
	st, _ := NewSettingsStore(dir)
	_, err := st.Update(SettingsUpdate{AppSettings: AppSettings{
		FailoverMode:            "standby",
		FailoverTrigger:         "hybrid",
		FailoverIntervalSec:     10,
		FailoverThreshold:       2,
		FailoverHandshakeSec:    30,
		FailoverHandshakeMaxAge: 180,
		FailoverCooldownSec:     60,
		FailoverProbeTarget:     "1.1.1.1:443",
		FailoverFailback:        true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1700000000, 0)
	primary := "de.conf"
	probeAlive := map[string]bool{"de": false, "nl": true}
	var switches []string

	fo := NewFailoverMonitor(nil, st, nil, logger)
	defer fo.Stop()
	fo.nowFn = func() time.Time { return now }
	fo.startedAtFn = func(string) time.Time { return now.Add(-2 * time.Minute) }
	fo.markFn = func(string) int { return 0 }
	fo.configsFn = func() ([]ConfigMeta, error) {
		return []ConfigMeta{
			{Name: "de.conf", Interface: "de", Enabled: true, Priority: 1, Active: true, Primary: primary == "de.conf", Selected: primary == "de.conf"},
			{Name: "nl.conf", Interface: "nl", Enabled: true, Priority: 2, Active: true, Primary: primary == "nl.conf", Selected: primary == "nl.conf"},
		}, nil
	}
	fo.ifacesFn = func() ([]InterfaceStatus, error) {
		return []InterfaceStatus{
			{Name: "de", Peers: []PeerStatus{{PublicKey: "p1", HandshakeAgeSec: 200}}},
			{Name: "nl", Peers: []PeerStatus{{PublicKey: "p2", HandshakeAgeSec: 5}}},
		}, nil
	}
	fo.probeFn = func(_ context.Context, iface string, _ int, _ string) (int64, error) {
		if probeAlive[iface] {
			return 12, nil
		}
		return 0, fmt.Errorf("timeout")
	}
	fo.switchFn = func(target string, standbyFast bool) error {
		if !standbyFast {
			t.Fatalf("expected fast standby switch in standby mode")
		}
		switches = append(switches, target)
		primary = target
		return nil
	}

	// Check 1: failure 1 (< threshold 2) -> degraded, no switch yet
	s1 := fo.CheckNow(false)
	if len(switches) != 0 || s1.Tunnels[0].State != "degraded" {
		t.Fatalf("expected degraded on check 1 with no switch, got switches=%v state=%s", switches, s1.Tunnels[0].State)
	}

	// Check 2: failure 2 (>= threshold 2) -> triggers fast switch to nl.conf
	now = now.Add(10 * time.Second)
	s2 := fo.CheckNow(false)
	if len(switches) != 1 || switches[0] != "nl.conf" || s2.SwitchesTotal != 1 {
		t.Fatalf("expected failover switch to nl.conf, got switches=%v total=%d", switches, s2.SwitchesTotal)
	}

	// Bring de back healthy while still in cooldown -> no failback yet
	probeAlive["de"] = true
	now = now.Add(20 * time.Second)
	fo.CheckNow(false)
	if len(switches) != 1 {
		t.Fatalf("expected cooldown to prevent early failback, got %v", switches)
	}

	// Advance past cooldown (60s total) + 2 healthy checks -> fails back to de.conf
	now = now.Add(50 * time.Second)
	fo.CheckNow(false)
	if len(switches) != 1 {
		t.Fatalf("expected failback to wait 2 healthy checks, got %v", switches)
	}
	now = now.Add(10 * time.Second)
	fo.CheckNow(false)
	if len(switches) != 2 || switches[1] != "de.conf" {
		t.Fatalf("expected failback to de.conf, got %v", switches)
	}
}

func TestTGNotifierGroupTopicAlertRoutingAndMasking(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(20)
	st, _ := NewSettingsStore(dir)
	_, err := st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:       true,
		TGBotToken:      "123456:SECRET_TOKEN",
		TGChatID:        "-100999888777",
		TGThreadID:      42,
		TGAlertThreadID: 99,
		TGNodeName:      "coredom25",
		TGVia:           "auto",
		TGOnStart:       true,
		TGOnFailover:    true,
		TGSilent:        true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	view := st.View()
	if !view.TGTokenSet || view.TGBotToken != "" {
		t.Fatalf("expected TGBotToken masked in View(): %+v", view)
	}

	tg := NewTGNotifier(st, nil, logger)
	defer tg.Stop()

	var payloads []map[string]any
	tg.sendHTTPFn = func(_ context.Context, _, _, token string, payload []byte) (int, []byte, error) {
		if token != "123456:SECRET_TOKEN" {
			t.Fatalf("unexpected token: %s", token)
		}
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		payloads = append(payloads, m)
		return 200, []byte(`{"ok":true,"result":{"message_id":777}}`), nil
	}

	// Test normal info/test -> main thread 42
	msgID, err := tg.SendTest(nil)
	if err != nil || msgID != 777 {
		t.Fatalf("expected SendTest ok (777), got id=%d err=%v", msgID, err)
	}
	// Test critical failover alert -> alert thread 99
	if _, err := tg.sendSyncWithSettings(st.Get(), TGKindFailover, "Switch", "<b>de</b> -> <b>nl</b>"); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 sent payloads, got %d", len(payloads))
	}
	if payloads[0]["message_thread_id"] != float64(42) || payloads[0]["disable_notification"] != true {
		t.Fatalf("unexpected topic/silent payload #1: %v", payloads[0])
	}
	if payloads[1]["message_thread_id"] != float64(99) || payloads[1]["chat_id"] != "-100999888777" {
		t.Fatalf("unexpected alert topic payload #2: %v", payloads[1])
	}
}

func TestDoHUpstreamNormalizationAndExchange(t *testing.T) {
	ups := parseUpstreamList("https://dns.quic.best/, https://dns.google/dns-query, 1.1.1.1")
	if len(ups) != 3 || ups[0] != "https://dns.quic.best/dns-query" || ups[1] != "https://dns.google/dns-query" || ups[2] != "1.1.1.1:53" {
		t.Fatalf("unexpected parseUpstreamList: %v", ups)
	}

	var gotCT string
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		q, _ := io.ReadAll(r.Body)
		if len(q) < 12 {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := buildDNSReplyError(q, len(q), 0)
		rw.Header().Set("Content-Type", "application/dns-message")
		_, _ = rw.Write(resp)
	}))
	defer srv.Close()

	dohTestTLSConfig = srv.TLS.Clone()
	dohTestTLSConfig.InsecureSkipVerify = true
	dohClientMu.Lock()
	dohClients = map[int]*http.Client{}
	dohClientMu.Unlock()
	defer func() {
		dohTestTLSConfig = nil
		dohClientMu.Lock()
		dohClients = map[int]*http.Client{}
		dohClientMu.Unlock()
	}()

	q := buildBootstrapAQuery("example.com")
	norm := parseUpstreamList(srv.URL)
	resp, err := exchangeUpstream(q, norm, 0, "udp")
	if err != nil {
		t.Fatalf("exchangeUpstream DoH failed: %v", err)
	}
	if gotCT != "application/dns-message" || gotPath != "/dns-query" || len(resp) < 12 {
		t.Fatalf("unexpected DoH request/response: ct=%q path=%q len=%d", gotCT, gotPath, len(resp))
	}
}

