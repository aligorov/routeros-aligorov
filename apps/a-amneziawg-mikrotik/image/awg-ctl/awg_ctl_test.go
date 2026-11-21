package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAwgDumpAndMeta(t *testing.T) {
	sample := strings.Join([]string{
		"awg0\tPRIVKEY\tPUBKEY0\t51820\t6\t50\t1000\t10\t20\t30\t40\t100\t200\t300\t400\t(null)\t(null)\t(null)\t(null)\t(null)\t(null)\t0\t0\t0\t0\t0\t0\toff\toff\toff",
		"awg0\tPEERPUB1\t(none)\t1.2.3.4:51820\t0.0.0.0/0,10.10.0.0/16\t1000\t2048\t4096\t25",
	}, "\n")

	ifaces := parseAwgDump(sample, 1042)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 iface, got %d", len(ifaces))
	}
	if ifaces[0].Name != "awg0" || ifaces[0].ListenPort != 51820 || ifaces[0].S1 != "10" || ifaces[0].H4 != "400" {
		t.Fatalf("unexpected iface parsed: %+v", ifaces[0])
	}
	if len(ifaces[0].Peers) != 1 || ifaces[0].Peers[0].HandshakeAgeSec != 42 || ifaces[0].Peers[0].RxBytes != 2048 {
		t.Fatalf("unexpected peer parsed: %+v", ifaces[0].Peers)
	}
}

func TestInjectAutoRouteAndSeed(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	run := filepath.Join(tmp, "run")
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(src, run, "AmneziaWGRoS", true, true, logger)

	raw := "[Interface]\r\nPrivateKey = abc=\r\nDNS = 1.1.1.1, 9.9.9.9\r\n\r\n[Peer]\r\nPublicKey = def=\r\nAllowedIPs = 10.20.0.0/16, 0.0.0.0/0\r\n"
	if err := mgr.SaveConfig("awg0.conf", raw); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}
	loaded, err := mgr.ReadConfig("awg0.conf")
	if err != nil || strings.Contains(loaded, "\r") {
		t.Fatalf("expected LF-normalized config, got err=%v", err)
	}
	injected := mgr.injectAutoRoute(loaded, "awg", true)
	if !strings.Contains(injected, "Table = awg") || !strings.Contains(injected, "iif AmneziaWGRoS lookup awg") || !strings.Contains(injected, "ip route add blackhole default table awg metric 254") || strings.Contains(injected, "ip route replace blackhole") {
		t.Fatalf("missing or broken injected auto-route rules:\n%s", injected)
	}

	// Regression: PostUp pasted after [Peer] must be moved under [Interface] before awg-quick runs.
	misplaced := "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = def=\nAllowedIPs = 0.0.0.0/0\nPostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE\n"
	norm := mgr.injectAutoRoute(misplaced, "awg", true)
	peerIdx := strings.Index(norm, "[Peer]")
	postUpIdx := strings.Index(norm, "PostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE")
	if peerIdx < 0 || postUpIdx < 0 || postUpIdx > peerIdx {
		t.Fatalf("expected PostUp relocated before [Peer], got:\n%s", norm)
	}
	if !strings.Contains(norm, "Table = awg") {
		t.Fatalf("expected Table = awg when config had only PostUp, got:\n%s", norm)
	}
}

func TestROSSyncMock(t *testing.T) {
	var createdRoutes []map[string]any
	var createdDNS []map[string]any
	var deletedPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/ip/route":
			_ = json.NewEncoder(rw).Encode([]map[string]any{
				{".id": "*1", "dst-address": "10.99.0.0/16", "gateway": "192.168.253.2", "comment": "awg-ctl:awg0"},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/rest/ip/route/"):
			deletedPaths = append(deletedPaths, r.URL.Path)
			rw.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/route":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			createdRoutes = append(createdRoutes, m)
			rw.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/rest/ip/dns/static":
			_ = json.NewEncoder(rw).Encode([]map[string]any{})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/dns/static":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			createdDNS = append(createdDNS, m)
			rw.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	logger := NewRingLogger(20)
	t.Setenv("ROS_URL", srv.URL)
	t.Setenv("ROS_USER", "admin")
	t.Setenv("ROS_PASS", "pass")
	ros := NewROSClient(tmp, logger)
	if err := ros.SaveDomains("example.com\nexample.com\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := ros.syncAllowedRoutes(map[string][]string{"awg0": {"10.20.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	if len(deletedPaths) != 1 || len(createdRoutes) != 1 || createdRoutes[0]["dst-address"] != "10.20.0.0/16" {
		t.Fatalf("unexpected route sync: deleted=%v created=%v", deletedPaths, createdRoutes)
	}
	domains, _ := ros.ReadDomains()
	if _, err := ros.syncDNSDomains(domains); err != nil {
		t.Fatal(err)
	}
	if len(createdDNS) != 1 || createdDNS[0]["name"] != "example.com" || createdDNS[0]["type"] != "FWD" {
		t.Fatalf("unexpected DNS sync: %v", createdDNS)
	}
	_ = os.RemoveAll(tmp)
}

func TestSelectStartConfigs(t *testing.T) {
	cfgs := []ConfigMeta{{Name: "a.conf"}, {Name: "b.conf"}, {Name: "c.conf"}}
	if got := selectStartConfigs(cfgs, "b.conf", false); len(got) != 1 || got[0].Name != "b.conf" {
		t.Fatalf("expected only b.conf, got %+v", got)
	}
	if got := selectStartConfigs(cfgs, "", false); len(got) != 1 || got[0].Name != "a.conf" {
		t.Fatalf("expected fallback a.conf, got %+v", got)
	}
	if got := selectStartConfigs(cfgs, "b.conf", true); len(got) != 3 {
		t.Fatalf("multi mode must start all, got %+v", got)
	}
}

func TestActiveConfigPersist(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "", false, false, NewRingLogger(10))
	_ = mgr.SaveConfig("nl.conf", "[Interface]\nPrivateKey = x\n")
	_ = mgr.SaveConfig("de.conf", "[Interface]\nPrivateKey = y\n")
	if err := mgr.SetActiveConfig("nl.conf"); err != nil {
		t.Fatal(err)
	}
	if mgr.GetActiveConfig() != "nl.conf" {
		t.Fatalf("active not persisted")
	}
	if err := mgr.SetActiveConfig("missing.conf"); err == nil {
		t.Fatalf("expected error for missing profile")
	}
}

func TestSaveConfigValidationRejectsMalformedEndpoint(t *testing.T) {
	tmp := t.TempDir()
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "eth0", true, true, logger)
	st, _ := NewSettingsStore(tmp)
	geo := NewGeoStore(tmp, logger)
	pol := NewPolicyEngine(tmp, st, geo, mgr, logger)
	ros := NewROSClient(tmp, logger)
	w := NewWebServer(":0", mgr, nil, ros, st, geo, pol, logger)
	w.uiUser = "admin"
	w.uiPass = "secret123"
	handler := w.Handler()

	badCases := []struct {
		name string
		conf string
	}{
		{"double_port", "[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nEndpoint = 64.118.133.197:443:443\nAllowedIPs = 0.0.0.0/0\n"},
		{"missing_port", "[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nEndpoint = 64.118.133.197\n"},
		{"empty_endpoint", "[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nEndpoint = \n"},
		{"bad_port_range", "[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nEndpoint = 1.2.3.4:70000\n"},
		{"bad_listen_port", "[Interface]\nPrivateKey = x=\nListenPort = 0\n"},
		{"bad_mtu", "[Interface]\nPrivateKey = x=\nMTU = 12\n"},
		{"bad_address_cidr", "[Interface]\nPrivateKey = x=\nAddress = not-a-cidr\n"},
		{"bad_allowedips", "[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nAllowedIPs = 999.999.0.0/24\n"},
		{"missing_interface", "[Peer]\nPublicKey = y=\nEndpoint = 1.2.3.4:51820\n"},
	}
	for _, tc := range badCases {
		if err := mgr.SaveConfig("bad.conf", tc.conf); err == nil {
			t.Fatalf("%s: expected SaveConfig to reject invalid config", tc.name)
		}
		payload, _ := json.Marshal(map[string]any{"content": tc.conf, "apply": true})
		req := httptest.NewRequest(http.MethodPost, "/api/configs/bad.conf", bytes.NewReader(payload))
		req.SetBasicAuth("admin", "secret123")
		req.Header.Set("Content-Type", "application/json")
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		if rw.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected HTTP 400, got %d (%s)", tc.name, rw.Code, rw.Body.String())
		}
	}

	goodCases := []string{
		"[Interface]\nPrivateKey = x=\nAddress = 10.0.0.2/32\nListenPort = 51820\nMTU = 1420\n[Peer]\nPublicKey = y=\nEndpoint = 64.118.133.197:443\nAllowedIPs = 0.0.0.0/0\n",
		"[Interface]\nPrivateKey = x=\n[Peer]\nPublicKey = y=\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = ::/0\n",
		"[Interface]\n# Endpoint = bad:bad:bad\nPrivateKey = x=\n",
	}
	for i, conf := range goodCases {
		if err := mgr.SaveConfig(fmt.Sprintf("ok%d.conf", i), conf); err != nil {
			t.Fatalf("valid case %d rejected: %v", i, err)
		}
	}
}

func TestStatusNonBlockingDuringSlowStartAll(t *testing.T) {
	tmp := t.TempDir()
	logger := NewRingLogger(30)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "eth0", false, false, logger)
	mgr.ipCmdFn = func(args ...string) error { return nil }

	upStarted := make(chan struct{})
	releaseUp := make(chan struct{})
	mgr.runCmdFn = func(ctx context.Context, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "up" {
			close(upStarted)
			select {
			case <-releaseUp:
				return "", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "", nil
	}

	conf := "[Interface]\nPrivateKey = x=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = y=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := mgr.SaveConfig("slow.conf", conf); err != nil {
		t.Fatal(err)
	}

	st, _ := NewSettingsStore(tmp)
	geo := NewGeoStore(tmp, logger)
	pol := NewPolicyEngine(tmp, st, geo, mgr, logger)
	ros := NewROSClient(tmp, logger)
	w := NewWebServer(":0", mgr, nil, ros, st, geo, pol, logger)
	w.uiUser = "admin"
	w.uiPass = "secret123"
	handler := w.Handler()

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- mgr.ApplySavedConfig("slow.conf")
	}()

	select {
	case <-upStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for slow awg-quick up to begin")
	}

	// While awg-quick up is blocked, /api/status must NOT block waiting for mgr.mu.
	statusDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.SetBasicAuth("admin", "secret123")
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		statusDone <- rw
	}()

	var rw *httptest.ResponseRecorder
	select {
	case rw = <-statusDone:
	case <-time.After(500 * time.Millisecond):
		close(releaseUp)
		t.Fatal("GET /api/status deadlocked/blocked while StartAll was running")
	}
	if rw.Code != http.StatusOK {
		close(releaseUp)
		t.Fatalf("expected /api/status 200 during apply, got %d (%s)", rw.Code, rw.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &payload); err != nil {
		close(releaseUp)
		t.Fatal(err)
	}
	if applying, _ := payload["applying"].(bool); !applying {
		close(releaseUp)
		t.Fatalf("expected applying=true in /api/status, got %v", payload["applying"])
	}
	if op, _ := payload["applying_op"].(string); op != "Запуск slow.conf" {
		close(releaseUp)
		t.Fatalf("expected applying_op='Запуск slow.conf', got %q", op)
	}

	close(releaseUp)
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("ApplySavedConfig failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApplySavedConfig did not finish after release")
	}
	if applying, _ := mgr.ApplyingState(); applying {
		t.Fatal("expected applying=false after ApplySavedConfig returned")
	}
}

func TestRunCmdTimeoutKillsHungProcess(t *testing.T) {
	tmp := t.TempDir()
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "eth0", false, false, logger)
	mgr.cmdTimeout = 120 * time.Millisecond

	start := time.Now()
	err := mgr.runCmd("sh", "-c", "echo partial-line; sleep 10")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error from hung command")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected command timeout quickly (<2s), took %s", elapsed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timed out error, got: %v", err)
	}
	logs := strings.Join(logger.Lines(), "\n")
	if !strings.Contains(logs, "partial-line") {
		t.Fatalf("expected partial stdout/stderr logged before timeout, got: %s", logs)
	}
}

func TestSplitBatchChunks(t *testing.T) {
	var b strings.Builder
	b.WriteString("route flush table 210\n\n")
	for i := 0; i < 1205; i++ {
		fmt.Fprintf(&b, "route replace 10.%d.%d.0/24 dev awg0 table 210\n", i/256, i%256)
	}
	chunks := splitBatchChunks(b.String(), 500)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks for 1206 lines, got %d", len(chunks))
	}
	if !strings.HasPrefix(chunks[0], "route flush table 210\n") {
		t.Fatalf("first chunk must start with route flush, got %q", chunks[0][:40])
	}
	if strings.Count(strings.TrimSuffix(chunks[0], "\n"), "\n")+1 != 500 ||
		strings.Count(strings.TrimSuffix(chunks[2], "\n"), "\n")+1 != 206 {
		t.Fatalf("unexpected chunk line counts")
	}
}

func TestSanitizeRuntimeConfigMTUAndIPv6(t *testing.T) {
	// 1. Dual-stack config with MTU = 1200 must clamp runtime MTU to 1280 (RFC 8200 min) when IPv6 is enabled.
	v6BadMTU := strings.Join([]string{
		"[Interface]",
		"PrivateKey = priv=",
		"Address = 10.105.200.2/32, fd42:42:42::2/128",
		"DNS = 1.1.1.1, 2606:4700:4700::1111",
		"MTU = 1200",
		"[Peer]",
		"PublicKey = pub=",
		"Endpoint = 185.216.84.74:40797",
		"AllowedIPs = 0.0.0.0/0, ::/0",
	}, "\n")
	out, notices := sanitizeRuntimeConfig(v6BadMTU, true)
	if !strings.Contains(out, "MTU = 1280") || strings.Contains(out, "MTU = 1200") {
		t.Fatalf("expected MTU clamped to 1280 for IPv6 config, got:\n%s", out)
	}
	if len(notices) == 0 {
		t.Fatalf("expected notice when clamping MTU 1200 -> 1280")
	}

	// 2. IPv4-only config keeps MTU = 1200 untouched.
	v4Only := strings.Join([]string{
		"[Interface]",
		"PrivateKey = priv=",
		"Address = 10.105.200.2/32",
		"MTU = 1200",
		"[Peer]",
		"PublicKey = pub=",
		"Endpoint = 1.2.3.4:443",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")
	out4, notices4 := sanitizeRuntimeConfig(v4Only, true)
	if !strings.Contains(out4, "MTU = 1200") || len(notices4) != 0 {
		t.Fatalf("expected IPv4-only MTU = 1200 untouched, got notices=%v\n%s", notices4, out4)
	}

	// 3. When IPv6 is disabled in container, IPv6 directives are stripped cleanly and MTU=1200 stays intact.
	stripped, noticesOff := sanitizeRuntimeConfig(v6BadMTU, false)
	if strings.Contains(stripped, "fd42:42:42::2") || strings.Contains(stripped, "::/0") || strings.Contains(stripped, "2606:4700") {
		t.Fatalf("expected all IPv6 entries stripped when ipv6Enabled=false, got:\n%s", stripped)
	}
	if !strings.Contains(stripped, "Address = 10.105.200.2/32") || !strings.Contains(stripped, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("expected IPv4 entries preserved when stripping IPv6, got:\n%s", stripped)
	}
	if len(noticesOff) == 0 {
		t.Fatalf("expected notice when IPv6 stripped")
	}
}

func TestPrepareRuntimeConfigAndFastSwitchIPv6(t *testing.T) {
	t.Setenv("AWG_ENABLE_IPV6", "on")
	tmp := t.TempDir()
	logger := NewRingLogger(30)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "veth-app", true, true, logger)

	raw := "[Interface]\nPrivateKey = priv=\nAddress = 10.105.200.2/32, fd42:42:42::2/128\nMTU = 1200\n[Peer]\nPublicKey = pub=\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	prep := mgr.prepareRuntimeConfig("nid.conf", raw, "202", false)
	if !strings.Contains(prep, "Table = 202") || !strings.Contains(prep, "MTU = 1280") {
		t.Fatalf("expected secondary config to have Table = 202 and MTU = 1280, got:\n%s", prep)
	}
	logs := strings.Join(logger.Lines(), "\n")
	if !strings.Contains(logs, "raised runtime MTU to 1280") {
		t.Fatalf("expected MTU adjustment warning in logger, got:\n%s", logs)
	}

	var ipCalls []string
	mgr.ipCmdFn = func(args ...string) error {
		ipCalls = append(ipCalls, "ip "+strings.Join(args, " "))
		return nil
	}
	_ = os.WriteFile(filepath.Join(tmp, "nid.conf"), []byte(raw), 0o600)
	if err := mgr.switchPrimaryFastOp("nid.conf"); err != nil {
		t.Fatalf("switchPrimaryFastOp failed: %v", err)
	}
	joined := strings.Join(ipCalls, "\n")
	for _, want := range []string{
		"ip route replace default dev nid table awg",
		"ip -6 route replace ::/0 dev nid table awg",
		"ip -6 route replace blackhole default table awg metric 254",
		"ip -6 rule add priority 300 from all iif veth-app lookup awg",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in switchPrimaryFastOp calls, got:\n%s", want, joined)
		}
	}
}

func TestSettingsStoreUpdatePreservesSubscriptions(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore: %v", err)
	}
	if _, err := st.SetSubscription("nl.conf", SubscriptionConfig{
		Token:         "awg_tok_preserve",
		APIHost:       "198.51.100.10",
		APIPort:       8443,
		AutoUpdate:    true,
		SyncOnFailure: true,
	}); err != nil {
		t.Fatalf("SetSubscription: %v", err)
	}

	updated, err := st.Update(SettingsUpdate{AppSettings: AppSettings{
		FailoverMode: "standby",
	}})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	sub, ok := updated.Subscriptions["nl.conf"]
	if !ok || sub.Token != "awg_tok_preserve" || sub.APIHost != "198.51.100.10" {
		t.Fatalf("expected existing subscription to be preserved when upd.Subscriptions is nil, got: %+v", updated.Subscriptions)
	}

	reloaded, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("reload SettingsStore: %v", err)
	}
	if got := reloaded.Get().Subscriptions["nl.conf"].Token; got != "awg_tok_preserve" {
		t.Fatalf("expected persisted subscription token after reload, got %q", got)
	}
}

func TestHandleSaveConfigKeepPrimary(t *testing.T) {
	w, _, mgr, _ := newTestWebServer(t, "SecretPass123")
	mgr.SetRuntimeOptions(true, true, true)
	mgr.runCmdFn = func(ctx context.Context, name string, args ...string) (string, error) {
		return "", nil
	}
	mgr.ipCmdFn = func(args ...string) error {
		return nil
	}
	const sampleMain = "[Interface]\nAddress = 10.10.0.2/32\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nEndpoint = 198.51.100.1:51820\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 0.0.0.0/0\n"
	const sampleSec = "[Interface]\nAddress = 10.20.0.2/32\nPrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n[Peer]\nEndpoint = 198.51.100.2:51820\nPublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\nAllowedIPs = 0.0.0.0/0\n"
	if err := mgr.SaveConfig("main.conf", sampleMain); err != nil {
		t.Fatalf("SaveConfig main: %v", err)
	}
	if err := mgr.SaveConfig("sec.conf", sampleSec); err != nil {
		t.Fatalf("SaveConfig sec: %v", err)
	}
	if err := mgr.SetActiveConfig("main.conf"); err != nil {
		t.Fatalf("SetActiveConfig: %v", err)
	}

	h := w.Handler()
	reqKeep := httptest.NewRequest(http.MethodPost, "/api/configs/sec.conf", strings.NewReader(`{"content":"[Interface]\nAddress = 10.20.0.3/32\nPrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n[Peer]\nEndpoint = 198.51.100.2:51820\nPublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\nAllowedIPs = 0.0.0.0/0\n","apply":true,"keep_primary":true}`))
	reqKeep.Header.Set("Content-Type", "application/json")
	reqKeep.SetBasicAuth("admin", "SecretPass123")
	rwKeep := httptest.NewRecorder()
	h.ServeHTTP(rwKeep, reqKeep)
	if rwKeep.Code != http.StatusOK {
		t.Fatalf("expected 200 on keep_primary save, got %d (%s)", rwKeep.Code, rwKeep.Body.String())
	}
	if got := mgr.GetActiveConfig(); got != "main.conf" {
		t.Fatalf("expected primary main.conf preserved when keep_primary=true, got %q", got)
	}

	reqSwitch := httptest.NewRequest(http.MethodPost, "/api/configs/sec.conf", strings.NewReader(`{"content":"[Interface]\nAddress = 10.20.0.4/32\nPrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n[Peer]\nEndpoint = 198.51.100.2:51820\nPublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\nAllowedIPs = 0.0.0.0/0\n","apply":true,"keep_primary":false}`))
	reqSwitch.Header.Set("Content-Type", "application/json")
	reqSwitch.SetBasicAuth("admin", "SecretPass123")
	rwSwitch := httptest.NewRecorder()
	h.ServeHTTP(rwSwitch, reqSwitch)
	if rwSwitch.Code != http.StatusOK {
		t.Fatalf("expected 200 on switch save, got %d (%s)", rwSwitch.Code, rwSwitch.Body.String())
	}
	if got := mgr.GetActiveConfig(); got != "sec.conf" {
		t.Fatalf("expected active config switched to sec.conf when keep_primary=false, got %q", got)
	}
}
