package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionEffectiveURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "awg-sub-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	confContent := `[Interface]
PrivateKey = aaaaaaaa
Address = 10.0.0.2/24

[Peer]
PublicKey = bbbbbbbb
Endpoint = 194.28.224.231:36144
AllowedIPs = 0.0.0.0/0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "tok.conf"), []byte(confContent), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := NewRingLogger(100)
	settings, err := NewSettingsStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewTunnelManager(tmpDir, tmpDir, "veth0", false, false, logger)
	sm := NewSubscriptionManager(settings, mgr, nil, logger)

	// 1. Direct explicit URL
	sub1 := SubscriptionConfig{URL: "http://myvps:8443/sub/awg_tok_1"}
	if u := sm.EffectiveURL(sub1, "tok.conf"); u != "http://myvps:8443/sub/awg_tok_1" {
		t.Errorf("expected explicit URL, got %s", u)
	}

	// 2. Token with default port 8443 and auto-extracted host from Endpoint
	sub2 := SubscriptionConfig{Token: "awg_tok_test123"}
	u2 := sm.EffectiveURL(sub2, "tok.conf")
	expected2 := "http://194.28.224.231:8443/sub/awg_tok_test123"
	if u2 != expected2 {
		t.Errorf("expected %s, got %s", expected2, u2)
	}

	// 3. Token with custom port
	sub3 := SubscriptionConfig{Token: "awg_tok_test123", APIPort: 9443}
	u3 := sm.EffectiveURL(sub3, "tok.conf")
	expected3 := "http://194.28.224.231:9443/sub/awg_tok_test123"
	if u3 != expected3 {
		t.Errorf("expected %s, got %s", expected3, u3)
	}

	// 4. APIHost accidentally containing WireGuard endpoint port: 64.118.150.81:48389
	sub4 := SubscriptionConfig{Token: "awg_tok_test123", APIHost: "64.118.150.81:48389", APIPort: 8443}
	u4 := sm.EffectiveURL(sub4, "tok.conf")
	expected4 := "http://64.118.150.81:8443/sub/awg_tok_test123"
	if u4 != expected4 {
		t.Errorf("expected %s, got %s", expected4, u4)
	}

	// 5. cfgName passed without .conf extension
	sub5 := SubscriptionConfig{Token: "awg_tok_test123"}
	u5 := sm.EffectiveURL(sub5, "tok")
	if u5 != expected2 {
		t.Errorf("expected %s, got %s", expected2, u5)
	}

	// 6. APIHost with http schema and slash
	sub6 := SubscriptionConfig{Token: "awg_tok_test123", APIHost: "http://64.118.150.81:8443/"}
	u6 := sm.EffectiveURL(sub6, "tok")
	if u6 != expected4 {
		t.Errorf("expected %s, got %s", expected4, u6)
	}

	// 7. APIHost with multiple chained ports: 64.118.150.81:48389:45968
	sub7 := SubscriptionConfig{Token: "awg_tok_test123", APIHost: "64.118.150.81:48389:45968", APIPort: 8443}
	u7 := sm.EffectiveURL(sub7, "tok")
	if u7 != expected4 {
		t.Errorf("expected %s, got %s", expected4, u7)
	}

	// 8. Explicit URL with chained ports: http://64.118.150.81:48389:8443/sub/awg_tok_test123
	sub8 := SubscriptionConfig{URL: "http://64.118.150.81:48389:8443/sub/awg_tok_test123"}
	u8 := sm.EffectiveURL(sub8, "tok")
	if u8 != expected4 {
		t.Errorf("expected %s, got %s", expected4, u8)
	}

	// 9. Full subscription URL accidentally saved in Token field must not be double-prefixed
	sub9 := SubscriptionConfig{Token: "http://194.28.224.231:8443/sub/awg_tok_test123"}
	u9 := sm.EffectiveURL(sub9, "tok.conf")
	if u9 != expected2 {
		t.Errorf("expected %s, got %s", expected2, u9)
	}
}

func TestSubscriptionFetchAndSync(t *testing.T) {
	currentETag := `"etag-v1"`
	rawConf := `[Interface]
PrivateKey = cccccccccccccccccccccccccccccccccccccccccccc=
Address = 10.0.0.3/24

[Peer]
PublicKey = dddddddddddddddddddddddddddddddddddddddddddd=
Endpoint = 194.28.224.231:40000
AllowedIPs = 0.0.0.0/0
`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sub/awg_tok_abc" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == currentETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", currentETag)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(rawConf))
	}))
	defer ts.Close()

	tmpDir, err := os.MkdirTemp("", "awg-sub-sync-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	srcDir := filepath.Join(tmpDir, "src")
	runDir := filepath.Join(tmpDir, "run")
	_ = os.MkdirAll(srcDir, 0o700)
	_ = os.MkdirAll(runDir, 0o700)

	logger := NewRingLogger(100)
	settings, err := NewSettingsStore(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewTunnelManager(srcDir, runDir, "veth0", false, false, logger)
	mgr.runCmdFn = func(ctx context.Context, name string, args ...string) (string, error) {
		return "", nil
	}
	mgr.ipCmdFn = func(args ...string) error {
		return nil
	}
	sm := NewSubscriptionManager(settings, mgr, nil, logger)

	sub := SubscriptionConfig{
		URL:           ts.URL + "/sub/awg_tok_abc",
		Token:         "awg_tok_abc",
		APIPort:       8443,
		AutoUpdate:    true,
		SyncOnFailure: true,
	}
	if _, err := settings.SetSubscription("awg0.conf", sub); err != nil {
		t.Fatal(err)
	}

	// 1. Initial sync (gets 200 OK)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sm.Sync(ctx, "awg0.conf"); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	st := settings.Get().Subscriptions["awg0.conf"]
	if st.LastStatus != "ok" {
		t.Errorf("expected last_status 'ok', got %s", st.LastStatus)
	}
	if strings.Trim(st.LastETag, "\"") != strings.Trim(currentETag, "\"") {
		t.Errorf("expected ETag %s, got %s", currentETag, st.LastETag)
	}

	// Check file was saved
	saved, err := os.ReadFile(filepath.Join(srcDir, "awg0.conf"))
	if err != nil || !strings.Contains(string(saved), "40000") {
		t.Errorf("config file was not saved properly: %v", err)
	}

	// 2. Second sync (should get 304 Not Modified)
	if err := sm.Sync(ctx, "awg0.conf"); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	st2 := settings.Get().Subscriptions["awg0.conf"]
	if st2.LastStatus != "not_modified" {
		t.Errorf("expected last_status 'not_modified', got %s", st2.LastStatus)
	}
}

func TestExtractTokenFromURL(t *testing.T) {
	cases := []struct {
		raw      string
		wantTok  string
		wantPort int
		wantOK   bool
	}{
		{"http://194.28.224.231:8443/sub/awg_tok_980e538dba0a824da223d4a87f9d4c99", "awg_tok_980e538dba0a824da223d4a87f9d4c99", 8443, true},
		{"https://vpn.example.com:9443/sub/awg_tok_abc123.conf?format=conf#top", "awg_tok_abc123", 9443, true},
		{"http://[2001:db8::1]:8443/vpn/awg_tok_ipv6.rsc", "awg_tok_ipv6", 8443, true},
		{"http://194.28.224.231/sub/awg_tok_noport.json", "awg_tok_noport", 0, true},
		{"http://194.28.224.231:8443/files/dom25.conf", "", 0, false},
		{"vpn://abcdef", "", 0, false},
	}
	for _, tc := range cases {
		tok, port, ok := extractTokenFromURL(tc.raw)
		if tok != tc.wantTok || port != tc.wantPort || ok != tc.wantOK {
			t.Errorf("extractTokenFromURL(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tc.raw, tok, port, ok, tc.wantTok, tc.wantPort, tc.wantOK)
		}
	}
}

func TestSubscriptionSyncForce(t *testing.T) {
	const currentETag = `"etag-force-v1"`
	serverConf := `[Interface]
PrivateKey = cccccccccccccccccccccccccccccccccccccccccccc=
Address = 10.0.0.3/24

[Peer]
PublicKey = dddddddddddddddddddddddddddddddddddddddddddd=
Endpoint = 194.28.224.231:40000
AllowedIPs = 0.0.0.0/0, ::/0
`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == currentETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", currentETag)
		_, _ = w.Write([]byte(serverConf))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	runDir := filepath.Join(tmpDir, "run")
	_ = os.MkdirAll(srcDir, 0o700)
	_ = os.MkdirAll(runDir, 0o700)

	logger := NewRingLogger(50)
	settings, err := NewSettingsStore(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewTunnelManager(srcDir, runDir, "veth0", false, false, logger)
	mgr.runCmdFn = func(ctx context.Context, name string, args ...string) (string, error) { return "", nil }
	mgr.ipCmdFn = func(args ...string) error { return nil }
	sm := NewSubscriptionManager(settings, mgr, nil, logger)

	sub := SubscriptionConfig{
		URL:        ts.URL + "/sub/awg_tok_force",
		Token:      "awg_tok_force",
		APIPort:    8443,
		AutoUpdate: true,
	}
	if _, err := settings.SetSubscription("dom25.conf", sub); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sm.Sync(ctx, "dom25.conf"); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}

	// Simulate modified local file while server still holds same ETag.
	staleConf := strings.ReplaceAll(serverConf, "0.0.0.0/0, ::/0", "0.0.0.0/0")
	if err := os.WriteFile(filepath.Join(srcDir, "dom25.conf"), []byte(staleConf), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := sm.SyncForce(ctx, "dom25.conf"); err != nil {
		t.Fatalf("SyncForce restore failed: %v", err)
	}
	if st := settings.Get().Subscriptions["dom25.conf"]; st.LastStatus != "ok" {
		t.Errorf("expected LastStatus 'ok' after restore, got %q", st.LastStatus)
	}
	restored, err := os.ReadFile(filepath.Join(srcDir, "dom25.conf"))
	if err != nil || !strings.Contains(string(restored), "::/0") {
		t.Fatalf("expected SyncForce to restore server config with ::/0, err=%v content=%s", err, string(restored))
	}

	// Subsequent SyncForce when disk already matches should avoid re-applying and mark not_modified.
	if err := sm.SyncForce(ctx, "dom25.conf"); err != nil {
		t.Fatalf("second SyncForce failed: %v", err)
	}
	if st := settings.Get().Subscriptions["dom25.conf"]; st.LastStatus != "not_modified" {
		t.Errorf("expected LastStatus 'not_modified' when on-disk config already matches, got %q", st.LastStatus)
	}
}

func TestWebStatusIncludesSubscriptionsAndSaveNormalizesURL(t *testing.T) {
	dir := t.TempDir()
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", false, false, logger)
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	geo := NewGeoStore(dir, logger)
	pol := NewPolicyEngine(dir, st, geo, mgr, logger)
	ros := NewROSClient(dir, logger)
	w := NewWebServer(":0", mgr, nil, ros, st, geo, pol, logger)
	w.uiUser = "admin"
	w.uiPass = "secret"

	if _, err := st.SetSubscription("dom25.conf", SubscriptionConfig{
		Token:      "awg_tok_980e538dba0a824da223d4a87f9d4c99",
		APIPort:    8443,
		LastStatus: "not_modified",
		LastETag:   "43bbd09194675e11",
	}); err != nil {
		t.Fatal(err)
	}

	mux := w.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("GET /api/status failed: %d %s", rw.Code, rw.Body.String())
	}
	var payload struct {
		Version       string                        `json:"version"`
		Subscriptions map[string]SubscriptionConfig `json:"subscriptions"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal /api/status: %v", err)
	}
	if payload.Version != AppVersion {
		t.Errorf("expected version %q, got %q", AppVersion, payload.Version)
	}
	gotSub, ok := payload.Subscriptions["dom25.conf"]
	if !ok || gotSub.Token != "awg_tok_980e538dba0a824da223d4a87f9d4c99" {
		t.Fatalf("expected dom25.conf subscription in /api/status, got %+v", payload.Subscriptions)
	}

	// Saving full URL into token field should normalize to clean token
	saveReq := httptest.NewRequest(http.MethodPost, "/api/subscriptions/tok.conf",
		strings.NewReader(`{"token":"http://64.118.150.81:8443/sub/awg_tok_e608ab504c6b471e23cc3575684f8923","api_port":8443}`))
	saveReq.SetBasicAuth("admin", "secret")
	saveRW := httptest.NewRecorder()
	mux.ServeHTTP(saveRW, saveReq)
	if saveRW.Code != http.StatusOK {
		t.Fatalf("POST /api/subscriptions/tok.conf failed: %d %s", saveRW.Code, saveRW.Body.String())
	}
	savedTok := st.Get().Subscriptions["tok.conf"]
	if savedTok.Token != "awg_tok_e608ab504c6b471e23cc3575684f8923" || savedTok.URL != "" {
		t.Errorf("expected normalized token without URL, got token=%q url=%q", savedTok.Token, savedTok.URL)
	}
}

func TestSubscriptionSyncPreservesPrimaryInMultiTunnel(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	runDir := filepath.Join(tmpDir, "run")
	_ = os.MkdirAll(srcDir, 0o700)
	_ = os.MkdirAll(runDir, 0o700)

	domConf := "[Interface]\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nAddress = 10.8.99.5/32\n[Peer]\nPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\nEndpoint = de-e1.ligam.org:36144\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	tokOld := "[Interface]\nPrivateKey = ccccccccccccccccccccccccccccccccccccccccccc=\nAddress = 10.149.104.2/32\n[Peer]\nPublicKey = ddddddddddddddddddddddddddddddddddddddddddd=\nEndpoint = 64.118.150.81:27015\nAllowedIPs = 0.0.0.0/0\n"
	tokNew := strings.ReplaceAll(tokOld, "0.0.0.0/0", "0.0.0.0/0, ::/0")

	_ = os.WriteFile(filepath.Join(srcDir, "dom25.conf"), []byte(domConf), 0o600)
	_ = os.WriteFile(filepath.Join(srcDir, "tok.conf"), []byte(tokOld), 0o600)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"tok-v2"`)
		_, _ = w.Write([]byte(tokNew))
	}))
	defer ts.Close()

	logger := NewRingLogger(50)
	settings, err := NewSettingsStore(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewTunnelManager(srcDir, runDir, "veth0", false, false, logger)
	mgr.SetRuntimeOptions(false, false, true)
	mgr.runCmdFn = func(ctx context.Context, name string, args ...string) (string, error) { return "", nil }
	mgr.ipCmdFn = func(args ...string) error { return nil }
	if err := mgr.SetActiveConfig("dom25.conf"); err != nil {
		t.Fatal(err)
	}

	sm := NewSubscriptionManager(settings, mgr, nil, logger)
	if _, err := settings.SetSubscription("tok.conf", SubscriptionConfig{
		URL:   ts.URL + "/sub/awg_tok_sec",
		Token: "awg_tok_sec",
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sm.SyncForce(ctx, "tok.conf"); err != nil {
		t.Fatalf("SyncForce secondary failed: %v", err)
	}
	if active := mgr.GetActiveConfig(); active != "dom25.conf" {
		t.Fatalf("expected primary to remain dom25.conf, got %q", active)
	}
	updated, err := os.ReadFile(filepath.Join(srcDir, "tok.conf"))
	if err != nil || !strings.Contains(string(updated), "::/0") {
		t.Fatalf("expected tok.conf updated on disk, err=%v content=%s", err, string(updated))
	}
}
