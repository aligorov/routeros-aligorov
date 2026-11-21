package main

import (
	"context"
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
