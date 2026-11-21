package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestTGNotifierSendClientConfig(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore: %v", err)
	}
	if _, err := store.Update(SettingsUpdate{
		AppSettings: AppSettings{
			TGEnabled:  true,
			TGBotToken: "123456:TESTTOKEN",
			TGChatID:   "999",
			TGVia:      "direct",
		},
	}); err != nil {
		t.Fatalf("Update settings: %v", err)
	}

	tg := NewTGNotifier(store, nil, NewRingLogger(50))
	defer tg.Stop()

	var mu sync.Mutex
	var calls []string
	var cts []string
	tg.sendMethodFn = func(_ context.Context, via, apiURL, token, method, contentType string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, method)
		cts = append(cts, contentType)
		if method == "sendPhoto" && !strings.Contains(string(payload), "alice.png") {
			t.Errorf("sendPhoto missing filename alice.png")
		}
		if method == "sendDocument" && !strings.Contains(string(payload), "alice.conf") {
			t.Errorf("sendDocument missing filename alice.conf")
		}
		return 200, []byte(`{"ok":true,"result":{"message_id":42}}`), nil
	}

	sampleConf := "[Interface]\nPrivateKey = AAA=\nAddress = 10.8.99.2/32\n[Peer]\nPublicKey = BBB=\nEndpoint = 1.2.3.4:443\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	err = tg.SendClientConfig(context.Background(), "777888", 12, "dom25", "alice", "Ротация", sampleConf, "vpn://abc123", "http://1.2.3.4:8443/sub/awg_tok_123")
	if err != nil {
		t.Fatalf("SendClientConfig failed: %v", err)
	}

	if len(calls) != 3 || calls[0] != "sendPhoto" || calls[1] != "sendDocument" || calls[2] != "sendMessage" {
		t.Fatalf("unexpected telegram calls: %v", calls)
	}
	if !strings.HasPrefix(cts[0], "multipart/form-data") || !strings.HasPrefix(cts[1], "multipart/form-data") {
		t.Fatalf("expected multipart content-types, got %v", cts)
	}

	// Test 403 chat not found friendly hint
	tg.sendMethodFn = func(_ context.Context, _, _, _, _, _ string, _ []byte) (int, []byte, error) {
		return 403, []byte(`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`), nil
	}
	err = tg.SendClientConfig(context.Background(), "777888", 0, "dom25", "alice", "Тест", sampleConf, "", "")
	if err == nil || !strings.Contains(err.Error(), "/start") {
		t.Fatalf("expected /start hint on 403 error, got: %v", err)
	}
}

func TestVPSFleetCRUDPresetEndpointAndAutoNotify(t *testing.T) {
	adminToken := "awg_adm_" + strings.Repeat("a", 64)
	var mu sync.Mutex
	preset := "quic"
	port := 443
	epMode := "ipv4"
	epHost := "198.51.100.10"
	etagRev := 1
	clients := map[string]*remoteClientItem{}

	makeConf := func(name, host string, p int) string {
		return "[Interface]\nPrivateKey = PRIV_" + name + "\nAddress = 10.8.99.2/32, fd42:42:42::2/128\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = SRVPUB\nEndpoint = " + host + ":" + strconv.Itoa(p) + "\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
	}
	curETag := func(name string) string {
		return "etag_" + name + "_v" + strconv.Itoa(etagRev)
	}
	buildMeta := func() *remoteServerMeta {
		return &remoteServerMeta{
			ListenPort:   port,
			Preset:       preset,
			EndpointMode: epMode,
			Endpoint:     epHost + ":" + strconv.Itoa(port),
			PublicIPv4:   "198.51.100.10",
			PublicIPv6:   "2001:db8::10",
			APIPort:      8443,
			TLSEnabled:   true,
			ClientCount:  len(clients),
			ServerETag:   "srv_v" + strconv.Itoa(etagRev),
			Presets:      DefaultVPSPresets,
		}
	}
	listItems := func() []remoteClientItem {
		out := make([]remoteClientItem, 0, len(clients))
		for _, c := range clients {
			cp := *c
			cp.Endpoint = epHost + ":" + strconv.Itoa(port)
			cp.ETag = curETag(cp.Name)
			out = append(out, cp)
		}
		return out
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+adminToken {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte(`{"error":"Forbidden"}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/clients":
			meta := buildMeta()
			etag := `"` + meta.ServerETag + `"`
			if r.Header.Get("If-None-Match") == etag {
				rw.Header().Set("ETag", etag)
				rw.WriteHeader(http.StatusNotModified)
				return
			}
			rw.Header().Set("ETag", etag)
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{Server: meta, Clients: listItems()})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/clients":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			nm := req["name"].(string)
			etagRev++
			item := &remoteClientItem{
				Name:         nm,
				IPv4:         "10.8.99.2",
				IPv6:         "fd42:42:42::2",
				Token:        "awg_tok_" + strings.Repeat("b", 32),
				Endpoint:     epHost + ":" + strconv.Itoa(port),
				EndpointMode: "server",
				DNS:          "1.1.1.1",
				MTU:          "1280",
				AllowedIPs:   "0.0.0.0/0, ::/0",
				ETag:         curETag(nm),
				Config:       makeConf(nm, epHost, port),
				VPNURL:       "vpn://test_" + nm,
			}
			clients[nm] = item
			rw.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Client: item})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/clients/"):
			nm := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
			c, ok := clients[nm]
			if !ok {
				rw.WriteHeader(http.StatusNotFound)
				return
			}
			cp := *c
			cp.Endpoint = epHost + ":" + strconv.Itoa(port)
			cp.ETag = curETag(nm)
			cp.Config = makeConf(nm, epHost, port)
			cp.VPNURL = "vpn://test_" + nm + "_v" + strconv.Itoa(etagRev)
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{Server: buildMeta(), Client: &cp})

		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v1/clients/"):
			nm := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
			c, ok := clients[nm]
			if !ok {
				rw.WriteHeader(http.StatusNotFound)
				return
			}
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if rn, ok := req["rename"].(string); ok && rn != "" && rn != nm {
				delete(clients, nm)
				c.Name = rn
				clients[rn] = c
				nm = rn
			}
			if ep, ok := req["endpoint"].(string); ok && ep != "" {
				c.EndpointMode = ep
			}
			etagRev++
			cp := *c
			cp.ETag = curETag(nm)
			cp.Config = makeConf(nm, epHost, port)
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Client: &cp})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/clients/"):
			nm := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
			delete(clients, nm)
			etagRev++
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Clients: listItems()})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/server/preset":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			preset = req["preset"].(string)
			port = 8801
			etagRev++
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Clients: listItems()})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/server/endpoint":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			epMode = req["target"].(string)
			if epMode == "ipv6" {
				epHost = "[2001:db8::10]"
			}
			etagRev++
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Clients: listItems()})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/server/rotate":
			port = 33445
			etagRev++
			_ = json.NewEncoder(rw).Encode(remoteClientsResp{OK: true, Server: buildMeta(), Clients: listItems()})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	tsPort, _ := strconv.Atoi(portStr)
	certSum := sha256.Sum256(ts.Certificate().Raw)
	certPin := hex.EncodeToString(certSum[:])

	dir := t.TempDir()
	store, _ := NewSettingsStore(dir)
	_, _ = store.Update(SettingsUpdate{
		AppSettings: AppSettings{TGEnabled: true, TGBotToken: "123:TOK", TGChatID: "1", TGVia: "direct"},
	})
	logger := NewRingLogger(100)
	tg := NewTGNotifier(store, nil, logger)
	defer tg.Stop()

	var tgMu sync.Mutex
	tgPhotoCount := 0
	tg.sendMethodFn = func(_ context.Context, _, _, _, method, _ string, _ []byte) (int, []byte, error) {
		tgMu.Lock()
		if method == "sendPhoto" {
			tgPhotoCount++
		}
		tgMu.Unlock()
		return 200, []byte(`{"ok":true,"result":{"message_id":1}}`), nil
	}

	fleet := NewVPSFleetManager(dir, store, nil, nil, tg, logger)
	useHTTPS := true
	skipVerify := true
	srvView, err := fleet.UpsertServer(UpsertVPSRequest{
		Name:          "dom25",
		APIHost:       host,
		APIPort:       tsPort,
		UseHTTPS:      &useHTTPS,
		TLSSkipVerify: &skipVerify,
		TLSPinSHA256:  certPin,
		AdminToken:    adminToken,
	})
	if err != nil {
		t.Fatalf("UpsertServer failed: %v", err)
	}
	if !srvView.AdminTokenSet || srvView.AdminToken != "" {
		t.Fatalf("expected redacted AdminToken with AdminTokenSet=true")
	}

	ctx := context.Background()
	// 1. Create client with Telegram recipient and SendNow=true
	created, err := fleet.CreateClient(ctx, srvView.ID, CreateVPSClientRequest{
		Name:       "iphone",
		TGChatID:   "555111",
		TGLabel:    "@wife",
		TGAutoSend: true,
		SendNow:    true,
	})
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	if !created.TGSent {
		t.Fatalf("expected TGSent=true, err=%s", created.TGError)
	}
	if tgPhotoCount != 1 {
		t.Fatalf("expected 1 TG photo delivery, got %d", tgPhotoCount)
	}

	// 2. Apply stealth preset -> should auto-deliver updated config to TG
	resPreset, err := fleet.ApplyServerPreset(ctx, srvView.ID, "dtls", "", "")
	if err != nil {
		t.Fatalf("ApplyServerPreset failed: %v", err)
	}
	if resPreset.Server.Preset != "dtls" || resPreset.NotifiedTG != 1 || tgPhotoCount != 2 {
		t.Fatalf("expected dtls + 1 TG notification (total 2), got preset=%s notified=%d total=%d", resPreset.Server.Preset, resPreset.NotifiedTG, tgPhotoCount)
	}

	// 3. Switch Endpoint to IPv6 -> should auto-deliver updated config to TG
	resEp, err := fleet.SwitchServerEndpoint(ctx, srvView.ID, "ipv6", false)
	if err != nil {
		t.Fatalf("SwitchServerEndpoint failed: %v", err)
	}
	if resEp.Server.EndpointMode != "ipv6" || resEp.NotifiedTG != 1 || tgPhotoCount != 3 {
		t.Fatalf("expected ipv6 + 1 TG notification (total 3), got mode=%s notified=%d total=%d", resEp.Server.EndpointMode, resEp.NotifiedTG, tgPhotoCount)
	}

	// 4. Refresh with unchanged ETag -> 0 duplicate deliveries
	sentDup, err := fleet.RefreshServer(ctx, srvView.ID, true, true, "repeat")
	if err != nil {
		t.Fatalf("RefreshServer failed: %v", err)
	}
	if sentDup != 0 || tgPhotoCount != 3 {
		t.Fatalf("expected 0 duplicate deliveries, got sentDup=%d total=%d", sentDup, tgPhotoCount)
	}

	// 5. Rename client + change endpoint -> should update record and notify once
	epV4 := "ipv4"
	updated, err := fleet.UpdateClient(ctx, srvView.ID, "iphone", UpdateVPSClientRequest{
		Rename:   "iphone_pro",
		Endpoint: &epV4,
	})
	if err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}
	if updated.Client.ClientName != "iphone_pro" || !updated.TGSent || tgPhotoCount != 4 {
		t.Fatalf("expected rename+notify (total 4), got name=%s sent=%v total=%d", updated.Client.ClientName, updated.TGSent, tgPhotoCount)
	}

	// 6. Delete client
	if err := fleet.DeleteClient(ctx, srvView.ID, "iphone_pro"); err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}
	if len(fleet.View().Clients) != 0 {
		t.Fatalf("expected 0 clients after delete, got %d", len(fleet.View().Clients))
	}
}

func TestWebVPSFleetEndpointsAuthAndContacts(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewSettingsStore(dir)
	logger := NewRingLogger(50)
	mgr := NewTunnelManager(dir, dir, "", false, false, logger)
	fleet := NewVPSFleetManager(dir, store, mgr, nil, nil, logger)

	ws := NewWebServer(":0", mgr, nil, nil, store, nil, nil, logger)
	ws.uiUser = "admin"
	ws.uiPass = "secret12345"
	ws.SetVPSFleet(fleet)
	handler := ws.Handler()

	// 1. Unauthenticated GET /api/vps -> 401
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/vps", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}

	// 2. Authenticated GET /api/vps -> 200
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/vps", nil)
	req.SetBasicAuth("admin", "secret12345")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with auth, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Create & delete TG contact via API
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/tg/contacts", strings.NewReader(`{"name":"@alex","chat_id":"123456","thread_id":5}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "secret12345")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/tg/contacts failed: %d %s", rec.Code, rec.Body.String())
	}
	var cResp struct {
		OK      bool      `json:"ok"`
		Contact TGContact `json:"contact"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &cResp)
	if !cResp.OK || cResp.Contact.ID == "" {
		t.Fatalf("unexpected contact response: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/tg/contacts/"+cResp.Contact.ID, nil)
	req.SetBasicAuth("admin", "secret12345")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/tg/contacts failed: %d", rec.Code)
	}
	if len(fleet.View().Contacts) != 0 {
		t.Fatalf("expected 0 contacts after delete")
	}
}
