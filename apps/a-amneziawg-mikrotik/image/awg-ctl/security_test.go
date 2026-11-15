package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestWebServer(t *testing.T, uiPass string) (*WebServer, *SettingsStore, *TunnelManager, *PolicyEngine) {
	t.Helper()
	t.Setenv("UI_PASSWORD", uiPass)
	t.Setenv("TERM_ENABLE", "")
	t.Setenv("AWG_ALLOW_HOOKS", "")
	dir := t.TempDir()
	logger := NewRingLogger(50)
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", true, true, logger)
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore: %v", err)
	}
	geo := NewGeoStore(dir, logger)
	pol := NewPolicyEngine(dir, st, geo, mgr, logger)
	ros := NewROSClient(dir, logger)
	w := NewWebServer(":0", mgr, nil, ros, st, geo, pol, logger)
	return w, st, mgr, pol
}

func TestSecurityFirstRunSetupAndCookieAuth(t *testing.T) {
	w, st, _, _ := newTestWebServer(t, "")
	h := w.Handler()

	// 1. Fresh state: auth/status reports needs_setup=true, /api/status returns 401 needs_setup=true
	reqSt := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	rwSt := httptest.NewRecorder()
	h.ServeHTTP(rwSt, reqSt)
	if rwSt.Code != http.StatusOK {
		t.Fatalf("auth status code=%d", rwSt.Code)
	}
	var stBody map[string]any
	_ = json.Unmarshal(rwSt.Body.Bytes(), &stBody)
	if stBody["needs_setup"] != true || stBody["authenticated"] != false {
		t.Fatalf("expected needs_setup=true authenticated=false, got %v", stBody)
	}

	reqAPI := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rwAPI := httptest.NewRecorder()
	h.ServeHTTP(rwAPI, reqAPI)
	if rwAPI.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 before setup, got %d", rwAPI.Code)
	}
	var apiErr map[string]any
	_ = json.Unmarshal(rwAPI.Body.Bytes(), &apiErr)
	if apiErr["needs_setup"] != true {
		t.Fatalf("expected needs_setup=true in 401 body, got %v", apiErr)
	}

	// GET / remains accessible (serves static UI with zero secrets)
	reqIdx := httptest.NewRequest(http.MethodGet, "/", nil)
	rwIdx := httptest.NewRecorder()
	h.ServeHTTP(rwIdx, reqIdx)
	if rwIdx.Code != http.StatusOK {
		t.Fatalf("expected GET / 200 for login modal HTML, got %d", rwIdx.Code)
	}

	// 2. Reject short password in /api/auth/setup
	reqShort := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"user":"admin","password":"123"}`))
	reqShort.Header.Set("Content-Type", "application/json")
	rwShort := httptest.NewRecorder()
	h.ServeHTTP(rwShort, reqShort)
	if rwShort.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", rwShort.Code)
	}

	// 3. Valid setup creates PBKDF2 hash (not plaintext) and sets HttpOnly SameSite=Strict cookie
	reqSetup := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"user":"alice","password":"CorrectHorse99"}`))
	reqSetup.Header.Set("Content-Type", "application/json")
	rwSetup := httptest.NewRecorder()
	h.ServeHTTP(rwSetup, reqSetup)
	if rwSetup.Code != http.StatusOK {
		t.Fatalf("setup failed: code=%d body=%s", rwSetup.Code, rwSetup.Body.String())
	}
	cookies := rwSetup.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessCookie = c
		}
	}
	if sessCookie == nil || !sessCookie.HttpOnly || sessCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected HttpOnly SameSite=Strict session cookie, got %+v", sessCookie)
	}
	saved := st.Get()
	if saved.UIPassHash == "" || strings.Contains(saved.UIPassHash, "CorrectHorse99") {
		t.Fatalf("expected PBKDF2 hash stored, got %q", saved.UIPassHash)
	}
	// View must scrub UIPassHash
	if view := st.View(); view.UIPassHash != "" || !view.UIAuthConfigured || view.UIAuthSource != "setup" {
		t.Fatalf("unexpected SettingsView: %+v", view)
	}

	// 4. Repeat setup must be rejected with 409 Conflict
	reqSetup2 := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"user":"mallory","password":"HackerPassword1"}`))
	reqSetup2.Header.Set("Content-Type", "application/json")
	rwSetup2 := httptest.NewRecorder()
	h.ServeHTTP(rwSetup2, reqSetup2)
	if rwSetup2.Code != http.StatusConflict {
		t.Fatalf("expected 409 on second setup, got %d", rwSetup2.Code)
	}

	// 5. Session cookie grants access to /api/status
	reqAuthed := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqAuthed.AddCookie(sessCookie)
	rwAuthed := httptest.NewRecorder()
	h.ServeHTTP(rwAuthed, reqAuthed)
	if rwAuthed.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid cookie, got %d (%s)", rwAuthed.Code, rwAuthed.Body.String())
	}

	// 6. Password change rotates password and invalidates old sessions
	reqChg := httptest.NewRequest(http.MethodPost, "/api/auth/password", strings.NewReader(`{"user":"alice","current_password":"CorrectHorse99","new_password":"NewStrongPass42"}`))
	reqChg.Header.Set("Content-Type", "application/json")
	reqChg.AddCookie(sessCookie)
	rwChg := httptest.NewRecorder()
	h.ServeHTTP(rwChg, reqChg)
	if rwChg.Code != http.StatusOK {
		t.Fatalf("password change failed: code=%d body=%s", rwChg.Code, rwChg.Body.String())
	}
	reqOldCookie := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqOldCookie.AddCookie(sessCookie)
	rwOldCookie := httptest.NewRecorder()
	h.ServeHTTP(rwOldCookie, reqOldCookie)
	if rwOldCookie.Code != http.StatusUnauthorized {
		t.Fatalf("expected old cookie invalidated after password change, got %d", rwOldCookie.Code)
	}

	// 7. Login with new password succeeds, then logout invalidates cookie
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"user":"alice","password":"NewStrongPass42"}`))
	reqLogin.Header.Set("Content-Type", "application/json")
	rwLogin := httptest.NewRecorder()
	h.ServeHTTP(rwLogin, reqLogin)
	if rwLogin.Code != http.StatusOK {
		t.Fatalf("login failed: code=%d body=%s", rwLogin.Code, rwLogin.Body.String())
	}
	var newSess *http.Cookie
	for _, c := range rwLogin.Result().Cookies() {
		if c.Name == sessionCookieName {
			newSess = c
		}
	}
	reqLogout := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	reqLogout.AddCookie(newSess)
	rwLogout := httptest.NewRecorder()
	h.ServeHTTP(rwLogout, reqLogout)
	if rwLogout.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", rwLogout.Code)
	}
	reqAfterLogout := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqAfterLogout.AddCookie(newSess)
	rwAfterLogout := httptest.NewRecorder()
	h.ServeHTTP(rwAfterLogout, reqAfterLogout)
	if rwAfterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", rwAfterLogout.Code)
	}
}

func TestSecurityBruteForceRateLimit(t *testing.T) {
	w, _, _, _ := newTestWebServer(t, "SecretPass123")
	h := w.Handler()

	for i := 1; i < authMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"user":"admin","password":"wrong"}`))
		req.RemoteAddr = "192.0.2.50:4444"
		req.Header.Set("Content-Type", "application/json")
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rw.Code)
		}
	}

	// authMaxFailures-th failure locks IP and returns 429
	reqLock := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"user":"admin","password":"wrong"}`))
	reqLock.RemoteAddr = "192.0.2.50:4444"
	reqLock.Header.Set("Content-Type", "application/json")
	rwLock := httptest.NewRecorder()
	h.ServeHTTP(rwLock, reqLock)
	if rwLock.Code != http.StatusTooManyRequests || rwLock.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After on %dth failure, got %d", authMaxFailures, rwLock.Code)
	}

	// Even correct password from same locked IP is blocked during lockout
	reqGoodSameIP := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"user":"admin","password":"SecretPass123"}`))
	reqGoodSameIP.RemoteAddr = "192.0.2.50:4445"
	reqGoodSameIP.Header.Set("Content-Type", "application/json")
	rwGoodSameIP := httptest.NewRecorder()
	h.ServeHTTP(rwGoodSameIP, reqGoodSameIP)
	if rwGoodSameIP.Code != http.StatusTooManyRequests {
		t.Fatalf("expected locked IP blocked on valid password too, got %d", rwGoodSameIP.Code)
	}

	// Different IP is unaffected
	reqOtherIP := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"user":"admin","password":"SecretPass123"}`))
	reqOtherIP.RemoteAddr = "192.0.2.99:4445"
	reqOtherIP.Header.Set("Content-Type", "application/json")
	rwOtherIP := httptest.NewRecorder()
	h.ServeHTTP(rwOtherIP, reqOtherIP)
	if rwOtherIP.Code != http.StatusOK {
		t.Fatalf("expected unaffected IP to login, got %d", rwOtherIP.Code)
	}
}

func TestSecurityCSRFHeadersAndFormRejection(t *testing.T) {
	w, _, _, _ := newTestWebServer(t, "SecretPass123")
	h := w.Handler()

	// Security headers on GET /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Header().Get("X-Frame-Options") != "DENY" ||
		rw.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rw.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(rw.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing security headers: %v", rw.Header())
	}

	// Cross-origin POST blocked with 403 even with valid BasicAuth
	reqCSRF := httptest.NewRequest(http.MethodPost, "/api/tunnel/up", nil)
	reqCSRF.Host = "192.168.1.1:8080"
	reqCSRF.Header.Set("Origin", "https://evil.example")
	reqCSRF.Header.Set("Sec-Fetch-Site", "cross-site")
	reqCSRF.SetBasicAuth("admin", "SecretPass123")
	rwCSRF := httptest.NewRecorder()
	h.ServeHTTP(rwCSRF, reqCSRF)
	if rwCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 CSRF block, got %d (%s)", rwCSRF.Code, rwCSRF.Body.String())
	}

	// HTML form Content-Type rejected with 415
	reqForm := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader("term_enabled=true"))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqForm.SetBasicAuth("admin", "SecretPass123")
	rwForm := httptest.NewRecorder()
	h.ServeHTTP(rwForm, reqForm)
	if rwForm.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 for form-urlencoded POST, got %d", rwForm.Code)
	}
}

func TestSecurityTerminalGating(t *testing.T) {
	w, st, _, _ := newTestWebServer(t, "SecretPass123")
	h := w.Handler()

	// Default disabled -> 403
	req1 := httptest.NewRequest(http.MethodPost, "/api/term/exec", strings.NewReader(`{"command":"id"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.SetBasicAuth("admin", "SecretPass123")
	rw1 := httptest.NewRecorder()
	h.ServeHTTP(rw1, req1)
	if rw1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when terminal disabled by default, got %d", rw1.Code)
	}

	reqKill := httptest.NewRequest(http.MethodPost, "/api/term/kill", strings.NewReader(`{"exec_id":"x"}`))
	reqKill.Header.Set("Content-Type", "application/json")
	reqKill.SetBasicAuth("admin", "SecretPass123")
	rwKill := httptest.NewRecorder()
	h.ServeHTTP(rwKill, reqKill)
	if rwKill.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on term/kill when disabled, got %d", rwKill.Code)
	}

	// Enabling via SettingsUpdate permits execution
	cur := st.Get()
	cur.TermEnabled = true
	if _, err := st.Update(SettingsUpdate{AppSettings: cur}); err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/api/term/exec", strings.NewReader(`{"command":"echo ok"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.SetBasicAuth("admin", "SecretPass123")
	rw2 := httptest.NewRecorder()
	h.ServeHTTP(rw2, req2)
	if rw2.Code != http.StatusOK {
		t.Fatalf("expected 200 when term_enabled=true, got %d (%s)", rw2.Code, rw2.Body.String())
	}

	// TERM_ENABLE=off hard override disables even when stored term_enabled=true
	t.Setenv("TERM_ENABLE", "off")
	req3 := httptest.NewRequest(http.MethodPost, "/api/term/exec", strings.NewReader(`{"command":"echo ok"}`))
	req3.Header.Set("Content-Type", "application/json")
	req3.SetBasicAuth("admin", "SecretPass123")
	rw3 := httptest.NewRecorder()
	h.ServeHTTP(rw3, req3)
	if rw3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when TERM_ENABLE=off, got %d", rw3.Code)
	}
}

func TestSecuritySaveConfigHooksGating(t *testing.T) {
	dir := t.TempDir()
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", true, true, NewRingLogger(10))

	for _, key := range []string{"PreUp", "PostUp", "PreDown", "PostDown"} {
		conf := "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" + key + " = /bin/sh -c id\n"
		if err := mgr.SaveConfig("wg0.conf", conf); err == nil {
			t.Fatalf("expected SaveConfig to reject %s when allowHooks=false", key)
		}
	}

	// Commented hook must still succeed
	commented := "[Interface]\n# PostUp = iptables -A ...\n; PreDown = echo bye\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	if err := mgr.SaveConfig("wg0.conf", commented); err != nil {
		t.Fatalf("expected commented hook to be allowed, got: %v", err)
	}

	mgr.SetAllowHooks(true)
	withHook := "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nPostUp = echo ok\n"
	if err := mgr.SaveConfig("wg0.conf", withHook); err != nil {
		t.Fatalf("expected PostUp allowed when SetAllowHooks(true), got: %v", err)
	}
}

func TestSecuritySecretExfiltrationGuardsAndRedaction(t *testing.T) {
	// 1. Redaction
	tok := "123456:ABCdef_SecretBotToken99"
	red := redactTelegramSecrets("Post https://api.telegram.org/bot"+tok+"/sendMessage: dial error token="+tok, tok)
	if strings.Contains(red, tok) || !strings.Contains(red, "bot***REDACTED***") {
		t.Fatalf("token not redacted: %q", red)
	}

	// 2. validateHTTPURL scheme & userinfo check
	for _, bad := range []string{"file:///etc/passwd", "ftp://example.com/a", "https://user:pass@example.com"} {
		if err := validateHTTPURL(bad); err == nil {
			t.Fatalf("expected validateHTTPURL(%q) to fail", bad)
		}
	}

	// 3. Telegram test cannot exfiltrate stored token to another tg_api_url
	w, st, mgr, _ := newTestWebServer(t, "SecretPass123")
	tg := NewTGNotifier(st, mgr, NewRingLogger(10))
	defer tg.Stop()
	w.SetIntegrations(nil, tg)

	cur := st.Get()
	cur.TGEnabled = true
	cur.TGBotToken = tok
	cur.TGChatID = "12345"
	if _, err := st.Update(SettingsUpdate{AppSettings: cur}); err != nil {
		t.Fatal(err)
	}

	attackerHits := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		attackerHits++
		rw.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	h := w.Handler()
	reqTG := httptest.NewRequest(http.MethodPost, "/api/telegram/test", strings.NewReader(`{"tg_api_url":"`+attacker.URL+`","tg_chat_id":"12345"}`))
	reqTG.Header.Set("Content-Type", "application/json")
	reqTG.SetBasicAuth("admin", "SecretPass123")
	rwTG := httptest.NewRecorder()
	h.ServeHTTP(rwTG, reqTG)
	if rwTG.Code != http.StatusBadRequest || attackerHits != 0 {
		t.Fatalf("expected 400 and 0 attacker hits on tg_api_url swap, got code=%d hits=%d body=%s", rwTG.Code, attackerHits, rwTG.Body.String())
	}

	// 4. ROS test cannot exfiltrate stored password to another ros_url or ros_user
	cur = st.Get()
	cur.ROSURL = "http://127.0.0.1:1"
	cur.ROSUser = "awg-api"
	cur.ROSPass = "TopSecretRouterPass"
	if _, err := st.Update(SettingsUpdate{AppSettings: cur}); err != nil {
		t.Fatal(err)
	}
	w.ros.Configure(st.Get())

	rosHits := 0
	rosAttacker := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rosHits++
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer rosAttacker.Close()

	reqROS := httptest.NewRequest(http.MethodPost, "/api/ros/test", strings.NewReader(`{"ros_url":"`+rosAttacker.URL+`","ros_user":"awg-api"}`))
	reqROS.Header.Set("Content-Type", "application/json")
	reqROS.SetBasicAuth("admin", "SecretPass123")
	rwROS := httptest.NewRecorder()
	h.ServeHTTP(rwROS, reqROS)
	if rwROS.Code != http.StatusBadRequest || rosHits != 0 {
		t.Fatalf("expected 400 and 0 attacker hits on ros_url swap, got code=%d hits=%d body=%s", rwROS.Code, rosHits, rwROS.Body.String())
	}

	// Direct ROSClient.TestConnection also blocks secret reuse
	res := w.ros.TestConnection(&AppSettings{ROSURL: rosAttacker.URL, ROSUser: "awg-api"})
	if res.OK || rosHits != 0 {
		t.Fatalf("expected ROSClient.TestConnection to block password reuse, got %+v hits=%d", res, rosHits)
	}
}

func TestROSAPITLSPortAutoSwitchAndServiceWarnings(t *testing.T) {
	// 1. Env ROS_API_TLS=on defaults port to 8729
	t.Setenv("ROS_API_TLS", "on")
	t.Setenv("ROS_API_PORT", "")
	def := defaultSettingsFromEnv()
	if !def.ROSAPITLS || def.ROSAPIPort != 8729 {
		t.Fatalf("expected ROS_API_TLS=on -> port 8729, got tls=%v port=%d", def.ROSAPITLS, def.ROSAPIPort)
	}

	// 2. SettingsStore Update auto-switches 8728 <-> 8729 when toggling ROSAPITLS
	t.Setenv("ROS_API_TLS", "off")
	dir := t.TempDir()
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cur := st.Get()
	if cur.ROSAPIPort != 8728 || cur.ROSAPITLS {
		t.Fatalf("expected default 8728/false, got %d/%v", cur.ROSAPIPort, cur.ROSAPITLS)
	}
	cur.ROSAPITLS = true
	next, err := st.Update(SettingsUpdate{AppSettings: cur})
	if err != nil || next.ROSAPIPort != 8729 {
		t.Fatalf("expected auto-switch to 8729, got %d (err=%v)", next.ROSAPIPort, err)
	}
	next.ROSAPITLS = false
	next2, err := st.Update(SettingsUpdate{AppSettings: next})
	if err != nil || next2.ROSAPIPort != 8728 {
		t.Fatalf("expected auto-switch back to 8728, got %d (err=%v)", next2.ROSAPIPort, err)
	}

	// 3. InspectSchema adds non-blocking warnings when /ip/service is unrestricted or api-ssl lacks cert
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/ip/service", "/rest/ip/service/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{
				{".id": "*1", "name": "api-ssl", "port": "8729", "address": "", "certificate": "none", "disabled": "false"},
				{".id": "*2", "name": "www-ssl", "port": "443", "address": "192.168.0.0/16", "certificate": "cert1", "disabled": "false"},
			})
		case "/rest/ip/dns", "/rest/ip/dns/print":
			_ = json.NewEncoder(rw).Encode(map[string]any{"servers": "192.168.253.2", "allow-remote-requests": "true"})
		case "/rest/routing/table", "/rest/routing/table/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{{".id": "*1", "name": "AmneziaWGRoS", "disabled": "false"}})
		case "/rest/ip/route", "/rest/ip/route/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "192.168.253.2", "routing-table": "AmneziaWGRoS", "disabled": "false"}})
		case "/rest/interface/list/member", "/rest/interface/list/member/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{{".id": "*1", "list": "LAN", "interface": "bridge"}})
		case "/rest/ip/firewall/mangle", "/rest/ip/firewall/mangle/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{
				{".id": "*1", "chain": "prerouting", "action": "accept", "src-address": "192.168.253.2", "disabled": "false"},
				{".id": "*2", "chain": "prerouting", "action": "mark-connection", "new-connection-mark": "AmneziaWGRoS", "comment": "AWG_GW_Mark_All", "disabled": "false"},
				{".id": "*3", "chain": "prerouting", "action": "mark-routing", "connection-mark": "AmneziaWGRoS", "new-routing-mark": "AmneziaWGRoS", "comment": "AWG_Route_Conn", "disabled": "false"},
				{".id": "*4", "chain": "prerouting", "action": "mark-routing", "connection-mark": "AmneziaWGRoS", "new-routing-mark": "AmneziaWGRoS", "comment": "AWG_Route_New", "disabled": "false"},
			})
		default:
			_ = json.NewEncoder(rw).Encode([]map[string]any{})
		}
	}))
	defer srv.Close()

	ros := NewROSClient(dir, NewRingLogger(10))
	s := st.Get()
	s.ROSMode = ROSModeGateway
	s.ROSURL = srv.URL
	s.ROSUser = "awg-api"
	s.ROSPass = "pass"
	s.ROSContainerIP = "192.168.253.2"
	s.ROSRouteTable = "AmneziaWGRoS"
	s.ROSUseBinaryAPI = false
	ros.Configure(s)
	rep := ros.InspectSchema(s)
	if !rep.OK {
		t.Fatalf("expected advisory warnings not to fail Schema OK (err=%q), got checks=%+v", rep.Error, rep.Checks)
	}
	joined := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(joined, "api-ssl") || !strings.Contains(joined, "certificate=none") {
		t.Fatalf("expected api-ssl service security warnings, got: %v", rep.Warnings)
	}
}

func TestPolicyIPv6LeakGuard(t *testing.T) {
	dir := t.TempDir()
	// Dummy IPv4 tunnel config (no IPv6 Address=)
	if err := os.WriteFile(filepath.Join(dir, "awg0.conf"), []byte("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := NewSettingsStore(dir)
	geo := NewGeoStore(dir, NewRingLogger(10))
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", true, true, NewRingLogger(10))
	pol := NewPolicyEngine(dir, st, geo, mgr, NewRingLogger(10))
	pol.detectRouteFn = func(lan string) (string, []netip.Prefix) {
		return "192.168.253.1", []netip.Prefix{netip.MustParsePrefix("192.168.253.0/30")}
	}
	pol.runBatchFn = func(script string) error { return nil }

	var cmds []string
	pol.runCmdFn = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}

	t.Setenv("AWG_ENABLE_IPV6", "")
	if err := pol.ApplyRouting(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip6tables -P FORWARD DROP") {
		t.Fatalf("expected ip6tables FORWARD DROP leak guard, got:\n%s", joined)
	}

	// When AWG_ENABLE_IPV6=on, IPv6 FORWARD DROP is not applied
	cmds = nil
	t.Setenv("AWG_ENABLE_IPV6", "on")
	if err := pol.ApplyRouting(); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(cmds, "\n")
	if strings.Contains(joined, "ip6tables -P FORWARD DROP") {
		t.Fatalf("expected no ip6tables drop when AWG_ENABLE_IPV6=on, got:\n%s", joined)
	}
}
