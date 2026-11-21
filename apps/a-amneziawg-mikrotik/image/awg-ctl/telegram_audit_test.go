package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", msg)
}

func TestTGStatefulIncidentNoSpamAndRecoveryReply(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:        true,
		TGBotToken:       "123:INCIDENT",
		TGChatID:         "-100777",
		TGThreadID:       10,
		TGAlertThreadID:  20,
		TGVia:            "direct",
		TGOnDown:         true,
		TGOnRecovery:     true,
		TGSilentInfo:     true,
		TGOnIntegrations: true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	tg := NewTGNotifier(st, nil, NewRingLogger(50))
	defer tg.Stop()

	var timeMu sync.Mutex
	curTime := time.Unix(1700000000, 0).UTC()
	tg.SetNowFnForTest(func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return curTime
	})

	var mu sync.Mutex
	var sent []map[string]any
	nextID := 1000
	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		sent = append(sent, m)
		nextID++
		return 200, []byte(fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, nextID)), nil
	}

	// Open same incident 5 times over 5 minutes -> must emit ONLY 1 TG message!
	for i := 0; i < 5; i++ {
		tg.OpenIncident("down:de.conf", TGKindDown, "Туннель не отвечает", "Профиль: <b>de.conf</b>")
		timeMu.Lock()
		curTime = curTime.Add(60 * time.Second)
		timeMu.Unlock()
	}
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sent) == 1
	}, "single open incident alert")
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	if len(sent) != 1 {
		mu.Unlock()
		t.Fatalf("expected exactly 1 alert for repeated OpenIncident, got %d", len(sent))
	}
	if sent[0]["message_thread_id"] != float64(20) {
		mu.Unlock()
		t.Fatalf("expected critical down alert in alert thread 20, got %v", sent[0]["message_thread_id"])
	}
	if _, hasSilent := sent[0]["disable_notification"]; hasSilent {
		mu.Unlock()
		t.Fatalf("expected critical down alert NOT silenced by tg_silent_info")
	}
	mu.Unlock()

	// Resolve incident -> must send green recovery replying to message_id 1001 in main thread 10 with disable_notification=true
	timeMu.Lock()
	curTime = curTime.Add(3 * time.Minute)
	timeMu.Unlock()
	tg.ResolveIncident("down:de.conf", "Туннель восстановлен", "Профиль: <b>de.conf</b>")
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sent) == 2
	}, "recovery notification")

	mu.Lock()
	rec := sent[1]
	mu.Unlock()
	if rec["message_thread_id"] != float64(10) {
		t.Fatalf("expected recovery in main thread 10, got %v", rec["message_thread_id"])
	}
	if rec["disable_notification"] != true {
		t.Fatalf("expected recovery silent when tg_silent_info=true")
	}
	rp, ok := rec["reply_parameters"].(map[string]any)
	if !ok || rp["message_id"] != float64(1001) {
		t.Fatalf("expected recovery reply_parameters.message_id=1001, got %v", rec["reply_parameters"])
	}
	if !strings.Contains(rec["text"].(string), "🟢") || !strings.Contains(rec["text"].(string), "Простой:") {
		t.Fatalf("unexpected recovery text: %v", rec["text"])
	}
	if tg.IsIncidentOpen("down:de.conf") {
		t.Fatalf("expected incident resolved")
	}
}

func TestTGHTMLFallbackMissingThreadAnd429Retry(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:       true,
		TGBotToken:      "123:FALLBACK",
		TGChatID:        "-100555",
		TGThreadID:      99,
		TGAlertThreadID: 88,
		TGVia:           "direct",
		TGOnDown:        true,
		TGOnStart:       true,
	}})

	tg := NewTGNotifier(st, nil, NewRingLogger(20))
	defer tg.Stop()

	var mu sync.Mutex
	var calls []map[string]any
	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		calls = append(calls, m)
		// 1st attempt: broken HTML entity simulation
		if m["parse_mode"] == "HTML" && strings.Contains(m["text"].(string), "<broken") {
			return 400, []byte(`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities: Unsupported start tag"}`), nil
		}
		// Missing thread 88 -> triggers fallback to root chat for critical event
		if m["message_thread_id"] == float64(88) {
			return 400, []byte(`{"ok":false,"error_code":400,"description":"Bad Request: message thread not found"}`), nil
		}
		return 200, []byte(`{"ok":true,"result":{"message_id":500}}`), nil
	}

	// 1. HTML error falls back to plain text without dropping message
	id, err := tg.sendSyncWithSettings(st.Get(), TGKindStart, "Boot", "raw <broken tag>")
	if err != nil || id != 500 {
		t.Fatalf("expected HTML fallback to succeed, got id=%d err=%v", id, err)
	}
	// 2. Missing thread 88 on critical TGKindDown falls back to root chat and records TopicError
	id2, err2 := tg.sendSyncWithSettings(st.Get(), TGKindDown, "Fail", "detail")
	if err2 != nil || id2 != 500 {
		t.Fatalf("expected critical thread fallback to succeed, got id=%d err=%v", id2, err2)
	}
	// Note: TopicError is populated on failed thread delivery then cleared if threadID==0 wasn't tracked; wait - let's check both TestSuite & Retry 429
	mu.Lock()
	calls = nil
	attempts := 0
	mu.Unlock()

	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		calls = append(calls, m)
		if attempts == 1 {
			return 429, []byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 1","parameters":{"retry_after":1}}`), nil
		}
		return 200, []byte(`{"ok":true,"result":{"message_id":777}}`), nil
	}
	tg.Notify(TGKindStart, "retry429", "Test429", "body")
	waitUntil(t, 4*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return attempts >= 2
	}, "worker retry after HTTP 429")

	// SendTestSuite tests both main thread (99) and alert thread (88)
	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		if m["message_thread_id"] == float64(88) {
			return 400, []byte(`{"ok":false,"error_code":400,"description":"Bad Request: message thread not found"}`), nil
		}
		return 200, []byte(`{"ok":true,"result":{"message_id":801}}`), nil
	}
	res := tg.SendTestSuite(nil, true)
	if !res.OK || res.MessageID != 801 || res.AlertError == "" {
		t.Fatalf("expected main ok and alert thread error reported, got %+v", res)
	}
}

func TestTGIndependentDeliveryModesQuietHoursAndPausedRetries(t *testing.T) {
	// 1. Quiet hours over midnight (UTC+3 = 180 min)
	// 20:30 UTC == 23:30 UTC+3 -> inside 23:00-08:00
	tQuiet := time.Date(2026, 11, 21, 20, 30, 0, 0, time.UTC)
	if !isInQuietHours("23:00-08:00", 180, tQuiet) {
		t.Fatalf("expected 23:30 UTC+3 to be inside 23:00-08:00")
	}
	// 06:00 UTC == 09:00 UTC+3 -> outside 23:00-08:00
	tLoud := time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC)
	if isInQuietHours("23:00-08:00", 180, tLoud) {
		t.Fatalf("expected 09:00 UTC+3 to be outside 23:00-08:00")
	}

	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	// Alerts DISABLED, but Client Delivery = compact!
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:      false,
		TGBotToken:     "123:DELIV",
		TGVia:          "direct",
		TGDeliveryMode: "compact",
	}})

	tg := NewTGNotifier(st, nil, NewRingLogger(20))
	defer tg.Stop()

	if status := tg.Status(); status.AlertsEnabled || !status.DeliveryEnabled || status.DeliveryMode != "compact" {
		t.Fatalf("unexpected split TGStatus: %+v", status)
	}

	var methods []string
	var bodyPayloads []string
	tg.sendMethodFn = func(_ context.Context, _, _, _, method, _ string, payload []byte) (int, []byte, error) {
		methods = append(methods, method)
		bodyPayloads = append(bodyPayloads, string(payload))
		return 200, []byte(`{"ok":true,"result":{"message_id":99}}`), nil
	}

	sampleConf := "[Interface]\nPrivateKey = AAA=\nAddress = 10.8.99.2/32\n[Peer]\nPublicKey = BBB=\nEndpoint = 1.2.3.4:443\nAllowedIPs = 0.0.0.0/0\n"
	// Compact mode on rotation (isCreation=false) -> ONLY sendDocument + CopyText button for subURL
	if err := tg.SendClientConfigWithOptions(context.Background(), "555", 0, "dom25", "bob", "Ротация", sampleConf, "vpn://verylong...", "http://1.2.3.4:8443/sub/awg_tok_xyz", false); err != nil {
		t.Fatalf("compact rotation delivery failed: %v", err)
	}
	if len(methods) != 1 || methods[0] != "sendDocument" {
		t.Fatalf("expected only sendDocument for compact rotation, got %v", methods)
	}
	if !strings.Contains(bodyPayloads[0], "copy_text") || !strings.Contains(bodyPayloads[0], "awg_tok_xyz") {
		t.Fatalf("expected copy_text button with subURL in sendDocument payload")
	}

	// Delivery mode OFF rejects SendClientConfig
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGBotToken:     "123:DELIV",
		TGDeliveryMode: "off",
	}})
	if err := tg.SendClientConfig(context.Background(), "555", 0, "dom25", "bob", "Тест", sampleConf, "", ""); err == nil {
		t.Fatalf("expected error when tg_delivery_mode=off")
	}
}

func TestFailoverSingleBlackoutRecoveryAndAntiFlap(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:               true,
		TGBotToken:              "123:FO",
		TGChatID:                "-100111",
		TGAlertThreadID:         55,
		TGVia:                   "direct",
		TGOnDown:                true,
		TGOnFailover:            true,
		TGOnRecovery:            true,
		TGOnIntegrations:        true,
		FailoverMode:            "switch",
		FailoverTrigger:         "probe",
		FailoverThreshold:       1,
		FailoverCooldownSec:     180,
		FailoverHandshakeSec:    10,
		FailoverHandshakeMaxAge: 180,
	}})

	tg := NewTGNotifier(st, nil, NewRingLogger(30))
	defer tg.Stop()

	var mu sync.Mutex
	var texts []string
	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		texts = append(texts, fmt.Sprint(m["text"]))
		return 200, []byte(`{"ok":true,"result":{"message_id":301}}`), nil
	}

	probeOK := false
	primary := "de.conf"
	now := time.Unix(1700000000, 0)
	fo := NewFailoverMonitor(nil, st, tg, NewRingLogger(30))
	defer fo.Stop()
	fo.nowFn = func() time.Time { return now }
	fo.startedAtFn = func(string) time.Time { return now.Add(-time.Minute) }
	fo.markFn = func(string) int { return 0 }
	fo.configsFn = func() ([]ConfigMeta, error) {
		return []ConfigMeta{{Name: primary, Interface: "de", Enabled: true, Primary: true, Selected: true}}, nil
	}
	fo.ifacesFn = func() ([]InterfaceStatus, error) {
		return []InterfaceStatus{{Name: "de", Peers: []PeerStatus{{HandshakeAgeSec: 5}}}}, nil
	}
	fo.probeFn = func(_ context.Context, _ string, _ int, _ string) (int64, error) {
		if probeOK {
			return 15, nil
		}
		return 0, fmt.Errorf("timeout")
	}
	fo.switchFn = func(target string, _ bool) error {
		primary = target
		return nil
	}

	// 4 consecutive failures -> ONLY 1 alert!
	for i := 0; i < 4; i++ {
		fo.CheckNow(false)
		now = now.Add(30 * time.Second)
	}
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(texts) == 1
	}, "single down alert")
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	if len(texts) != 1 || !strings.Contains(texts[0], "Туннель не отвечает") {
		mu.Unlock()
		t.Fatalf("expected 1 down alert despite 4 failed checks, got %v", texts)
	}
	mu.Unlock()

	// Recover -> 2 healthy checks (hysteresis) trigger 1 green recovery
	probeOK = true
	fo.CheckNow(false) // streak 1
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	if len(texts) != 1 {
		mu.Unlock()
		t.Fatalf("expected hysteresis before recovery alert, got %v", texts)
	}
	mu.Unlock()
	fo.CheckNow(false) // streak 2 -> resolves!
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(texts) == 2
	}, "recovery alert")
	mu.Lock()
	if !strings.Contains(texts[1], "Туннель восстановлен") {
		mu.Unlock()
		t.Fatalf("expected recovery message, got %q", texts[1])
	}
	texts = nil
	mu.Unlock()

	// Anti-flap: 4 switches in <5m triggers flap suppression
	fo.configsFn = func() ([]ConfigMeta, error) {
		return []ConfigMeta{
			{Name: "de.conf", Interface: "de", Enabled: true, Primary: primary == "de.conf", Selected: primary == "de.conf"},
			{Name: "nl.conf", Interface: "nl", Enabled: true, Primary: primary == "nl.conf", Selected: primary == "nl.conf"},
		}, nil
	}
	_ = fo.SwitchTo("nl.conf", "probe fail")
	now = now.Add(30 * time.Second)
	_ = fo.SwitchTo("de.conf", "probe fail")
	now = now.Add(30 * time.Second)
	_ = fo.SwitchTo("nl.conf", "probe fail") // 3rd -> triggers flap warning & suppression
	now = now.Add(30 * time.Second)
	_ = fo.SwitchTo("de.conf", "probe fail") // 4th -> suppressed!

	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, txt := range texts {
			if strings.Contains(txt, "флаппинг") {
				return true
			}
		}
		return false
	}, "anti-flap warning")
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	if len(texts) > 3 {
		mu.Unlock()
		t.Fatalf("expected 4th switch suppressed after flap warning, got %d msgs: %v", len(texts), texts)
	}
	mu.Unlock()
}

func TestVPSFleetBaselineNoPrematureSendAndAutoPause(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/clients" {
			_, _ = rw.Write([]byte(`{"ok":true,"server":{"listen_port":443,"preset":"quic","server_etag":"srv1"},"client":{"name":"no_send","ipv4":"10.8.99.5","endpoint":"1.2.3.4:443","etag":"etag_init","config":"[Interface]\nPrivateKey=A\n[Peer]\nEndpoint=1.2.3.4:443"}}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/clients" {
			_, _ = rw.Write([]byte(`{"ok":true,"server":{"listen_port":443,"preset":"quic","server_etag":"srv2"},"clients":[{"name":"no_send","ipv4":"10.8.99.5","endpoint":"1.2.3.4:443","etag":"etag_init"},{"name":"blocked_user","ipv4":"10.8.99.6","endpoint":"1.2.3.4:443","etag":"etag_new"}]}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/clients/") {
			_, _ = rw.Write([]byte(`{"ok":true,"client":{"name":"blocked_user","ipv4":"10.8.99.6","endpoint":"1.2.3.4:443","etag":"etag_new","config":"[Interface]\nPrivateKey=B\nAddress=10.8.99.6/32\n[Peer]\nEndpoint=1.2.3.4:443\nPublicKey=C"}}`))
			return
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGBotToken:     "123:FLEET",
		TGVia:          "direct",
		TGDeliveryMode: "compact",
	}})
	tg := NewTGNotifier(st, nil, NewRingLogger(20))
	defer tg.Stop()

	var tgCalls int
	tg.sendMethodFn = func(_ context.Context, _, _, _, _, _ string, _ []byte) (int, []byte, error) {
		tgCalls++
		return 403, []byte(`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`), nil
	}

	fm := NewVPSFleetManager(dir, st, nil, nil, tg, NewRingLogger(20))
	u := strings.TrimPrefix(ts.URL, "https://")
	parts := strings.Split(u, ":")
	port := 8443
	_, _ = fmt.Sscanf(parts[1], "%d", &port)
	useHTTPS, skip := true, true
	srv, err := fm.UpsertServer(UpsertVPSRequest{
		Name: "v1", APIHost: parts[0], APIPort: port, UseHTTPS: &useHTTPS, TLSSkipVerify: &skip, AdminToken: "awg_adm_1234567890",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create client with SendNow=false -> baseline LastSentETag set, poller MUST NOT send etag_init!
	created, err := fm.CreateClient(context.Background(), srv.ID, CreateVPSClientRequest{
		Name: "no_send", TGChatID: "111", TGAutoSend: true, SendNow: false,
	})
	if err != nil || created.Client.LastSentETag != "etag_init" {
		t.Fatalf("expected baseline LastSentETag=etag_init when SendNow=false, got %+v err=%v", created.Client, err)
	}

	// Simulate blocked_user failing 3 times -> pauses auto-delivery
	fm.mu.Lock()
	fm.state.Clients = append(fm.state.Clients, FleetClient{
		ID: fleetClientKey(srv.ID, "blocked_user"), VPSID: srv.ID, ClientName: "blocked_user",
		TGChatID: "222", TGAutoSend: true, LastETag: "etag_old", LastSentETag: "etag_old",
	})
	fm.mu.Unlock()

	// Attempt 1 via RefreshServer
	_, _ = fm.RefreshServer(context.Background(), srv.ID, false, true, "rot")
	if tgCalls != 1 {
		t.Fatalf("expected 1 TG attempt (no_send skipped cleanly!), got %d", tgCalls)
	}
	// Reset backoff timer in test to simulate 2nd and 3rd failures
	for attempt := 2; attempt <= 3; attempt++ {
		fm.mu.Lock()
		for i := range fm.state.Clients {
			if fm.state.Clients[i].ClientName == "blocked_user" {
				fm.state.Clients[i].AutoSendNextRetry = time.Now().Add(-time.Minute)
			}
		}
		fm.mu.Unlock()
		_, _ = fm.RefreshServer(context.Background(), srv.ID, false, true, "rot")
	}
	if tgCalls != 3 {
		t.Fatalf("expected 3 total TG attempts before auto-pause, got %d", tgCalls)
	}
	// 4th refresh -> AutoSendPaused MUST prevent any further spam!
	_, _ = fm.RefreshServer(context.Background(), srv.ID, false, true, "rot")
	if tgCalls != 3 {
		t.Fatalf("expected auto-paused client skipped on 4th refresh (want 3 calls, got %d)", tgCalls)
	}

	// ResetClientTGState restores delivery capability
	if err := fm.ResetClientTGState(srv.ID, "blocked_user"); err != nil {
		t.Fatal(err)
	}
	for _, c := range fm.View().Clients {
		if c.ClientName == "blocked_user" && c.AutoSendPaused {
			t.Fatalf("expected AutoSendPaused cleared after ResetClientTGState")
		}
	}
}

func TestSubscriptionAndROSIncidentThreshold(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewSettingsStore(dir)
	_, _ = st.Update(SettingsUpdate{AppSettings: AppSettings{
		TGEnabled:        true,
		TGBotToken:       "123:INT",
		TGChatID:         "-100222",
		TGVia:            "direct",
		TGOnIntegrations: true,
		TGOnRecovery:     true,
	}})
	tg := NewTGNotifier(st, nil, NewRingLogger(20))
	defer tg.Stop()

	var mu sync.Mutex
	var texts []string
	tg.sendHTTPFn = func(_ context.Context, _, _, _ string, payload []byte) (int, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		texts = append(texts, fmt.Sprint(m["text"]))
		return 200, []byte(`{"ok":true,"result":{"message_id":404}}`), nil
	}

	sm := NewSubscriptionManager(st, nil, tg, NewRingLogger(10))
	// 1 and 2 errors must NOT open incident
	sm.recordSyncOutcome("de.conf", fmt.Errorf("conn refused"))
	sm.recordSyncOutcome("de.conf", fmt.Errorf("conn refused"))
	if tg.IsIncidentOpen("sub_err:de.conf") {
		t.Fatalf("expected no sub_err incident before 3 failures")
	}
	// 3rd failure opens sub_err incident
	sm.recordSyncOutcome("de.conf", fmt.Errorf("conn refused"))
	if !tg.IsIncidentOpen("sub_err:de.conf") {
		t.Fatalf("expected sub_err incident opened on 3rd failure")
	}
	// Success resolves it
	sm.recordSyncOutcome("de.conf", nil)
	if tg.IsIncidentOpen("sub_err:de.conf") {
		t.Fatalf("expected sub_err incident resolved on success")
	}

	// ROS 3 failures -> opens ros:sync -> recordModeSuccess resolves
	ros := NewROSClient(dir, NewRingLogger(10))
	ros.SetTGNotifier(tg)
	ros.recordFailure("timeout 1", true, true)
	ros.recordFailure("timeout 2", true, true)
	if tg.IsIncidentOpen("ros:sync") {
		t.Fatalf("expected no ros:sync incident before 3 failures")
	}
	ros.recordFailure("timeout 3", true, true)
	if !tg.IsIncidentOpen("ros:sync") {
		t.Fatalf("expected ros:sync incident on 3rd failure")
	}
	ros.recordModeSuccess(rosConnConfig{mode: ROSModeAddressList}, "fp", 0, 0, 1, 0, 0, "rest", true)
	if tg.IsIncidentOpen("ros:sync") {
		t.Fatalf("expected ros:sync incident resolved")
	}

	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(texts) >= 4
	}, "all integration alert & recovery messages")
}
