package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestROSURLAndContainerIPNormalization(t *testing.T) {
	if got := normalizeROSBaseURL(" 172.18.0.1/ "); got != "https://172.18.0.1" {
		t.Fatalf("missing scheme should default to https://, got %q", got)
	}
	if got := normalizeROSBaseURL("https://172.18.0.1:8443/rest/"); got != "https://172.18.0.1:8443" {
		t.Fatalf("trailing /rest/ should be stripped, got %q", got)
	}
	if got := normalizeROSBaseURL("http://192.168.88.1/rest"); got != "http://192.168.88.1" {
		t.Fatalf("trailing /rest should be stripped, got %q", got)
	}
	if errMsg := validateROSBaseURL("ftp://172.18.0.1"); errMsg == "" {
		t.Fatalf("expected ftp scheme validation failure")
	}

	if got := normalizeROSContainerIP("172.18.0.99/24"); got != "172.18.0.99" {
		t.Fatalf("expected CIDR strip to 172.18.0.99, got %q", got)
	}
	if got := normalizeROSContainerIP("AUTO"); got != "" {
		t.Fatalf("expected AUTO -> empty auto mode, got %q", got)
	}

	tmp := t.TempDir()
	ros := NewROSClient(tmp, NewRingLogger(20))
	ros.SetAutoGatewayFn(func() string { return "172.18.0.99" })
	ros.Configure(AppSettings{ROSURL: "172.18.0.1/rest", ROSUser: "awg-api"})

	st := ros.Status()
	if !st.Enabled || st.URL != "https://172.18.0.1" || st.GatewayIP != "172.18.0.99" || st.AutoGatewayIP != "172.18.0.99" {
		t.Fatalf("unexpected ROS status: %+v", st)
	}

	ros.Configure(AppSettings{ROSURL: "ftp://172.18.0.1", ROSUser: "awg-api"})
	if st2 := ros.Status(); st2.Enabled || st2.LastError == "" {
		t.Fatalf("expected invalid scheme disabled with LastError, got %+v", st2)
	}
}

func TestROSPostPrintPatchCIDRAndAddrListUpdate(t *testing.T) {
	var mu sync.Mutex
	var ops []string
	var dnsPrintQueries [][]string
	var patchedRoutes []map[string]any
	var patchedDNS []map[string]any
	var createdRoutes []map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ops = append(ops, r.Method+" "+r.URL.Path)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/route/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{
				// Host route without /32 and with %bridge interface scope — must match 10.8.0.5/32 without flap!
				{".id": "*1", "dst-address": "10.8.0.5", "gateway": "172.18.0.99%bridge", "comment": "awg-ctl:awg0", "routing-table": "main", "disabled": "false"},
				// Route with wrong gateway + disabled — must be PATCHed in-place instead of DELETE+PUT!
				{".id": "*2", "dst-address": "10.20.0.0/24", "gateway": "192.168.253.2", "comment": "awg-ctl:awg0", "disabled": "true"},
				// Stale route — must be DELETEd
				{".id": "*3", "dst-address": "10.99.0.0/16", "gateway": "172.18.0.99", "comment": "awg-ctl:awg0"},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/ip/route/*2":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			patchedRoutes = append(patchedRoutes, body)
			rw.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/rest/ip/route/*3":
			rw.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/route":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdRoutes = append(createdRoutes, body)
			rw.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/dns/static/print":
			var body struct {
				Proplist []string `json:".proplist"`
				Query    []string `json:".query"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			dnsPrintQueries = append(dnsPrintQueries, body.Query)
			_ = json.NewEncoder(rw).Encode([]map[string]any{
				// Existing domain with outdated address-list — must be PATCHed!
				{".id": "*10", "name": "example.com", "type": "FWD", "forward-to": "172.18.0.99", "address-list": "OldList", "match-subdomain": "true", "comment": "awg-ctl", "disabled": "false"},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/ip/dns/static/*10":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			patchedDNS = append(patchedDNS, body)
			rw.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected REST call: %s %s", r.Method, r.URL.Path)
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	ros := NewROSClient(tmp, NewRingLogger(30))
	ros.SetAutoGatewayFn(func() string { return "172.18.0.99" })
	ros.Configure(AppSettings{
		ROSURL:         srv.URL,
		ROSUser:        "awg",
		ROSPass:        "secret",
		ROSAddressList: "NewList",
		ROSSyncRoutes:  true,
		ROSSyncDomains: true,
	})
	if err := ros.SaveDomains("EXAMPLE.COM.\n"); err != nil {
		t.Fatal(err)
	}

	// Unnormalized CIDR 10.20.0.5/24 + default 0.0.0.0/0 (must be ignored by guard)
	nRoutes, err := ros.syncAllowedRoutes(map[string][]string{"awg0": {"0.0.0.0/0", "10.8.0.5/32", "10.20.0.5/24", "10.30.0.0/24"}})
	if err != nil {
		t.Fatalf("syncAllowedRoutes error: %v", err)
	}
	if nRoutes != 3 {
		t.Fatalf("expected 3 non-default routes synced, got %d", nRoutes)
	}
	if len(patchedRoutes) != 1 || patchedRoutes[0]["gateway"] != "172.18.0.99" || patchedRoutes[0]["disabled"] != "false" {
		t.Fatalf("expected PATCH on *2 route, got %+v", patchedRoutes)
	}
	if len(createdRoutes) != 1 || createdRoutes[0]["dst-address"] != "10.30.0.0/24" {
		t.Fatalf("expected PUT only for 10.30.0.0/24, got %+v", createdRoutes)
	}

	domains, err := ros.ReadDomains()
	if err != nil {
		t.Fatal(err)
	}
	nDom, err := ros.syncDNSDomains(domains)
	if err != nil {
		t.Fatalf("syncDNSDomains error: %v", err)
	}
	if nDom != 1 || len(patchedDNS) != 1 || patchedDNS[0]["address-list"] != "NewList" || patchedDNS[0]["match-subdomain"] != "true" {
		t.Fatalf("expected DNS PATCH updating address-list to NewList, got %+v (nDom=%d)", patchedDNS, nDom)
	}
	if len(dnsPrintQueries) != 1 || len(dnsPrintQueries[0]) != 1 || dnsPrintQueries[0][0] != "comment=awg-ctl" {
		t.Fatalf("expected .query comment=awg-ctl on dns print, got %+v", dnsPrintQueries)
	}
}

func TestROSHTMLErrorFailFastBackoffAndLogDedup(t *testing.T) {
	var routeHits atomic.Int32
	var dnsHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ip/dns") {
			dnsHits.Add(1)
		} else {
			routeHits.Add(1)
		}
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("<!doctype html>\n<html lang=en>\n<title>Error 403 : Forbidden</title>\n<h1>Error 403 : Forbidden</h1>"))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	logger := NewRingLogger(50)
	ros := NewROSClient(tmp, logger)
	ros.Configure(AppSettings{
		ROSURL:         srv.URL,
		ROSUser:        "admin",
		ROSPass:        "pass",
		ROSSyncRoutes:  true,
		ROSSyncDomains: true,
	})
	_ = ros.SaveDomains("example.com\n")
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "", false, false, logger)

	err := ros.SyncAll(mgr)
	if err == nil {
		t.Fatalf("expected 403 error")
	}
	// Route print + fallback GET may run on 403 (Wait: 403 does NOT fallback to GET, only 400/404/405/501!),
	// AND fail-fast must prevent calling /ip/dns/static at all!
	if routeHits.Load() != 1 || dnsHits.Load() != 0 {
		t.Fatalf("expected 1 route hit and 0 dns hits on 403 fail-fast, got route=%d dns=%d", routeHits.Load(), dnsHits.Load())
	}

	st := ros.Status()
	if strings.Contains(st.LastError, "<") || !strings.Contains(st.LastError, "HTTP 403") || !strings.Contains(st.LastError, "rest-plain=yes") {
		t.Fatalf("expected sanitized HTML + rest-plain hint, got: %q", st.LastError)
	}
	if st.ConsecFailures != 1 || st.NextRetryAt == "" {
		t.Fatalf("expected backoff scheduled, got %+v", st)
	}

	// Periodic tick immediately after must be skipped due to backoff (zero new HTTP hits or extra log lines!)
	beforeLines := len(logger.Lines())
	_ = ros.SyncPeriodic(mgr)
	_ = ros.SyncPeriodic(mgr)
	if routeHits.Load() != 1 || len(logger.Lines()) != beforeLines {
		t.Fatalf("expected backoff skip with zero extra hits/logs, got hits=%d logs=%d (was %d)", routeHits.Load(), len(logger.Lines()), beforeLines)
	}
}

func TestROSTestConnectionCleanupAndConcurrentSync(t *testing.T) {
	var routeStore = map[string]map[string]any{
		"*1": {".id": "*1", "dst-address": "10.10.0.0/16", "gateway": "172.18.0.99", "comment": "awg-ctl:awg0"},
		"*2": {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "192.168.1.1", "comment": "default"},
	}
	var dnsStore = map[string]map[string]any{
		"*5": {".id": "*5", "name": "example.com", "type": "FWD", "forward-to": "172.18.0.99", "address-list": "AmneziaWGRoS", "match-subdomain": "true", "comment": "awg-ctl"},
	}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/resource":
			_ = json.NewEncoder(rw).Encode(map[string]any{"board-name": "RB5009UG+S+", "version": "7.22.1"})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/identity":
			_ = json.NewEncoder(rw).Encode(map[string]any{"name": "HomeCore"})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/route/print":
			var list []map[string]any
			for _, v := range routeStore {
				list = append(list, v)
			}
			_ = json.NewEncoder(rw).Encode(list)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/rest/ip/route/"):
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/route/")
			delete(routeStore, id)
			rw.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/dns/static/print":
			var list []map[string]any
			for _, v := range dnsStore {
				list = append(list, v)
			}
			_ = json.NewEncoder(rw).Encode(list)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/rest/ip/dns/static/"):
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/dns/static/")
			delete(dnsStore, id)
			rw.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	logger := NewRingLogger(50)
	stStore, _ := NewSettingsStore(tmp)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "", false, false, logger)
	ros := NewROSClient(tmp, logger)
	ros.SetAutoGatewayFn(func() string { return "172.18.0.99" })

	// Persist legacy overridden 192.168.253.2 in settings, then verify /api/ros/test with empty ros_container_ip overrides it cleanly!
	cur := stStore.Get()
	cur.ROSURL = srv.URL
	cur.ROSUser = "admin"
	cur.ROSPass = "pass"
	cur.ROSContainerIP = "192.168.253.2"
	_, _ = stStore.Update(SettingsUpdate{AppSettings: cur})
	ros.Configure(stStore.Get())

	w := NewWebServer(":0", mgr, nil, ros, stStore, nil, nil, logger)

	body := bytes.NewBufferString(`{"ros_url":"` + srv.URL + `","ros_user":"admin","ros_container_ip":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ros/test", body)
	rec := httptest.NewRecorder()
	w.handleROSTest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res ROSTestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Identity != "HomeCore" || res.Version != "7.22.1" || res.GatewayIP != "172.18.0.99" {
		t.Fatalf("unexpected test response: %+v", res)
	}

	// Concurrent SyncAll under -race
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ros.SyncAll(mgr)
		}()
	}
	wg.Wait()

	// Cleanup endpoint should remove remaining managed entries if any while leaving non-managed *2 route intact.
	mu.Lock()
	routeStore["*9"] = map[string]any{".id": "*9", "dst-address": "10.50.0.0/16", "gateway": "172.18.0.99", "comment": "awg-ctl:awg1"}
	mu.Unlock()

	rec2 := httptest.NewRecorder()
	w.handleROSCleanup(rec2, httptest.NewRequest(http.MethodPost, "/api/ros/cleanup", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("cleanup failed: %d %s", rec2.Code, rec2.Body.String())
	}
	mu.Lock()
	_, unmanagedStillHere := routeStore["*2"]
	_, managedGone := routeStore["*9"]
	mu.Unlock()
	if !unmanagedStillHere || managedGone {
		t.Fatalf("expected *2 preserved and *9 deleted, got %+v", routeStore)
	}
}
