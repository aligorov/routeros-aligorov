package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if !strings.Contains(injected, "Table = awg") || !strings.Contains(injected, "iif AmneziaWGRoS lookup awg") || !strings.Contains(injected, "blackhole default table awg") {
		t.Fatalf("missing injected auto-route rules:\n%s", injected)
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
