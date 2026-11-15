package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSettingsROSModeMigrationAndNormalization(t *testing.T) {
	// Legacy settings.json with ros_url and no ros_mode must migrate to "manual".
	tmp1 := t.TempDir()
	legacyJSON := `{"default_policy":"proxy","ros_url":"https://192.168.88.1","ros_user":"admin"}`
	if err := writeTestFile(filepath.Join(tmp1, "settings.json"), legacyJSON); err != nil {
		t.Fatal(err)
	}
	st1, err := NewSettingsStore(tmp1)
	if err != nil {
		t.Fatal(err)
	}
	if got := st1.Get().ROSMode; got != ROSModeManual {
		t.Fatalf("expected legacy migration to manual, got %q", got)
	}

	// Brand new install with no settings.json must default to "gateway".
	tmp2 := t.TempDir()
	st2, err := NewSettingsStore(tmp2)
	if err != nil {
		t.Fatal(err)
	}
	if got := st2.Get().ROSMode; got != ROSModeGateway {
		t.Fatalf("expected fresh install default gateway, got %q", got)
	}
	if !st2.Get().ROSUseBinaryAPI || st2.Get().ROSDynamicTimeout != "12:00:00" {
		t.Fatalf("unexpected defaults: %+v", st2.Get())
	}

	// Duration parser & normalizer checks
	if got := normalizeROSDynamicTimeout("1d"); got != "1d" {
		t.Fatalf("expected 1d, got %q", got)
	}
	if got := normalizeROSDynamicTimeout("1d12:00:00"); got != "1d 12:00:00" {
		t.Fatalf("expected 1d 12:00:00, got %q", got)
	}
	if got := normalizeROSDynamicTimeout("invalid"); got != "12:00:00" {
		t.Fatalf("expected fallback 12:00:00, got %q", got)
	}
}

func TestPolicyComputeRouterOSPrefixesAndDNSFiltering(t *testing.T) {
	tmp := t.TempDir()
	logger := NewRingLogger(20)
	stStore, _ := NewSettingsStore(tmp)
	geo := NewGeoStore(tmp, logger)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "", false, false, logger)
	pol := NewPolicyEngine(tmp, stStore, geo, mgr, logger)

	// Configure DefaultPolicy = proxy so we verify unmatched "default" domains are NOT synced.
	s := stStore.Get()
	s.DefaultPolicy = "proxy"
	_, _ = stStore.Update(SettingsUpdate{AppSettings: s})

	rules := strings.Join([]string{
		"DIRECT,cidr:1.1.1.1/32",
		"DIRECT,cidr:8.8.8.0/24",
		"PROXY,domain:gemini.google.com",
		"PROXY,cidr:1.1.1.0/24",
		"PROXY,cidr:0.0.0.0/0",      // must be ignored
		"PROXY,cidr:127.0.0.0/8",    // must be ignored (loopback)
		"PROXY,cidr:8.8.8.0/24",     // overridden by earlier DIRECT
		"PROXY,cidr:172.18.0.0/24",  // contains container/router excluded IPs
		"PROXY,cidr:203.0.113.0/24", // clean
	}, "\n")
	if _, err := pol.SaveRules(rules); err != nil {
		t.Fatal(err)
	}

	exROS := netip.MustParseAddr("172.18.0.1")
	exCont := netip.MustParseAddr("172.18.0.99")

	plan := pol.ComputeRouterOSPrefixes(100, exROS, exCont)
	for _, pfx := range plan.Prefixes {
		if pfx.Bits() == 0 {
			t.Fatalf("default route leaked into plan")
		}
		if pfx.Contains(netip.MustParseAddr("1.1.1.1")) {
			t.Fatalf("DIRECT 1.1.1.1/32 leaked inside prefix %s", pfx)
		}
		if pfx.Overlaps(netip.MustParsePrefix("8.8.8.0/24")) {
			t.Fatalf("DIRECT 8.8.8.0/24 leaked: %s", pfx)
		}
		if pfx.Contains(exROS) || pfx.Contains(exCont) {
			t.Fatalf("excluded host IP leaked inside prefix %s", pfx)
		}
	}
	// Verify 1.1.1.0/32 and 1.1.1.2/31.. remained from carving 1.1.1.1 out of 1.1.1.0/24.
	covered1112 := false
	covered203 := false
	for _, pfx := range plan.Prefixes {
		if pfx.Contains(netip.MustParseAddr("1.1.1.2")) {
			covered1112 = true
		}
		if pfx == netip.MustParsePrefix("203.0.113.0/24") {
			covered203 = true
		}
	}
	if !covered1112 || !covered203 {
		t.Fatalf("expected carved 1.1.1.2 and clean 203.0.113.0/24, got %+v", plan.Prefixes)
	}

	// Verify cap limit enforcement
	smallPlan := pol.ComputeRouterOSPrefixes(2, exROS, exCont)
	if len(smallPlan.Prefixes) != 2 || smallPlan.DroppedByLimit == 0 {
		t.Fatalf("expected limit=2 with DroppedByLimit>0, got len=%d dropped=%d", len(smallPlan.Prefixes), smallPlan.DroppedByLimit)
	}

	// Verify DNS evaluation: unmatched domain must NOT sync even when default_policy=proxy
	if ok, _, _ := pol.EvaluateForRouterOS("unlisted.example.org", []netip.Addr{netip.MustParseAddr("93.184.216.34")}); ok {
		t.Fatalf("expected default-policy unmatched domain NOT to push to RouterOS")
	}
	// Explicit PROXY domain pushing skips DIRECT CIDR + excluded IPs while keeping valid ones
	ok, rule, kept := pol.EvaluateForRouterOS(
		"gemini.google.com",
		[]netip.Addr{
			netip.MustParseAddr("8.8.8.8"),      // covered by DIRECT 8.8.8.0/24
			netip.MustParseAddr("172.18.0.99"),  // excluded container IP
			netip.MustParseAddr("142.250.74.4"), // allowed
		},
		exROS, exCont,
	)
	if !ok || rule != "domain:gemini.google.com" || len(kept) != 1 || kept[0].String() != "142.250.74.4" {
		t.Fatalf("unexpected EvaluateForRouterOS result: ok=%v rule=%q kept=%v", ok, rule, kept)
	}
}

// --- Mock RouterOS Binary API Server ---

type mockBinAddrEntry struct {
	ID       string
	List     string
	Address  string
	Comment  string
	Timeout  string
	Disabled string
}

type mockROSBinServer struct {
	ln           net.Listener
	user         string
	pass         string
	requireChall bool

	mu         sync.Mutex
	addrs      map[string]mockBinAddrEntry
	nextID     int
	addCalls   int
	setCalls   int
	delCalls   int
	printCalls int
}

func startMockROSBinServer(t *testing.T, user, pass string, requireChallenge bool) *mockROSBinServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockROSBinServer{
		ln:           ln,
		user:         user,
		pass:         pass,
		requireChall: requireChallenge,
		addrs:        make(map[string]mockBinAddrEntry),
		nextID:       1,
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *mockROSBinServer) Port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

func (s *mockROSBinServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func readClientSentence(r *bufio.Reader) (string, map[string]string, error) {
	var cmd string
	attrs := make(map[string]string)
	for {
		w, err := readAPIWord(r)
		if err != nil {
			return "", nil, err
		}
		if w == "" {
			if cmd == "" {
				continue
			}
			return cmd, attrs, nil
		}
		if cmd == "" {
			cmd = w
			continue
		}
		if strings.HasPrefix(w, "=") {
			kv := w[1:]
			if eq := strings.IndexByte(kv, '='); eq >= 0 {
				attrs[kv[:eq]] = kv[eq+1:]
			} else {
				attrs[kv] = ""
			}
		} else if strings.HasPrefix(w, "?") {
			kv := w[1:]
			if eq := strings.IndexByte(kv, '='); eq >= 0 {
				attrs["?"+kv[:eq]] = kv[eq+1:]
			}
		}
	}
}

func (s *mockROSBinServer) handleConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := false
	challenge := "0123456789abcdef0123456789abcdef"

	for {
		cmd, attrs, err := readClientSentence(r)
		if err != nil {
			return
		}
		switch cmd {
		case "/login":
			if s.requireChall && attrs["response"] == "" {
				_ = writeAPISentence(c, []string{"!done", "=ret=" + challenge})
				continue
			}
			if attrs["name"] != s.user {
				_ = writeAPISentence(c, []string{"!trap", "=category=0", "=message=invalid user name or password"})
				_ = writeAPISentence(c, []string{"!done"})
				continue
			}
			if s.requireChall {
				chB, _ := hex.DecodeString(challenge)
				sum := md5.Sum(append(append([]byte{0}, s.pass...), chB...))
				want := "00" + hex.EncodeToString(sum[:])
				if attrs["response"] != want {
					_ = writeAPISentence(c, []string{"!trap", "=message=invalid response"})
					_ = writeAPISentence(c, []string{"!done"})
					continue
				}
			} else if attrs["password"] != s.pass {
				_ = writeAPISentence(c, []string{"!trap", "=message=invalid password"})
				_ = writeAPISentence(c, []string{"!done"})
				continue
			}
			authed = true
			_ = writeAPISentence(c, []string{"!done"})

		case "/system/identity/print":
			if !authed {
				return
			}
			_ = writeAPISentence(c, []string{"!re", "=name=MockBinROS"})
			_ = writeAPISentence(c, []string{"!done"})

		case "/ip/firewall/address-list/print":
			if !authed {
				return
			}
			s.mu.Lock()
			s.printCalls++
			wantList := attrs["?list"]
			wantAddr := attrs["?address"]
			for _, e := range s.addrs {
				if wantList != "" && e.List != wantList {
					continue
				}
				if wantAddr != "" && e.Address != wantAddr {
					continue
				}
				_ = writeAPISentence(c, []string{
					"!re",
					"=.id=" + e.ID,
					"=list=" + e.List,
					"=address=" + e.Address,
					"=comment=" + e.Comment,
					"=timeout=" + e.Timeout,
					"=dynamic=" + map[bool]string{true: "true", false: "false"}[e.Timeout != ""],
					"=disabled=" + e.Disabled,
				})
			}
			s.mu.Unlock()
			_ = writeAPISentence(c, []string{"!done"})

		case "/ip/firewall/address-list/add":
			s.mu.Lock()
			s.addCalls++
			addrKey := normalizeAddrListKey(attrs["address"])
			dup := false
			for _, e := range s.addrs {
				if e.List == attrs["list"] && e.Address == addrKey {
					dup = true
					break
				}
			}
			if dup {
				s.mu.Unlock()
				_ = writeAPISentence(c, []string{"!trap", "=message=failure: already have such entry"})
				_ = writeAPISentence(c, []string{"!done"})
				continue
			}
			id := "*" + strconv.Itoa(s.nextID)
			s.nextID++
			s.addrs[id] = mockBinAddrEntry{
				ID:       id,
				List:     attrs["list"],
				Address:  addrKey,
				Comment:  attrs["comment"],
				Timeout:  attrs["timeout"],
				Disabled: "false",
			}
			s.mu.Unlock()
			_ = writeAPISentence(c, []string{"!done", "=ret=" + id})

		case "/ip/firewall/address-list/set":
			s.mu.Lock()
			s.setCalls++
			if e, ok := s.addrs[attrs[".id"]]; ok {
				if cmt, has := attrs["comment"]; has {
					e.Comment = cmt
				}
				if to, has := attrs["timeout"]; has {
					e.Timeout = to
				}
				if dis, has := attrs["disabled"]; has {
					e.Disabled = dis
				}
				s.addrs[attrs[".id"]] = e
			}
			s.mu.Unlock()
			_ = writeAPISentence(c, []string{"!done"})

		case "/ip/firewall/address-list/remove":
			s.mu.Lock()
			s.delCalls++
			delete(s.addrs, attrs[".id"])
			s.mu.Unlock()
			_ = writeAPISentence(c, []string{"!done"})

		default:
			_ = writeAPISentence(c, []string{"!trap", "=message=unknown command " + cmd})
			_ = writeAPISentence(c, []string{"!done"})
		}
	}
}

func TestBinaryAPIClientPlainAndLegacyChallengeLogin(t *testing.T) {
	srvPlain := startMockROSBinServer(t, "admin", "secret", false)
	cli := NewROSBinClient()
	defer cli.Close()

	cfg := rosBinConfig{
		Addr: "127.0.0.1:" + strconv.Itoa(srvPlain.Port()),
		User: "admin",
		Pass: "secret",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := cli.Exec(ctx, cfg, "/system/identity/print")
	if err != nil || len(rows) != 1 || rows[0]["name"] != "MockBinROS" {
		t.Fatalf("plaintext Binary API failed: rows=%v err=%v", rows, err)
	}

	// Also verify legacy challenge-response login
	srvChall := startMockROSBinServer(t, "admin", "secret", true)
	cfgChall := rosBinConfig{
		Addr: "127.0.0.1:" + strconv.Itoa(srvChall.Port()),
		User: "admin",
		Pass: "secret",
	}
	rows2, err := cli.Exec(ctx, cfgChall, "/system/identity/print")
	if err != nil || len(rows2) != 1 || rows2[0]["name"] != "MockBinROS" {
		t.Fatalf("legacy MD5 Binary API failed: rows=%v err=%v", rows2, err)
	}

	// Verify already-have-such-entry trap detection
	_, _ = cli.Exec(ctx, cfg, "/ip/firewall/address-list/add", "=list=T", "=address=1.2.3.4", "=comment=x")
	_, err = cli.Exec(ctx, cfg, "/ip/firewall/address-list/add", "=list=T", "=address=1.2.3.4", "=comment=x")
	if !isROSAlreadyExistsErr(err) {
		t.Fatalf("expected isROSAlreadyExistsErr, got %v", err)
	}
}

func TestAddressListModeSyncLiveDNSRebootRecoveryAndManualPreserve(t *testing.T) {
	binSrv := startMockROSBinServer(t, "admin", "pass", false)
	binSrv.mu.Lock()
	binSrv.addrs["*900"] = mockBinAddrEntry{
		ID:       "*900",
		List:     "AmneziaWGRoS",
		Address:  "9.9.9.9",
		Comment:  "user manual entry",
		Disabled: "false",
	}
	binSrv.addrs["*901"] = mockBinAddrEntry{
		ID:       "*901",
		List:     "AmneziaWGRoS",
		Address:  "4.4.4.4",
		Comment:  "awg-ctl:dyn:old.example",
		Timeout:  "01:00:00",
		Disabled: "false",
	}
	binSrv.addrs["*902"] = mockBinAddrEntry{
		ID:       "*902",
		List:     "OTHER_LIST",
		Address:  "192.168.1.0/24",
		Comment:  "lan",
		Disabled: "false",
	}
	binSrv.mu.Unlock()

	httpSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.NotFound(rw, r)
	}))
	defer httpSrv.Close()

	tmp := t.TempDir()
	logger := NewRingLogger(50)
	stStore, _ := NewSettingsStore(tmp)
	geo := NewGeoStore(tmp, logger)
	mgr := NewTunnelManager(tmp, filepath.Join(tmp, "run"), "", false, false, logger)
	pol := NewPolicyEngine(tmp, stStore, geo, mgr, logger)

	_, _ = pol.SaveRules("PROXY,cidr:203.0.113.0/24\nPROXY,domain:youtube.com\n")

	s := stStore.Get()
	s.ROSURL = httpSrv.URL
	s.ROSUser = "admin"
	s.ROSPass = "pass"
	s.ROSMode = ROSModeAddressList
	s.ROSUseBinaryAPI = true
	s.ROSAPIPort = binSrv.Port()
	s.ROSAddressList = "AmneziaWGRoS"
	s.ROSDynamicTimeout = "12:00:00"
	s.ROSSyncPolicyCIDRs = true
	_, _ = stStore.Update(SettingsUpdate{AppSettings: s})

	ros := NewROSClient(tmp, logger)
	ros.SetAutoGatewayFn(func() string { return "172.18.0.99" })
	ros.SetManager(mgr)
	ros.SetPolicy(pol)
	ros.Configure(stStore.Get())
	defer ros.Close()

	// 1. Live DNS push for youtube.com
	ros.PushDynamicFromDNS("www.youtube.com", []netip.Addr{netip.MustParseAddr("142.250.74.14")})
	addsAfterPush := binSrv.addCalls
	if addsAfterPush != 1 {
		t.Fatalf("expected 1 live Binary API add, got %d", addsAfterPush)
	}
	// Repeat DNS lookup immediately -> zero ROS writes (cache hit)
	ros.PushDynamicFromDNS("www.youtube.com", []netip.Addr{netip.MustParseAddr("142.250.74.14")})
	if binSrv.addCalls != addsAfterPush {
		t.Fatalf("expected cached DNS IP not to rewrite ROS, addCalls=%d", binSrv.addCalls)
	}

	// 2. Full SyncAll reconciles static CIDR, keeps live dynamic IP, removes stale awg-ctl *901, preserves *900 and *902
	if err := ros.SyncAll(mgr); err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}
	binSrv.mu.Lock()
	_, keptManual := binSrv.addrs["*900"]
	_, keptOtherList := binSrv.addrs["*902"]
	_, deletedStale := binSrv.addrs["*901"]
	var foundStatic, foundDyn bool
	for _, e := range binSrv.addrs {
		if e.Address == "203.0.113.0/24" && e.Comment == rosStaticComment && e.Timeout != "" {
			foundStatic = true
		}
		if e.Address == "142.250.74.14" && e.Comment == "awg-ctl:dyn:www.youtube.com" {
			foundDyn = true
		}
	}
	binSrv.mu.Unlock()
	if !keptManual || !keptOtherList || deletedStale || !foundStatic || !foundDyn {
		t.Fatalf("unexpected address-list state: manual=%v other=%v stalePresent=%v static=%v dyn=%v",
			keptManual, keptOtherList, deletedStale, foundStatic, foundDyn)
	}

	// 3. RouterOS reboot simulation: wipe RAM entries on ROS, run SyncAll -> rehydrates from DynIPStore + Policy!
	binSrv.mu.Lock()
	binSrv.addrs = make(map[string]mockBinAddrEntry)
	binSrv.mu.Unlock()

	if err := ros.SyncAll(mgr); err != nil {
		t.Fatalf("SyncAll after reboot failed: %v", err)
	}
	binSrv.mu.Lock()
	rehydrated := len(binSrv.addrs)
	binSrv.mu.Unlock()
	if rehydrated != 2 {
		t.Fatalf("expected 2 entries rehydrated after ROS reboot, got %d", rehydrated)
	}

	// 4. Verify REST fallback works automatically when Binary API port is closed!
	var restAdds int
	restSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/firewall/address-list/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/firewall/address-list":
			restAdds++
			_ = json.NewEncoder(rw).Encode(map[string]any{".id": "*55"})
		default:
			http.NotFound(rw, r)
		}
	}))
	defer restSrv.Close()

	s = stStore.Get()
	s.ROSURL = restSrv.URL
	s.ROSAPIPort = 1 // closed port -> triggers REST fallback
	_, _ = stStore.Update(SettingsUpdate{AppSettings: s})
	ros.Configure(stStore.Get())

	if err := ros.SyncAll(mgr); err != nil {
		t.Fatalf("REST fallback SyncAll failed: %v", err)
	}
	if restAdds != 2 || ros.Status().Transport != "rest" {
		t.Fatalf("expected 2 REST adds and transport=rest, got adds=%d transport=%q", restAdds, ros.Status().Transport)
	}
}

func TestBGPWireAndLiveSessionAnnounceWithdraw(t *testing.T) {
	// Start mock BGP peer on 127.0.0.1:<port>
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerPort := ln.Addr().(*net.TCPAddr).Port

	type peerEvent struct {
		msgType  byte
		withdrawn []netip.Prefix
		nlri      []netip.Prefix
	}
	eventsCh := make(chan peerEvent, 16)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read speaker OPEN
		mType, payload, err := readBGPMessage(conn, 5*time.Second)
		if err != nil || mType != bgpMsgOpen {
			return
		}
		openPkt, err := parseBGPOpen(payload)
		if err != nil {
			return
		}
		_ = openPkt

		// Send peer OPEN (AS 65510, supports Cap 65 AS4) + KEEPALIVE
		_ = writeAll(conn, buildBGPOpen(65510, 90, netip.MustParseAddr("172.18.0.1")))
		mType, _, err = readBGPMessage(conn, 5*time.Second)
		if err != nil || mType != bgpMsgKeepalive {
			return
		}
		_ = writeAll(conn, buildBGPKeepalive())

		for {
			t, p, rErr := readBGPMessage(conn, 5*time.Second)
			if rErr != nil {
				return
			}
			ev := peerEvent{msgType: t}
			if t == bgpMsgUpdate && len(p) >= 4 {
				wLen := int(binary.BigEndian.Uint16(p[0:2]))
				if 2+wLen+2 <= len(p) {
					ev.withdrawn = decodeBGPPfxs(p[2 : 2+wLen])
					paLen := int(binary.BigEndian.Uint16(p[2+wLen : 4+wLen]))
					if 4+wLen+paLen <= len(p) {
						ev.nlri = decodeBGPPfxs(p[4+wLen+paLen:])
					}
				}
			}
			eventsCh <- ev
		}
	}()

	speaker := NewROSBGPSpeaker(NewRingLogger(20))
	defer speaker.Close()

	speaker.SetDesiredPrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("142.250.74.14/32"),
	})
	speaker.Configure(ROSBGPConfig{
		Enabled:  true,
		PeerIP:   "127.0.0.1",
		PeerPort: peerPort,
		LocalAS:  65511,
		RemoteAS: 65510,
		NextHop:  netip.MustParseAddr("172.18.0.99"),
	})

	// Wait for initial ANNOUNCE UPDATE
	select {
	case ev := <-eventsCh:
		if ev.msgType != bgpMsgUpdate || len(ev.nlri) != 2 {
			t.Fatalf("expected UPDATE with 2 NLRI, got %+v", ev)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for BGP initial UPDATE; status=%+v", speaker.Status())
	}

	if st := speaker.Status(); st.State != "established" || st.AnnouncedRoutes != 2 {
		t.Fatalf("expected established with 2 routes, got %+v", st)
	}

	// Withdraw 142.250.74.14/32 and verify incremental withdrawal UPDATE
	speaker.SetDesiredPrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	})
	select {
	case ev := <-eventsCh:
		if ev.msgType != bgpMsgUpdate || len(ev.withdrawn) != 1 || ev.withdrawn[0] != netip.MustParsePrefix("142.250.74.14/32") {
			t.Fatalf("expected withdrawal of 142.250.74.14/32, got %+v", ev)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for BGP withdraw UPDATE")
	}

	// Verify UPDATE chunking splits 1500 prefixes under bgpMaxMsgLen
	var many []netip.Prefix
	for i := 0; i < 1500; i++ {
		a := byte(10 + (i >> 8))
		b := byte(i & 0xFF)
		many = append(many, netip.MustParsePrefix("100."+strconv.Itoa(int(a))+"."+strconv.Itoa(int(b))+".1/32"))
	}
	frames := buildBGPUpdateChunks(many, nil, 65511, netip.MustParseAddr("172.18.0.99"), true, false)
	if len(frames) < 2 {
		t.Fatalf("expected multiple chunked BGP UPDATE frames for 1500 prefixes, got %d", len(frames))
	}
	for _, f := range frames {
		if len(f) > bgpMaxMsgLen {
			t.Fatalf("BGP frame exceeded 4096 bytes: %d", len(f))
		}
	}
}

func decodeBGPPfxs(b []byte) []netip.Prefix {
	var out []netip.Prefix
	for len(b) > 0 {
		bits := int(b[0])
		nbytes := (bits + 7) / 8
		if 1+nbytes > len(b) {
			break
		}
		var a4 [4]byte
		copy(a4[:], b[1:1+nbytes])
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(a4), bits))
		b = b[1+nbytes:]
	}
	return out
}

func TestROSProvisionAddressListAndBGP(t *testing.T) {
	var mu sync.Mutex
	ifaceLists := map[string]bool{}
	lanMembers := []map[string]any{{"disabled": "false", "list": "LAN", "interface": "bridge"}}
	tables := map[string]map[string]any{}
	routes := map[string]map[string]any{}
	filters := map[string]map[string]any{
		"*1": {".id": "*1", "action": "fasttrack-connection", "disabled": "false"},
	}
	mangles := []map[string]any{}
	bgpFilters := map[string]map[string]any{}
	bgpConns := map[string]map[string]any{}
	nextID := 10

	allocID := func() string {
		nextID++
		return "*" + strconv.Itoa(nextID)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body map[string]any
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &body)
			}
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/interface/list/member/print":
			_ = json.NewEncoder(rw).Encode(lanMembers)
		case r.Method == http.MethodPost && r.URL.Path == "/rest/interface/list/print":
			var out []map[string]any
			for k := range ifaceLists {
				out = append(out, map[string]any{".id": k, "name": k})
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/interface/list":
			ifaceLists[strField(body, "name")] = true
			rw.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/routing/table/print":
			var out []map[string]any
			for _, v := range tables {
				out = append(out, v)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/routing/table":
			id := allocID()
			body[".id"] = id
			tables[id] = body
			rw.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/route/print":
			var out []map[string]any
			for _, v := range routes {
				out = append(out, v)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/route":
			id := allocID()
			body[".id"] = id
			routes[id] = body
			rw.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/firewall/filter/print":
			var out []map[string]any
			for _, v := range filters {
				out = append(out, v)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/rest/ip/firewall/filter/"):
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/firewall/filter/")
			if cur, ok := filters[id]; ok {
				for k, v := range body {
					cur[k] = v
				}
			}
			rw.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/firewall/mangle/print":
			_ = json.NewEncoder(rw).Encode(mangles)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/ip/firewall/mangle":
			id := allocID()
			body[".id"] = id
			mangles = append(mangles, body)
			rw.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/firewall/address-list/print":
			_ = json.NewEncoder(rw).Encode([]map[string]any{})

		case r.Method == http.MethodPost && r.URL.Path == "/rest/routing/filter/rule/print":
			var out []map[string]any
			for _, v := range bgpFilters {
				out = append(out, v)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/routing/filter/rule":
			id := allocID()
			body[".id"] = id
			bgpFilters[id] = body
			rw.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPost && r.URL.Path == "/rest/routing/bgp/connection/print":
			var out []map[string]any
			for _, v := range bgpConns {
				out = append(out, v)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/rest/routing/bgp/connection":
			id := allocID()
			body[".id"] = id
			bgpConns[id] = body
			rw.WriteHeader(http.StatusCreated)

		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	logger := NewRingLogger(50)
	ros := NewROSClient(tmp, logger)
	ros.SetAutoGatewayFn(func() string { return "172.18.0.99" })

	s := AppSettings{
		ROSURL:          srv.URL,
		ROSUser:         "admin",
		ROSPass:         "pass",
		ROSMode:         ROSModeAddressList,
		ROSUseBinaryAPI: false,
		ROSAddressList:  "AmneziaWGRoS",
		ROSRouteTable:   "AmneziaWGRoS",
		ROSBGPLocalAS:   65511,
		ROSBGPRemoteAS:  65510,
		ROSBGPRouteTable: "main",
	}
	ros.Configure(s)
	defer ros.Close()

	// 1. Before provisioning: InspectSchema must report NOT OK
	before := ros.InspectSchema(s)
	if before.OK {
		t.Fatalf("expected InspectSchema not OK before provision, got %+v", before)
	}

	// 2. Provision address_list schema
	prov := ros.ProvisionSchema(s, ROSProvisionOptions{})
	if !prov.OK || !prov.Report.OK || len(prov.Applied) == 0 {
		t.Fatalf("expected ProvisionSchema OK for address_list, got ok=%v err=%q checks=%+v",
			prov.OK, prov.Error, prov.Report.Checks)
	}

	// Verify AWG_Accept_Container came BEFORE AWG_Mark_AddressList
	mu.Lock()
	var acceptIdx, markIdx = -1, -1
	for i, m := range mangles {
		if strField(m, "comment") == "AWG_Accept_Container" {
			acceptIdx = i
		}
		if strField(m, "comment") == "AWG_Mark_AddressList" {
			markIdx = i
		}
	}
	ftMark := strField(filters["*1"], "connection-mark")
	mu.Unlock()
	if acceptIdx == -1 || markIdx == -1 || acceptIdx > markIdx || ftMark != "no-mark" {
		t.Fatalf("unexpected mangle/fasttrack order: acceptIdx=%d markIdx=%d ftMark=%q", acceptIdx, markIdx, ftMark)
	}

	// 3. Provision BGP schema and confirm checks pass (except live bgp_session when no peer listening)
	sBGP := s
	sBGP.ROSMode = ROSModeBGP
	provBGP := ros.ProvisionSchema(sBGP, ROSProvisionOptions{})
	if !provBGP.OK || len(bgpConns) != 1 || len(bgpFilters) != 1 {
		t.Fatalf("expected BGP provision OK with 1 conn & 1 filter, got ok=%v err=%q conns=%d filters=%d",
			provBGP.OK, provBGP.Error, len(bgpConns), len(bgpFilters))
	}
	checkMap := map[string]bool{}
	for _, ch := range provBGP.Report.Checks {
		checkMap[ch.Key] = ch.OK
	}
	if !checkMap["bgp_filter"] || !checkMap["bgp_conn"] {
		t.Fatalf("expected bgp_filter and bgp_conn OK after provision, got %+v", provBGP.Report.Checks)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
