package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultROSContainerIP = "192.168.253.2"
	rosPeriodicDriftEvery = 10 * time.Minute
	rosErrorLogRepeat     = 15 * time.Minute
	rosMaxErrorBodyRunes  = 180
)

var (
	htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	htmlH1Re    = regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)
	htmlTagRe   = regexp.MustCompile(`(?s)<[^>]+>`)
)

// ROSSyncStatus describes the current state of RouterOS integration.
type ROSSyncStatus struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode,omitempty"`
	Transport      string `json:"transport,omitempty"`
	URL            string `json:"url,omitempty"`
	GatewayIP      string `json:"gateway_ip,omitempty"`
	AutoGatewayIP  string `json:"auto_gateway_ip,omitempty"`
	RouteTable     string `json:"route_table,omitempty"`
	AddressList    string `json:"address_list,omitempty"`
	RouterName     string `json:"router_name,omitempty"`
	RouterOSVer    string `json:"routeros_version,omitempty"`
	LastSync       string `json:"last_sync,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	Routes         int    `json:"routes_synced"`
	Domains        int    `json:"domains_synced"`
	StaticSynced   int    `json:"static_cidrs_synced"`
	DynSynced      int    `json:"dynamic_ips_synced"`
	DroppedByLimit int    `json:"dropped_by_limit,omitempty"`
	BGPState       string `json:"bgp_state,omitempty"`
	BGPRoutes      int    `json:"bgp_routes"`
	BGPPeer        string `json:"bgp_peer,omitempty"`
	BGPLastError   string `json:"bgp_last_error,omitempty"`
	BGPNextHop     string `json:"bgp_next_hop,omitempty"`
	ConsecFailures int    `json:"consecutive_failures,omitempty"`
	NextRetryAt    string `json:"next_retry_at,omitempty"`
}

// ROSTestResult is returned by POST /api/ros/test with RouterOS diagnostics.
type ROSTestResult struct {
	OK          bool   `json:"ok"`
	URL         string `json:"url,omitempty"`
	GatewayIP   string `json:"gateway_ip,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Board       string `json:"board,omitempty"`
	Version     string `json:"version,omitempty"`
	Hint        string `json:"hint,omitempty"`
	Error       string `json:"error,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	BinAPIAddr  string `json:"bin_api_addr,omitempty"`
	BinAPIOK    bool   `json:"bin_api_ok,omitempty"`
	BinAPIError string `json:"bin_api_error,omitempty"`
}

type rosConnConfig struct {
	baseURL           string
	urlErr            string
	user              string
	pass              string
	insecure          bool
	gatewayIP         string
	routeTable        string
	forwardDNS        string
	addrList          string
	client            *http.Client
	mode              string
	useBinAPI         bool
	binCfg            rosBinConfig
	dynamicTimeout    string
	syncPolicyCIDRs   bool
	staticPrefixLimit int
	bgpLocalAS        uint32
	bgpRemoteAS       uint32
	bgpPeerIP         string
	bgpRouteTable     string
}

type rosHTTPError struct {
	Method     string
	Path       string
	StatusCode int
	Summary    string
	Hint       string
}

func (e *rosHTTPError) Error() string {
	msg := fmt.Sprintf("REST %s %s -> HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Summary != "" {
		msg += ": " + e.Summary
	}
	return msg
}

func newROSHTTPClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		},
	}
}

// ROSClient manages RouterOS integration (Binary API, REST API, Address-List, BGP, routes/DNS).
type ROSClient struct {
	baseURL           string
	urlErr            string
	user              string
	pass              string
	insecure          bool
	gatewayOverride   string
	routeTable        string
	forwardDNS        string
	addrList          string
	syncRoutes        bool
	syncDomains       bool
	rosMode           string
	useBinAPI         bool
	apiPort           int
	apiTLS            bool
	dynamicTimeout    string
	syncPolicyCIDRs   bool
	staticPrefixLimit int
	bgpLocalAS        uint32
	bgpRemoteAS       uint32
	bgpPeerIP         string
	bgpRouteTable     string
	httpClient        *http.Client
	domainsFile       string
	logger            *RingLogger
	autoGatewayFn     func() string
	noAddrListURL     string

	binSync    *ROSBinClient
	binLive    *ROSBinClient
	bgpSpeaker *ROSBGPSpeaker
	dynStore   *DynIPStore
	policy     *PolicyEngine
	mgr        *TunnelManager
	dns        *DNSForwarder

	resolveSeedFn func(ctx context.Context, domain string) []netip.Addr

	liveBreakerMu    sync.Mutex
	liveBreakerUntil time.Time

	syncMu              sync.Mutex
	mu                  sync.Mutex
	status              ROSSyncStatus
	lastFingerprint     string
	lastFullSyncAt      time.Time
	consecutiveFailures int
	nextRetryAt         time.Time
	lastLoggedErr       string
	lastLoggedErrAt     time.Time
	hadSuccess          bool
}

// NewROSClient builds a RouterOS client initialized from environment variables.
func NewROSClient(cfgDir string, logger *RingLogger) *ROSClient {
	baseURL := normalizeROSBaseURL(os.Getenv("ROS_URL"))
	user := strings.TrimSpace(os.Getenv("ROS_USER"))
	pass := os.Getenv("ROS_PASS")
	insecure := envOr("ROS_TLS_INSECURE", "true") == "true"
	urlErr := validateROSBaseURL(baseURL)

	rawMode := strings.TrimSpace(os.Getenv("ROS_MODE"))
	if rawMode == "" && baseURL != "" {
		rawMode = ROSModeManual
	}
	mode := normalizeROSMode(rawMode)

	useBinAPI := envOr("ROS_USE_BINARY_API", "true") == "true"
	apiTLS := envOr("ROS_API_TLS", "false") == "true"
	apiPort := 8728
	if apiTLS {
		apiPort = 8729
	}

	dynStorePath := ""
	if strings.TrimSpace(cfgDir) != "" {
		dynStorePath = filepath.Join(cfgDir, "ros-dynamic.json")
	}

	c := &ROSClient{
		baseURL:           baseURL,
		urlErr:            urlErr,
		user:              user,
		pass:              pass,
		insecure:          insecure,
		gatewayOverride:   normalizeROSContainerIP(os.Getenv("ROS_CONTAINER_IP")),
		routeTable:        strings.TrimSpace(os.Getenv("ROS_ROUTE_TABLE")),
		forwardDNS:        envOr("ROS_FORWARD_DNS", "AmneziaWGRoS"),
		addrList:          envOr("ROS_ADDRESS_LIST", "AmneziaWGRoS"),
		syncRoutes:        envOr("ROS_SYNC_ROUTES", "on") == "on",
		syncDomains:       envOr("ROS_SYNC_DOMAINS", "on") == "on",
		rosMode:           mode,
		useBinAPI:         useBinAPI,
		apiPort:           apiPort,
		apiTLS:            apiTLS,
		dynamicTimeout:    normalizeROSDynamicTimeout(os.Getenv("ROS_DYNAMIC_TIMEOUT")),
		syncPolicyCIDRs:   envOr("ROS_SYNC_POLICY_CIDRS", "true") == "true",
		staticPrefixLimit: 2500,
		bgpLocalAS:        65511,
		bgpRemoteAS:       65510,
		bgpPeerIP:         normalizeROSContainerIP(os.Getenv("ROS_BGP_PEER_IP")),
		bgpRouteTable:     envOr("ROS_BGP_ROUTE_TABLE", "main"),
		domainsFile:       filepath.Join(cfgDir, "domains.txt"),
		logger:            logger,
		httpClient:        newROSHTTPClient(insecure),
		binSync:           NewROSBinClient(),
		binLive:           NewROSBinClient(),
		bgpSpeaker:        NewROSBGPSpeaker(logger),
		dynStore:          NewDynIPStore(dynStorePath, logger),
	}
	c.refreshStatusLocked()
	return c
}

// SetAutoGatewayFn registers a callback returning the container's live veth IPv4.
func (c *ROSClient) SetAutoGatewayFn(fn func() string) {
	c.mu.Lock()
	c.autoGatewayFn = fn
	c.mu.Unlock()
	c.configureBGPFromState()
}

// SetPolicy attaches PolicyEngine for address_list and bgp rule synchronization.
func (c *ROSClient) SetPolicy(p *PolicyEngine) {
	c.mu.Lock()
	c.policy = p
	c.mu.Unlock()
	c.refreshBGPDesiredPrefixes()
}

// SetManager attaches TunnelManager for WireGuard endpoint exclusion during ROS sync.
func (c *ROSClient) SetManager(m *TunnelManager) {
	c.mu.Lock()
	c.mgr = m
	c.mu.Unlock()
}

// SetDNS attaches DNSForwarder so policy updates can proactively seed domain rules.
func (c *ROSClient) SetDNS(d *DNSForwarder) {
	c.mu.Lock()
	c.dns = d
	c.mu.Unlock()
}

// Close shuts down persistent Binary API sockets, BGP speaker, and flushes dynamic IP store.
func (c *ROSClient) Close() {
	if c == nil {
		return
	}
	if c.bgpSpeaker != nil {
		c.bgpSpeaker.Close()
	}
	if c.binSync != nil {
		c.binSync.Close()
	}
	if c.binLive != nil {
		c.binLive.Close()
	}
	if c.dynStore != nil {
		c.dynStore.Close()
	}
}

// OnPolicyChanged should be invoked after policy rules or Geo databases update.
func (c *ROSClient) OnPolicyChanged() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.lastFingerprint = ""
	mode := c.rosMode
	c.mu.Unlock()

	if mode == ROSModeBGP || mode == ROSModeAddressList {
		go func() {
			_ = c.OnPolicyChangedSync(nil)
		}()
	}
}

// OnPolicyChangedSync backfills recently observed DNS answers, proactively resolves representative
// domains for active PROXY rules, and immediately synchronizes RouterOS state.
func (c *ROSClient) OnPolicyChangedSync(mgr *TunnelManager) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.lastFingerprint = ""
	mode := c.rosMode
	if mgr == nil {
		mgr = c.mgr
	}
	c.mu.Unlock()

	if mode == ROSModeBGP || mode == ROSModeAddressList {
		ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
		c.syncBackfillAndSeedDomains(ctx, mgr)
		cancel()
	}

	if mode == ROSModeBGP {
		c.refreshBGPDesiredPrefixes()
		return nil
	}
	if mode == ROSModeAddressList {
		return c.SyncAll(mgr)
	}
	return nil
}

// Configure applies runtime AppSettings and resets backoff on credential/URL changes.
func (c *ROSClient) Configure(s AppSettings) {
	baseURL := normalizeROSBaseURL(s.ROSURL)
	user := strings.TrimSpace(s.ROSUser)
	urlErr := validateROSBaseURL(baseURL)
	gwOverride := normalizeROSContainerIP(s.ROSContainerIP)
	routeTable := strings.TrimSpace(s.ROSRouteTable)

	rawMode := strings.TrimSpace(s.ROSMode)
	if rawMode == "" && (s.ROSSyncRoutes || s.ROSSyncDomains || baseURL != "") {
		rawMode = ROSModeManual
	}
	mode := normalizeROSMode(rawMode)

	apiPort := s.ROSAPIPort
	if apiPort <= 0 || apiPort > 65535 {
		if s.ROSAPITLS {
			apiPort = 8729
		} else {
			apiPort = 8728
		}
	}
	dynTimeout := normalizeROSDynamicTimeout(s.ROSDynamicTimeout)
	prefixLimit := s.ROSStaticPrefixLimit
	if prefixLimit <= 0 {
		prefixLimit = 2500
	}
	localAS := s.ROSBGPLocalAS
	if localAS == 0 {
		localAS = 65511
	}
	remoteAS := s.ROSBGPRemoteAS
	if remoteAS == 0 {
		remoteAS = 65510
	}
	bgpPeerIP := normalizeROSContainerIP(s.ROSBGPPeerIP)
	bgpTable := strings.TrimSpace(s.ROSBGPRouteTable)
	if bgpTable == "" {
		bgpTable = "main"
	}

	var oldClient *http.Client

	c.mu.Lock()
	connChanged := c.baseURL != baseURL ||
		c.user != user ||
		c.pass != s.ROSPass ||
		c.insecure != s.ROSTLSSkipVerify ||
		c.gatewayOverride != gwOverride ||
		c.routeTable != routeTable ||
		c.addrList != strings.TrimSpace(s.ROSAddressList) ||
		c.syncRoutes != s.ROSSyncRoutes ||
		c.syncDomains != s.ROSSyncDomains ||
		c.rosMode != mode ||
		c.useBinAPI != s.ROSUseBinaryAPI ||
		c.apiPort != apiPort ||
		c.apiTLS != s.ROSAPITLS ||
		c.dynamicTimeout != dynTimeout ||
		c.syncPolicyCIDRs != s.ROSSyncPolicyCIDRs ||
		c.staticPrefixLimit != prefixLimit

	if c.baseURL != baseURL {
		c.noAddrListURL = ""
		c.status.RouterName = ""
		c.status.RouterOSVer = ""
	}
	c.baseURL = baseURL
	c.urlErr = urlErr
	c.user = user
	c.pass = s.ROSPass
	c.gatewayOverride = gwOverride
	c.routeTable = routeTable
	if v := strings.TrimSpace(s.ROSForwardDNS); v != "" {
		c.forwardDNS = v
	}
	if v := strings.TrimSpace(s.ROSAddressList); v != "" {
		c.addrList = v
	}
	c.syncRoutes = s.ROSSyncRoutes
	c.syncDomains = s.ROSSyncDomains
	c.rosMode = mode
	c.useBinAPI = s.ROSUseBinaryAPI
	c.apiPort = apiPort
	c.apiTLS = s.ROSAPITLS
	c.dynamicTimeout = dynTimeout
	c.syncPolicyCIDRs = s.ROSSyncPolicyCIDRs
	c.staticPrefixLimit = prefixLimit
	c.bgpLocalAS = localAS
	c.bgpRemoteAS = remoteAS
	c.bgpPeerIP = bgpPeerIP
	c.bgpRouteTable = bgpTable

	if c.httpClient == nil || c.insecure != s.ROSTLSSkipVerify {
		oldClient = c.httpClient
		c.httpClient = newROSHTTPClient(s.ROSTLSSkipVerify)
		c.insecure = s.ROSTLSSkipVerify
	}

	if connChanged {
		c.consecutiveFailures = 0
		c.nextRetryAt = time.Time{}
		c.lastLoggedErr = ""
		c.lastFingerprint = ""
		if c.binSync != nil {
			c.binSync.Close()
		}
		if c.binLive != nil {
			c.binLive.Close()
		}
	}
	c.refreshStatusLocked()
	c.mu.Unlock()

	c.liveBreakerMu.Lock()
	c.liveBreakerUntil = time.Time{}
	c.liveBreakerMu.Unlock()

	if oldClient != nil {
		oldClient.CloseIdleConnections()
	}

	c.refreshBGPDesiredPrefixes()
	c.configureBGPFromState()
}

func (c *ROSClient) configureBGPFromState() {
	if c == nil || c.bgpSpeaker == nil {
		return
	}
	conn := c.connSnapshot()
	if conn.mode != ROSModeBGP {
		c.bgpSpeaker.Configure(ROSBGPConfig{Enabled: false})
		return
	}
	peerIP := firstNonEmpty(conn.bgpPeerIP, rosURLHost(conn.baseURL))
	nh, _ := netip.ParseAddr(conn.gatewayIP)
	c.bgpSpeaker.Configure(ROSBGPConfig{
		Enabled:  peerIP != "" && nh.IsValid() && nh.Is4(),
		PeerIP:   peerIP,
		LocalAS:  conn.bgpLocalAS,
		RemoteAS: conn.bgpRemoteAS,
		NextHop:  nh,
		RouterID: nh,
	})
}

func (c *ROSClient) refreshBGPDesiredPrefixes() {
	if c == nil || c.bgpSpeaker == nil {
		return
	}
	conn := c.connSnapshot()
	if conn.mode != ROSModeBGP {
		return
	}
	c.mu.Lock()
	pol := c.policy
	dynStore := c.dynStore
	mgr := c.mgr
	c.mu.Unlock()

	var exclude []netip.Addr
	if pol != nil {
		exclude = rosExcludedHostAddrs(conn, mgr)
	}

	seen := make(map[netip.Prefix]struct{})
	var all []netip.Prefix

	if pol != nil && conn.syncPolicyCIDRs {
		plan := pol.ComputeRouterOSPrefixes(conn.staticPrefixLimit, exclude...)
		for _, pfx := range plan.Prefixes {
			m := pfx.Masked()
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				all = append(all, m)
			}
		}
		c.mu.Lock()
		c.status.StaticSynced = len(plan.Prefixes)
		c.status.DroppedByLimit = plan.DroppedByLimit
		c.mu.Unlock()
	}
	if dynStore != nil {
		if pol != nil {
			dynStore.Revalidate(func(domain string, ip netip.Addr) (bool, string) {
				return pol.RevalidateDynamicHostIP(domain, ip, exclude...)
			})
		}
		for _, pfx := range dynStore.Prefixes() {
			if _, ok := seen[pfx]; !ok {
				seen[pfx] = struct{}{}
				all = append(all, pfx)
			}
		}
		c.mu.Lock()
		c.status.DynSynced = dynStore.Count()
		c.mu.Unlock()
	}
	c.bgpSpeaker.SetDesiredPrefixes(all)
}

func (c *ROSClient) refreshStatusLocked() {
	c.status.Enabled = c.baseURL != "" && c.user != "" && c.urlErr == ""
	c.status.Mode = c.rosMode
	c.status.URL = c.baseURL
	c.status.RouteTable = c.routeTable
	c.status.AddressList = c.addrList
	c.status.ConsecFailures = c.consecutiveFailures
	if c.nextRetryAt.IsZero() {
		c.status.NextRetryAt = ""
	} else {
		c.status.NextRetryAt = c.nextRetryAt.UTC().Format(time.RFC3339)
	}
	if !c.status.Enabled {
		c.status.LastError = c.urlErr
	}
}

// Status returns a snapshot of the current RouterOS integration status.
func (c *ROSClient) Status() ROSSyncStatus {
	c.mu.Lock()
	fn := c.autoGatewayFn
	override := c.gatewayOverride
	st := c.status
	bgp := c.bgpSpeaker
	dyn := c.dynStore
	mode := c.rosMode
	c.mu.Unlock()

	autoIP := ""
	if fn != nil {
		autoIP = normalizeROSContainerIP(fn())
	}
	st.AutoGatewayIP = autoIP
	if override != "" {
		st.GatewayIP = override
	} else if autoIP != "" {
		st.GatewayIP = autoIP
	} else {
		st.GatewayIP = defaultROSContainerIP
	}
	if dyn != nil && (mode == ROSModeAddressList || mode == ROSModeBGP) && st.DynSynced == 0 {
		st.DynSynced = dyn.Count()
	}
	if bgp != nil {
		bst := bgp.Status()
		st.BGPState = bst.State
		st.BGPRoutes = bst.AnnouncedRoutes
		st.BGPPeer = bst.Peer
		st.BGPLastError = bst.LastError
		st.BGPNextHop = bst.NextHop
		if mode == ROSModeBGP {
			st.Enabled = bst.Enabled || (st.URL != "" && c.user != "")
		}
	}
	return st
}

func (c *ROSClient) autoOrDefaultGatewayIP() string {
	c.mu.Lock()
	fn := c.autoGatewayFn
	c.mu.Unlock()
	if fn != nil {
		if ip := normalizeROSContainerIP(fn()); ip != "" {
			return ip
		}
	}
	return defaultROSContainerIP
}

func (c *ROSClient) connSnapshot() rosConnConfig {
	c.mu.Lock()
	binCfg, _ := rosBinEndpointFromSettings(AppSettings{
		ROSURL:           c.baseURL,
		ROSUser:          c.user,
		ROSPass:          c.pass,
		ROSTLSSkipVerify: c.insecure,
		ROSUseBinaryAPI:  c.useBinAPI,
		ROSAPIPort:       c.apiPort,
		ROSAPITLS:        c.apiTLS,
	})
	conn := rosConnConfig{
		baseURL:           c.baseURL,
		urlErr:            c.urlErr,
		user:              c.user,
		pass:              c.pass,
		insecure:          c.insecure,
		gatewayIP:         c.gatewayOverride,
		routeTable:        c.routeTable,
		forwardDNS:        c.forwardDNS,
		addrList:          c.addrList,
		client:            c.httpClient,
		mode:              c.rosMode,
		useBinAPI:         c.useBinAPI,
		binCfg:            binCfg,
		dynamicTimeout:    c.dynamicTimeout,
		syncPolicyCIDRs:   c.syncPolicyCIDRs,
		staticPrefixLimit: c.staticPrefixLimit,
		bgpLocalAS:        c.bgpLocalAS,
		bgpRemoteAS:       c.bgpRemoteAS,
		bgpPeerIP:         c.bgpPeerIP,
		bgpRouteTable:     c.bgpRouteTable,
	}
	c.mu.Unlock()

	if conn.gatewayIP == "" {
		conn.gatewayIP = c.autoOrDefaultGatewayIP()
	}
	return conn
}

// ReadDomains loads deduplicated domain names from domains.txt.
func (c *ROSClient) ReadDomains() ([]string, error) {
	b, err := os.ReadFile(c.domainsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return normalizeDomainLines(string(b)), nil
}

// SaveDomains validates, deduplicates, and writes domains.txt.
func (c *ROSClient) SaveDomains(raw string) error {
	clean := normalizeDomainLines(raw)
	if err := os.MkdirAll(filepath.Dir(c.domainsFile), 0o700); err != nil {
		return err
	}
	data := strings.Join(clean, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(c.domainsFile, []byte(data), 0o600); err != nil {
		return err
	}
	c.mu.Lock()
	c.lastFingerprint = ""
	c.mu.Unlock()
	return nil
}

func normalizeDomainLines(raw string) []string {
	var clean []string
	seen := map[string]bool{}
	for _, line := range strings.Split(normalizeLF(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(strings.ToLower(line), ".")
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		clean = append(clean, line)
	}
	return clean
}

func (c *ROSClient) do(method, path string, body any) ([]byte, int, error) {
	return c.doWithConn(c.connSnapshot(), method, path, body)
}

func (c *ROSClient) doWithConn(conn rosConnConfig, method, path string, body any) ([]byte, int, error) {
	if conn.urlErr != "" {
		return nil, 0, errors.New(conn.urlErr)
	}
	if conn.baseURL == "" || conn.user == "" {
		return nil, 0, errors.New("ROS_URL и ROS_USER не настроены")
	}

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	endpoint := conn.baseURL + "/rest" + path
	req, err := http.NewRequest(method, endpoint, r)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(conn.user, conn.pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := conn.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return data, resp.StatusCode, formatROSError(conn.baseURL, method, path, resp.StatusCode, data)
	}
	return data, resp.StatusCode, nil
}

func (c *ROSClient) listResources(conn rosConnConfig, path string, proplist, query []string) ([]map[string]any, error) {
	reqBody := map[string]any{}
	if len(proplist) > 0 {
		reqBody[".proplist"] = proplist
	}
	if len(query) > 0 {
		reqBody[".query"] = query
	}
	raw, status, err := c.doWithConn(conn, http.MethodPost, path+"/print", reqBody)
	if err != nil {
		if status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
			raw, _, err = c.doWithConn(conn, http.MethodGet, path, nil)
		}
		if err != nil {
			return nil, err
		}
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var out []map[string]any
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("REST %s JSON decode: %w", path, err)
	}
	return out, nil
}

// SyncAll synchronizes routes and DNS domains immediately, serializing concurrent callers.
func (c *ROSClient) SyncAll(mgr *TunnelManager) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	return c.syncLocked(mgr, false)
}

// SyncPeriodic runs on background ticks: honors exponential backoff on errors and avoids redundant polls.
func (c *ROSClient) SyncPeriodic(mgr *TunnelManager) error {
	if !c.syncMu.TryLock() {
		return nil
	}
	defer c.syncMu.Unlock()
	return c.syncLocked(mgr, true)
}

func (c *ROSClient) syncLocked(mgr *TunnelManager, isPeriodic bool) error {
	c.mu.Lock()
	if mgr == nil {
		mgr = c.mgr
	}
	mode := c.rosMode
	enabled := c.baseURL != "" && c.user != "" && c.urlErr == ""
	urlErr := c.urlErr
	syncRoutes := c.syncRoutes
	syncDomains := c.syncDomains
	nextRetry := c.nextRetryAt
	lastErr := c.status.LastError
	lastFP := c.lastFingerprint
	lastFull := c.lastFullSyncAt
	c.mu.Unlock()

	conn := c.connSnapshot()

	if mode == ROSModeGateway {
		c.configureBGPFromState()
		if !isPeriodic {
			c.recordModeSuccess(conn, "", 0, 0, 0, 0, 0, "", isPeriodic)
		}
		return nil
	}

	if mode == ROSModeBGP {
		c.configureBGPFromState()
		c.refreshBGPDesiredPrefixes()
		st := c.bgpSpeaker.Status()
		c.recordModeSuccess(conn, "bgp", 0, 0, c.status.StaticSynced, st.DesiredRoutes-c.status.StaticSynced, c.status.DroppedByLimit, "bgp", isPeriodic)
		return nil
	}

	if !enabled {
		if urlErr != "" {
			c.recordFailure(urlErr, false, isPeriodic)
			return errors.New(urlErr)
		}
		return nil
	}

	now := time.Now()
	if isPeriodic && !nextRetry.IsZero() && now.Before(nextRetry) {
		return nil
	}

	if mode == ROSModeAddressList {
		// Reconcile at least every ~60s on periodic ticks to ensure reboot recovery and RAM timeouts.
		if isPeriodic && lastErr == "" && lastFP == "address_list" && !lastFull.IsZero() && now.Sub(lastFull) < 55*time.Second {
			return nil
		}
		staticSynced, dynSynced, dropped, transport, err := c.syncPolicyAddressListWithConn(conn, mgr)
		if err != nil {
			errText := err.Error()
			if h := extractROSHint(err); h != "" && !strings.Contains(errText, h) {
				errText += " — " + h
			}
			c.recordFailure(errText, true, isPeriodic)
			return errors.New(errText)
		}
		c.recordModeSuccess(conn, "address_list", 0, 0, staticSynced, dynSynced, dropped, transport, isPeriodic)
		return nil
	}

	// Legacy ROSModeManual (domains.txt + AllowedIPs)
	var byIface map[string][]string
	if syncRoutes && mgr != nil {
		byIface = mgr.AllNonDefaultAllowedIPs()
	}
	var domains []string
	var readDomErr error
	if syncDomains {
		domains, readDomErr = c.ReadDomains()
	}

	fp := buildROSFingerprint(conn, syncRoutes, syncDomains, byIface, domains)
	if isPeriodic && lastErr == "" && readDomErr == nil && fp == lastFP && !lastFull.IsZero() && now.Sub(lastFull) < rosPeriodicDriftEvery {
		return nil
	}

	var routesCount, domainsCount int
	var errs []string
	var hint string
	fatal := false

	if syncRoutes {
		n, err := c.syncAllowedRoutesWithConn(conn, byIface)
		routesCount = n
		if err != nil {
			errs = append(errs, err.Error())
			if h := extractROSHint(err); h != "" {
				hint = h
			}
			if isFatalROSError(err) {
				fatal = true
			}
		}
	}

	if syncDomains && !fatal {
		if readDomErr != nil {
			errs = append(errs, readDomErr.Error())
		} else {
			n, err := c.syncDNSDomainsWithConn(conn, domains)
			domainsCount = n
			if err != nil {
				errs = append(errs, err.Error())
				if h := extractROSHint(err); h != "" && hint == "" {
					hint = h
				}
			}
		}
	}

	if len(errs) > 0 {
		errText := strings.Join(errs, "; ")
		if hint != "" && !strings.Contains(errText, hint) {
			errText += " — " + hint
		}
		c.recordFailure(errText, true, isPeriodic)
		return errors.New(errText)
	}

	c.recordModeSuccess(conn, fp, routesCount, domainsCount, 0, 0, 0, "rest", isPeriodic)
	return nil
}

func (c *ROSClient) recordFailure(errText string, applyBackoff, isPeriodic bool) {
	now := time.Now()
	shouldLog := false

	c.mu.Lock()
	c.status.LastSync = now.UTC().Format(time.RFC3339)
	c.status.LastError = errText
	if applyBackoff {
		c.consecutiveFailures++
		c.nextRetryAt = now.Add(rosBackoffDuration(c.consecutiveFailures))
	}
	c.refreshStatusLocked()
	if !isPeriodic || errText != c.lastLoggedErr || now.Sub(c.lastLoggedErrAt) >= rosErrorLogRepeat {
		c.lastLoggedErr = errText
		c.lastLoggedErrAt = now
		shouldLog = true
	}
	c.mu.Unlock()

	if shouldLog && c.logger != nil {
		c.logger.Logf("ROS sync error: %s", errText)
	}
}

func (c *ROSClient) recordModeSuccess(conn rosConnConfig, fp string, routesCount, domainsCount, staticSynced, dynSynced, dropped int, transport string, isPeriodic bool) {
	now := time.Now()
	c.mu.Lock()
	prevRoutes := c.status.Routes
	prevDomains := c.status.Domains
	prevStatic := c.status.StaticSynced
	prevDyn := c.status.DynSynced
	hadErr := c.status.LastError != "" || !c.hadSuccess

	c.status.LastSync = now.UTC().Format(time.RFC3339)
	c.status.LastError = ""
	c.status.Routes = routesCount
	c.status.Domains = domainsCount
	if conn.mode != ROSModeBGP {
		c.status.StaticSynced = staticSynced
		c.status.DynSynced = dynSynced
		c.status.DroppedByLimit = dropped
	}
	if transport != "" {
		c.status.Transport = transport
	}
	c.status.GatewayIP = conn.gatewayIP
	c.status.RouteTable = conn.routeTable
	c.consecutiveFailures = 0
	c.nextRetryAt = time.Time{}
	c.lastLoggedErr = ""
	c.lastFingerprint = fp
	c.lastFullSyncAt = now
	c.hadSuccess = true
	c.refreshStatusLocked()
	c.mu.Unlock()

	if c.logger == nil {
		return
	}
	switch conn.mode {
	case ROSModeAddressList:
		if !isPeriodic || hadErr || staticSynced != prevStatic || dynSynced != prevDyn {
			c.logger.Logf("ROS address-list sync OK (list=%s, static=%d, dyn=%d, via=%s, gw=%s)",
				conn.addrList, staticSynced, dynSynced, transport, conn.gatewayIP)
		}
	case ROSModeBGP:
		if !isPeriodic || hadErr {
			c.logger.Logf("ROS BGP routes updated (desired_static=%d, dyn=%d, next_hop=%s)",
				c.status.StaticSynced, c.status.DynSynced, conn.gatewayIP)
		}
	case ROSModeGateway:
		if !isPeriodic {
			c.logger.Logf("ROS gateway mode active (gw=%s)", conn.gatewayIP)
		}
	default:
		if !isPeriodic || hadErr || routesCount != prevRoutes || domainsCount != prevDomains {
			c.logger.Logf("ROS sync OK (routes=%d, domains=%d, gw=%s)", routesCount, domainsCount, conn.gatewayIP)
		}
	}
}

func rosBackoffDuration(failures int) time.Duration {
	if failures <= 1 {
		return time.Minute
	}
	shift := min(failures-1, 4)
	d := time.Minute << shift
	if d > 15*time.Minute {
		return 15 * time.Minute
	}
	return d
}

// TestConnection probes /system/resource, /system/identity (REST) and optionally Binary API (:8728/:8729).
func (c *ROSClient) TestConnection(override *AppSettings) ROSTestResult {
	conn := c.connSnapshot()
	if override != nil {
		baseURL := normalizeROSBaseURL(override.ROSURL)
		urlErr := validateROSBaseURL(baseURL)
		pass := override.ROSPass
		if pass == "" {
			pass = conn.pass
		}
		gw := normalizeROSContainerIP(override.ROSContainerIP)
		if gw == "" {
			gw = c.autoOrDefaultGatewayIP()
		}
		ovCopy := *override
		ovCopy.ROSURL = baseURL
		ovCopy.ROSUser = strings.TrimSpace(override.ROSUser)
		ovCopy.ROSPass = pass
		binCfg, _ := rosBinEndpointFromSettings(ovCopy)
		conn = rosConnConfig{
			baseURL:    baseURL,
			urlErr:     urlErr,
			user:       ovCopy.ROSUser,
			pass:       pass,
			insecure:   override.ROSTLSSkipVerify,
			gatewayIP:  gw,
			routeTable: strings.TrimSpace(override.ROSRouteTable),
			client:     newROSHTTPClient(override.ROSTLSSkipVerify),
			useBinAPI:  override.ROSUseBinaryAPI,
			binCfg:     binCfg,
		}
		defer conn.client.CloseIdleConnections()
	}

	res := ROSTestResult{
		URL:        conn.baseURL,
		GatewayIP:  conn.gatewayIP,
		BinAPIAddr: conn.binCfg.Addr,
	}

	if conn.useBinAPI && conn.binCfg.Addr != "" && conn.urlErr == "" && conn.user != "" {
		probe := NewROSBinClient()
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		rows, bErr := probe.Exec(ctx, conn.binCfg, "/system/identity/print")
		cancel()
		probe.Close()
		if bErr == nil {
			res.BinAPIOK = true
			if len(rows) > 0 && res.Identity == "" {
				res.Identity = rows[0]["name"]
			}
		} else {
			res.BinAPIError = bErr.Error()
		}
	}

	raw, status, err := c.doWithConn(conn, http.MethodGet, "/system/resource", nil)
	if err != nil {
		res.HTTPStatus = status
		res.Error = err.Error()
		res.Hint = extractROSHint(err)
		if res.Hint == "" {
			res.Hint = rosNetworkHint(conn.baseURL, err)
		}
		return res
	}

	var resource map[string]any
	if json.Unmarshal(raw, &resource) == nil {
		res.Board = strField(resource, "board-name")
		res.Version = strField(resource, "version")
	}

	if idRaw, _, idErr := c.doWithConn(conn, http.MethodGet, "/system/identity", nil); idErr == nil {
		var ident map[string]any
		if json.Unmarshal(idRaw, &ident) == nil {
			res.Identity = strField(ident, "name")
		}
	}

	res.OK = true

	// Cache detected router metadata if testing the active configuration.
	c.mu.Lock()
	if override == nil || (conn.baseURL == c.baseURL && conn.user == c.user) {
		c.status.RouterName = res.Identity
		c.status.RouterOSVer = res.Version
	}
	c.mu.Unlock()

	return res
}

// CleanupManaged deletes all routes, DNS records, and managed address-list entries created by awg-ctl on RouterOS.
func (c *ROSClient) CleanupManaged() (routesDeleted, dnsDeleted int, err error) {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	conn := c.connSnapshot()
	if !c.Status().Enabled {
		return 0, 0, errors.New("ROS_URL и ROS_USER не настроены")
	}

	routes, err := c.listResources(conn, "/ip/route", []string{".id", "comment"}, nil)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range routes {
		if !strings.HasPrefix(strField(r, "comment"), "awg-ctl:") {
			continue
		}
		if id := strField(r, ".id"); id != "" {
			if _, _, delErr := c.doWithConn(conn, http.MethodDelete, "/ip/route/"+id, nil); delErr != nil {
				return routesDeleted, dnsDeleted, delErr
			}
			routesDeleted++
		}
	}

	dnsList, err := c.listResources(conn, "/ip/dns/static", []string{".id", "comment"}, []string{"comment=awg-ctl"})
	if err != nil {
		return routesDeleted, dnsDeleted, err
	}
	for _, r := range dnsList {
		if strField(r, "comment") != "awg-ctl" {
			continue
		}
		if id := strField(r, ".id"); id != "" {
			if _, _, delErr := c.doWithConn(conn, http.MethodDelete, "/ip/dns/static/"+id, nil); delErr != nil {
				return routesDeleted, dnsDeleted, delErr
			}
			dnsDeleted++
		}
	}

	addrDeleted := 0
	if conn.mode == ROSModeAddressList && conn.addrList != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		rows, _, alErr := c.listAddressList(ctx, conn, c.binSync, conn.addrList)
		if alErr == nil {
			for _, row := range rows {
				if isManagedROSComment(row.Comment) && row.ID != "" {
					if dErr := c.removeAddressListEntry(ctx, conn, c.binSync, row.ID); dErr == nil {
						addrDeleted++
					}
				}
			}
		}
		cancel()
	}

	if c.dynStore != nil {
		c.dynStore.Clear()
	}
	if conn.mode == ROSModeBGP {
		c.refreshBGPDesiredPrefixes()
	}

	c.mu.Lock()
	c.status.Routes = 0
	c.status.Domains = 0
	c.status.StaticSynced = 0
	c.status.DynSynced = 0
	c.status.LastError = ""
	c.lastFingerprint = ""
	c.mu.Unlock()

	if c.logger != nil {
		c.logger.Logf("ROS cleanup OK (routes_deleted=%d, dns_deleted=%d, addr_list_deleted=%d)", routesDeleted, dnsDeleted, addrDeleted)
	}
	return routesDeleted, dnsDeleted, nil
}

func (c *ROSClient) syncAllowedRoutes(byIface map[string][]string) (int, error) {
	return c.syncAllowedRoutesWithConn(c.connSnapshot(), byIface)
}

func (c *ROSClient) syncAllowedRoutesWithConn(conn rosConnConfig, byIface map[string][]string) (int, error) {
	existing, err := c.listResources(conn, "/ip/route", []string{".id", "dst-address", "gateway", "comment", "routing-table", "disabled"}, nil)
	if err != nil {
		return 0, err
	}

	desired := map[string]string{}
	ifaces := make([]string, 0, len(byIface))
	for iface := range byIface {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)
	for _, iface := range ifaces {
		comment := "awg-ctl:" + iface
		cidrs := append([]string(nil), byIface[iface]...)
		sort.Strings(cidrs)
		for _, cidr := range cidrs {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil || pfx.Bits() == 0 {
				continue
			}
			norm := pfx.Masked().String()
			if _, exists := desired[norm]; !exists {
				desired[norm] = comment
			}
		}
	}

	kept := map[string]bool{}
	for _, r := range existing {
		comment := strField(r, "comment")
		if !strings.HasPrefix(comment, "awg-ctl:") {
			continue
		}
		id := strField(r, ".id")
		dst := normalizeRouterCIDR(strField(r, "dst-address"))
		gw := stripIfaceScope(strField(r, "gateway"))
		tbl := strField(r, "routing-table")
		disabled := isTruthyROS(r["disabled"])

		wantComment, ok := desired[dst]
		if ok && !kept[dst] {
			if wantComment == comment && gw == conn.gatewayIP && routeTableMatches(tbl, conn.routeTable) && !disabled {
				kept[dst] = true
				continue
			}
			if id != "" {
				patch := map[string]any{
					"gateway":  conn.gatewayIP,
					"comment":  wantComment,
					"disabled": "false",
				}
				if conn.routeTable != "" {
					patch["routing-table"] = conn.routeTable
				}
				if _, _, pErr := c.doWithConn(conn, http.MethodPatch, "/ip/route/"+id, patch); pErr == nil {
					kept[dst] = true
					continue
				} else if isFatalROSError(pErr) {
					return len(kept), pErr
				}
			}
		}
		if id != "" {
			if _, _, delErr := c.doWithConn(conn, http.MethodDelete, "/ip/route/"+id, nil); delErr != nil {
				return len(kept), delErr
			}
		}
	}

	desiredKeys := make([]string, 0, len(desired))
	for dst := range desired {
		desiredKeys = append(desiredKeys, dst)
	}
	sort.Strings(desiredKeys)

	for _, dst := range desiredKeys {
		if kept[dst] {
			continue
		}
		payload := map[string]any{
			"dst-address": dst,
			"gateway":     conn.gatewayIP,
			"comment":     desired[dst],
		}
		if conn.routeTable != "" {
			payload["routing-table"] = conn.routeTable
		}
		if _, _, err := c.doWithConn(conn, http.MethodPut, "/ip/route", payload); err != nil {
			return len(kept), err
		}
		kept[dst] = true
	}
	return len(desired), nil
}

func (c *ROSClient) syncDNSDomains(domains []string) (int, error) {
	return c.syncDNSDomainsWithConn(c.connSnapshot(), domains)
}

func (c *ROSClient) syncDNSDomainsWithConn(conn rosConnConfig, domains []string) (int, error) {
	cleanDomains := normalizeDomainLines(strings.Join(domains, "\n"))
	existing, err := c.listResources(
		conn,
		"/ip/dns/static",
		[]string{".id", "name", "type", "forward-to", "address-list", "match-subdomain", "comment", "disabled"},
		[]string{"comment=awg-ctl"},
	)
	if err != nil {
		return 0, err
	}

	desired := make(map[string]bool, len(cleanDomains))
	for _, d := range cleanDomains {
		desired[d] = true
	}

	c.mu.Lock()
	skipAddrList := conn.addrList == "" || c.noAddrListURL == conn.baseURL
	c.mu.Unlock()

	kept := map[string]bool{}
	for _, r := range existing {
		if strField(r, "comment") != "awg-ctl" {
			continue
		}
		id := strField(r, ".id")
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strField(r, "name"))), ".")
		typ := strings.ToUpper(strings.TrimSpace(strField(r, "type")))
		fwd := strField(r, "forward-to")
		al := strField(r, "address-list")
		sub := isTruthyROS(r["match-subdomain"])
		disabled := isTruthyROS(r["disabled"])

		if desired[name] && !kept[name] {
			addrListOK := skipAddrList || al == conn.addrList
			if typ == "FWD" && fwd == conn.gatewayIP && sub && !disabled && addrListOK {
				kept[name] = true
				continue
			}
			if id != "" {
				patch := map[string]any{
					"type":            "FWD",
					"forward-to":      conn.gatewayIP,
					"match-subdomain": "true",
					"disabled":        "false",
				}
				if !skipAddrList {
					patch["address-list"] = conn.addrList
				}
				_, status, pErr := c.doWithConn(conn, http.MethodPatch, "/ip/dns/static/"+id, patch)
				if pErr != nil && !skipAddrList && status == http.StatusBadRequest {
					delete(patch, "address-list")
					if _, _, pErr2 := c.doWithConn(conn, http.MethodPatch, "/ip/dns/static/"+id, patch); pErr2 == nil {
						c.markNoAddrList(conn.baseURL)
						skipAddrList = true
						pErr = nil
					} else {
						pErr = pErr2
					}
				}
				if pErr == nil {
					kept[name] = true
					continue
				}
				if isFatalROSError(pErr) {
					return len(kept), pErr
				}
			}
		}
		if id != "" {
			if _, _, delErr := c.doWithConn(conn, http.MethodDelete, "/ip/dns/static/"+id, nil); delErr != nil {
				return len(kept), delErr
			}
		}
	}

	for _, name := range cleanDomains {
		if kept[name] {
			continue
		}
		payload := map[string]any{
			"name":            name,
			"type":            "FWD",
			"forward-to":      conn.gatewayIP,
			"match-subdomain": "true",
			"comment":         "awg-ctl",
		}
		if !skipAddrList {
			payload["address-list"] = conn.addrList
		}
		_, status, err := c.doWithConn(conn, http.MethodPut, "/ip/dns/static", payload)
		if err != nil && !skipAddrList && status == http.StatusBadRequest {
			// Fallback for RouterOS < 7.15 without address-list on FWD
			delete(payload, "address-list")
			if _, _, err2 := c.doWithConn(conn, http.MethodPut, "/ip/dns/static", payload); err2 != nil {
				return len(kept), err2
			}
			c.markNoAddrList(conn.baseURL)
			skipAddrList = true
		} else if err != nil {
			return len(kept), err
		}
		kept[name] = true
	}
	return len(cleanDomains), nil
}

func (c *ROSClient) markNoAddrList(baseURL string) {
	c.mu.Lock()
	c.noAddrListURL = baseURL
	c.mu.Unlock()
}

// normalizeROSBaseURL canonicalizes ROS_URL, defaults missing scheme to https://, and strips trailing /rest.
func normalizeROSBaseURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimRight(s, "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	cleanPath := strings.TrimRight(u.Path, "/")
	if strings.EqualFold(cleanPath, "/rest") {
		cleanPath = ""
	} else if len(cleanPath) > len("/rest") && strings.EqualFold(cleanPath[len(cleanPath)-len("/rest"):], "/rest") {
		cleanPath = cleanPath[:len(cleanPath)-len("/rest")]
	}
	u.Path = cleanPath
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func validateROSBaseURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Sprintf("неверный ROS_URL %q: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Sprintf("неподдерживаемая схема ROS_URL %q (допустимо http:// или https://)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Sprintf("в ROS_URL %q не указан хост", raw)
	}
	return ""
}

// normalizeROSContainerIP strips CIDR masks and treats "auto" as empty (auto-detect).
func normalizeROSContainerIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "auto") {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil && ip.To4() != nil {
		return ip.To4().String()
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	return s
}

func detectInterfaceIPv4(ifaceName string) string {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return ""
	}
	ifc, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP != nil {
			if ip4 := ipn.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

func formatROSError(baseURL, method, path string, statusCode int, data []byte) error {
	summary := extractROSErrorBody(data)
	if summary == "" {
		summary = http.StatusText(statusCode)
	}
	return &rosHTTPError{
		Method:     method,
		Path:       path,
		StatusCode: statusCode,
		Summary:    summary,
		Hint:       rosHTTPStatusHint(baseURL, statusCode),
	}
}

func extractROSErrorBody(data []byte) string {
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "{") {
		var obj map[string]any
		if json.Unmarshal(data, &obj) == nil {
			msg := strings.TrimSpace(strField(obj, "message"))
			detail := strings.TrimSpace(strField(obj, "detail"))
			errStr := strings.TrimSpace(strField(obj, "error"))
			var parts []string
			for _, p := range []string{msg, detail, errStr} {
				if p != "" {
					parts = append(parts, p)
				}
			}
			if len(parts) > 0 {
				return collapseAndTruncate(strings.Join(parts, ": "), rosMaxErrorBodyRunes)
			}
		}
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<title") {
		if m := htmlH1Re.FindStringSubmatch(raw); len(m) == 2 {
			if t := collapseAndTruncate(htmlTagRe.ReplaceAllString(m[1], " "), rosMaxErrorBodyRunes); t != "" {
				return t
			}
		}
		if m := htmlTitleRe.FindStringSubmatch(raw); len(m) == 2 {
			if t := collapseAndTruncate(htmlTagRe.ReplaceAllString(m[1], " "), rosMaxErrorBodyRunes); t != "" {
				return t
			}
		}
		return collapseAndTruncate(htmlTagRe.ReplaceAllString(raw, " "), rosMaxErrorBodyRunes)
	}
	return collapseAndTruncate(raw, rosMaxErrorBodyRunes)
}

func collapseAndTruncate(s string, maxRunes int) string {
	clean := strings.Join(strings.Fields(s), " ")
	runes := []rune(clean)
	if len(runes) <= maxRunes {
		return clean
	}
	return string(runes[:maxRunes]) + "…"
}

func rosHTTPStatusHint(baseURL string, statusCode int) string {
	switch statusCode {
	case http.StatusForbidden:
		if strings.HasPrefix(strings.ToLower(baseURL), "http://") {
			return "На RouterOS 7.21+ может быть выключен /ip/service/webserver rest-plain=yes (перейдите на https://...), либо IP контейнера не входит в address= сервиса/пользователя, либо у группы нет политики rest-api"
		}
		return "Проверьте /ip/service www-ssl (disabled=no, address= подсеть контейнера), /ip/service/webserver rest-secure=yes и политику rest-api в /user/group"
	case http.StatusUnauthorized:
		return "Проверьте логин ROS_USER, пароль ROS_PASS и разрешённый address= в /user"
	case http.StatusNotFound:
		return "Проверьте ROS_URL (без /rest) и версию RouterOS (REST API требует v7+)"
	default:
		return ""
	}
}

func rosNetworkHint(baseURL string, err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "Таймаут подключения: проверьте адрес шлюза в ROS_URL и правило /ip/firewall/filter input (пакеты из подсети контейнера не должны попадать под drop !LAN)"
	case strings.Contains(msg, "connection refused"):
		return "Соединение отклонено: включите нужный сервис (/ip/service www-ssl для https или www для http)"
	case strings.Contains(msg, "x509") || strings.Contains(msg, "tls"):
		return "Ошибка TLS-сертификата: включите галку «Пропускать проверку TLS»"
	case strings.HasPrefix(strings.ToLower(baseURL), "http://"):
		return "Проверьте доступность порта 80 и rest-plain=yes"
	default:
		return ""
	}
}

func extractROSHint(err error) string {
	var he *rosHTTPError
	if errors.As(err, &he) {
		return he.Hint
	}
	return ""
}

func isFatalROSError(err error) bool {
	if err == nil {
		return false
	}
	var he *rosHTTPError
	if errors.As(err, &he) {
		return he.StatusCode == http.StatusUnauthorized ||
			he.StatusCode == http.StatusForbidden ||
			he.StatusCode == http.StatusNotFound ||
			he.StatusCode >= http.StatusInternalServerError
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func buildROSFingerprint(conn rosConnConfig, syncRoutes, syncDomains bool, byIface map[string][]string, domains []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s|%v|%v\n",
		conn.baseURL, conn.user, conn.gatewayIP, conn.routeTable, conn.forwardDNS, conn.addrList, syncRoutes, syncDomains)
	ifaces := make([]string, 0, len(byIface))
	for k := range byIface {
		ifaces = append(ifaces, k)
	}
	sort.Strings(ifaces)
	for _, ifc := range ifaces {
		cidrs := append([]string(nil), byIface[ifc]...)
		sort.Strings(cidrs)
		fmt.Fprintf(h, "R:%s=%s\n", ifc, strings.Join(cidrs, ","))
	}
	for _, d := range domains {
		fmt.Fprintf(h, "D:%s\n", d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeRouterCIDR(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked().String()
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	return s
}

func stripIfaceScope(gw string) string {
	s := strings.TrimSpace(gw)
	if idx := strings.IndexByte(s, '%'); idx >= 0 {
		s = s[:idx]
	}
	return s
}

func routeTableMatches(actual, want string) bool {
	a := strings.TrimSpace(actual)
	w := strings.TrimSpace(want)
	if w == "" || w == "main" {
		return a == "" || a == "main"
	}
	return a == w
}

func isTruthyROS(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "true" || s == "yes"
	default:
		return false
	}
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
