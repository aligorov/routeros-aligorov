package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type VPSPresetInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	DefaultPort int    `json:"default_port"`
	Desc        string `json:"desc"`
}

var DefaultVPSPresets = []VPSPresetInfo{
	{ID: "quic", Label: "HTTP/3 (QUIC)", DefaultPort: 443, Desc: "YouTube / HTTPS (RFC 9000)"},
	{ID: "quic-alt", Label: "HTTP/3 (QUIC Alt)", DefaultPort: 0, Desc: "QUIC на высоком порту 20000-59999/udp"},
	{ID: "stun", Label: "WebRTC / STUN", DefaultPort: 3478, Desc: "Telegram / WhatsApp звонки (RFC 5389)"},
	{ID: "stun-alt", Label: "WebRTC / STUN (Alt)", DefaultPort: 0, Desc: "STUN на высоком порту 20000-50000/udp"},
	{ID: "dtls", Label: "DTLS 1.2 (Zoom / VoIP)", DefaultPort: 8801, Desc: "RFC 6347 ClientHello"},
	{ID: "dns", Label: "DNS (EDNS0)", DefaultPort: 53, Desc: "DNS-запрос ya.ru (RFC 6891)"},
	{ID: "ntp", Label: "NTP v4 (Время)", DefaultPort: 123, Desc: "RFC 5905 Client Request"},
	{ID: "sip", Label: "SIP (VoIP / Телефония)", DefaultPort: 5060, Desc: "RFC 3261 OPTIONS"},
	{ID: "steam", Label: "Игровой (Steam A2S)", DefaultPort: 27015, Desc: "Source Engine Query"},
	{ID: "minecraft", Label: "Игровой (Minecraft)", DefaultPort: 19132, Desc: "RakNet Unconnected Ping"},
	{ID: "discord", Label: "Discord Voice (UDP)", DefaultPort: 50001, Desc: "UDP IP Discovery"},
	{ID: "dht", Label: "BitTorrent DHT (BEP-5)", DefaultPort: 6881, Desc: "DHT Ping Query"},
	{ID: "custom", Label: "Пользовательский", DefaultPort: 0, Desc: "Ручной порт и строка I1"},
}

type VPSServer struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	APIHost          string    `json:"api_host"`
	APIPort          int       `json:"api_port"`
	UseHTTPS         bool      `json:"use_https"`
	TLSSkipVerify    bool      `json:"tls_insecure"`
	TLSPinSHA256     string    `json:"tls_pin_sha256,omitempty"`
	AdminToken       string    `json:"admin_token,omitempty"`
	PollIntervalMin  int       `json:"poll_interval_min,omitempty"`
	LastServerETag   string    `json:"last_server_etag,omitempty"`
	LastPreset       string    `json:"last_preset,omitempty"`
	LastPort         int       `json:"last_port,omitempty"`
	LastEndpoint     string    `json:"last_endpoint,omitempty"`
	LastEndpointMode string    `json:"last_endpoint_mode,omitempty"`
	LastPublicIPv4   string    `json:"last_public_ipv4,omitempty"`
	LastPublicIPv6   string    `json:"last_public_ipv6,omitempty"`
	LastCheckedAt    time.Time `json:"last_checked_at,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

type VPSServerView struct {
	VPSServer
	AdminTokenSet bool            `json:"admin_token_set"`
	ClientCount   int             `json:"client_count"`
	Presets       []VPSPresetInfo `json:"presets,omitempty"`
}

type FleetClient struct {
	ID           string `json:"id"`
	VPSID        string `json:"vps_id"`
	VPSName      string `json:"vps_name,omitempty"`
	ClientName   string `json:"client_name"`
	SubToken     string `json:"sub_token,omitempty"`
	IPv4         string `json:"ipv4,omitempty"`
	IPv6         string `json:"ipv6,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	EndpointMode string `json:"endpoint_mode,omitempty"`
	EndpointHost string `json:"endpoint_host,omitempty"`
	DNS          string `json:"dns,omitempty"`
	MTU          string `json:"mtu,omitempty"`
	AllowedIPs   string `json:"allowed_ips,omitempty"`
	Keepalive    string `json:"keepalive,omitempty"`
	IsOnline     bool   `json:"is_online"`
	HandshakeAge int64  `json:"handshake_age_sec"`
	RxBytes      uint64 `json:"rx_bytes"`
	TxBytes      uint64 `json:"tx_bytes"`
	LastETag     string `json:"last_etag,omitempty"`

	// Telegram binding and delivery state (stored locally in the container)
	TGChatID          string    `json:"tg_chat_id,omitempty"`
	TGThreadID        int       `json:"tg_thread_id,omitempty"`
	TGLabel           string    `json:"tg_label,omitempty"`
	TGAutoSend        bool      `json:"tg_auto_send"`
	LastSentETag      string    `json:"last_sent_etag,omitempty"`
	LastSentAt        time.Time `json:"last_sent_at,omitempty"`
	LastSendError     string    `json:"last_send_error,omitempty"`
	AutoSendFailures  int       `json:"auto_send_failures,omitempty"`
	AutoSendPaused    bool      `json:"auto_send_paused,omitempty"`
	AutoSendNextRetry time.Time `json:"auto_send_next_retry,omitempty"`
}

type TGContact struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ChatID   string `json:"chat_id"`
	ThreadID int    `json:"thread_id,omitempty"`
}

type VPSDiscoveryCandidate struct {
	ConfigName string `json:"config_name"`
	Name       string `json:"name"`
	APIHost    string `json:"api_host"`
	APIPort    int    `json:"api_port"`
	AlreadySet bool   `json:"already_set"`
}

type vpsFleetDisk struct {
	Servers  []VPSServer   `json:"servers"`
	Clients  []FleetClient `json:"clients"`
	Contacts []TGContact   `json:"contacts"`
}

type VPSFleetView struct {
	Servers    []VPSServerView         `json:"servers"`
	Clients    []FleetClient           `json:"clients"`
	Contacts   []TGContact             `json:"contacts"`
	Candidates []VPSDiscoveryCandidate `json:"candidates"`
	Presets    []VPSPresetInfo         `json:"presets"`
}

type VPSClientConfigPayload struct {
	Client   FleetClient `json:"client"`
	Config   string      `json:"config"`
	VPNURL   string      `json:"vpn_url"`
	SubURL   string      `json:"sub_url"`
	ETag     string      `json:"etag"`
	TGSent   bool        `json:"tg_sent,omitempty"`
	TGError  string      `json:"tg_error,omitempty"`
	ServerOK bool        `json:"server_ok,omitempty"`
}

// Remote API payloads from awg-3xui-installer api.py v2
type remoteServerMeta struct {
	ListenPort   int             `json:"listen_port"`
	Preset       string          `json:"preset"`
	EndpointMode string          `json:"endpoint_mode"`
	Endpoint     string          `json:"endpoint"`
	PublicIPv4   string          `json:"public_ipv4"`
	PublicIPv6   string          `json:"public_ipv6"`
	APIPort      int             `json:"api_port"`
	TLSEnabled   bool            `json:"tls_enabled"`
	ClientCount  int             `json:"client_count"`
	ServerETag   string          `json:"server_etag"`
	Presets      []VPSPresetInfo `json:"presets"`
}

type remoteClientItem struct {
	Name            string `json:"name"`
	IPv4            string `json:"ipv4"`
	IPv6            string `json:"ipv6"`
	PublicKey       string `json:"public_key"`
	IsOnline        bool   `json:"is_online"`
	LastHandshake   int64  `json:"last_handshake"`
	HandshakeAgeSec int64  `json:"handshake_age_sec"`
	RxBytes         uint64 `json:"rx_bytes"`
	TxBytes         uint64 `json:"tx_bytes"`
	Token           string `json:"token"`
	Endpoint        string `json:"endpoint"`
	EndpointMode    string `json:"endpoint_mode"`
	EndpointHost    string `json:"endpoint_host"`
	DNS             string `json:"dns"`
	MTU             string `json:"mtu"`
	AllowedIPs      string `json:"allowed_ips"`
	Keepalive       string `json:"keepalive"`
	ETag            string `json:"etag"`
	Config          string `json:"config"`
	VPNURL          string `json:"vpn_url"`
	SubPath         string `json:"sub_path"`
}

type remoteClientsResp struct {
	OK      bool               `json:"ok"`
	Server  *remoteServerMeta  `json:"server"`
	Clients []remoteClientItem `json:"clients"`
	Client  *remoteClientItem  `json:"client"`
	Error   string             `json:"error"`
	Message string             `json:"message"`
	Output  string             `json:"output"`
}

type VPSFleetManager struct {
	path     string
	settings *SettingsStore
	mgr      *TunnelManager
	subMgr   *SubscriptionManager
	tg       *TGNotifier
	logger   *RingLogger

	mu           sync.RWMutex
	state        vpsFleetDisk
	presetsMap   map[string][]VPSPresetInfo
	pollFailures map[string]int
	stopCh       chan struct{}
	stopped      bool
	syncLocks    sync.Map // per-vpsID mutex to prevent overlapping polls
}

func NewVPSFleetManager(srcDir string, settings *SettingsStore, mgr *TunnelManager, subMgr *SubscriptionManager, tg *TGNotifier, logger *RingLogger) *VPSFleetManager {
	fm := &VPSFleetManager{
		path:         filepath.Join(srcDir, "vps_fleet.json"),
		settings:     settings,
		mgr:          mgr,
		subMgr:       subMgr,
		tg:           tg,
		logger:       logger,
		presetsMap:   make(map[string][]VPSPresetInfo),
		pollFailures: make(map[string]int),
		stopCh:       make(chan struct{}),
	}
	_ = fm.load()
	return fm
}

func (fm *VPSFleetManager) load() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	b, err := os.ReadFile(fm.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var disk vpsFleetDisk
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	fm.state = disk
	return nil
}

func (fm *VPSFleetManager) saveLocked() error {
	if fm.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(fm.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(fm.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := fm.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fm.path)
}

func fleetRandID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

func fleetClientKey(vpsID, clientName string) string {
	return vpsID + ":" + clientName
}

func (fm *VPSFleetManager) Start() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-fm.stopCh:
				return
			case <-ticker.C:
				fm.pollDueServers()
			}
		}
	}()
}

func (fm *VPSFleetManager) Stop() {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if !fm.stopped {
		fm.stopped = true
		close(fm.stopCh)
	}
}

func (fm *VPSFleetManager) pollDueServers() {
	fm.mu.RLock()
	servers := append([]VPSServer(nil), fm.state.Servers...)
	fm.mu.RUnlock()

	now := time.Now()
	for _, srv := range servers {
		if srv.AdminToken == "" || srv.APIHost == "" {
			continue
		}
		interval := srv.PollIntervalMin
		if interval <= 0 {
			interval = 15
		}
		if now.Sub(srv.LastCheckedAt) < time.Duration(interval)*time.Minute {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = fm.RefreshServer(ctx, srv.ID, true, true, "Автообновление конфигурации (ротация / смена параметров на VPS)")
		cancel()
	}
}

// OnLocalSubscriptionUpdated is called by SubscriptionManager whenever a local tunnel profile
// gets a new config from a VPS, triggering an immediate check and Telegram delivery to clients on that VPS.
func (fm *VPSFleetManager) OnLocalSubscriptionUpdated(cfgName, remoteHost string) {
	host := strings.ToLower(cleanHost(remoteHost))
	if host == "" {
		return
	}
	fm.mu.RLock()
	var matchedIDs []string
	for _, srv := range fm.state.Servers {
		if srv.AdminToken == "" {
			continue
		}
		if strings.EqualFold(cleanHost(srv.APIHost), host) ||
			(srv.LastPublicIPv4 != "" && strings.EqualFold(srv.LastPublicIPv4, host)) ||
			(srv.LastPublicIPv6 != "" && strings.EqualFold(srv.LastPublicIPv6, host)) ||
			(srv.LastEndpoint != "" && strings.EqualFold(cleanHost(srv.LastEndpoint), host)) {
			matchedIDs = append(matchedIDs, srv.ID)
		}
	}
	fm.mu.RUnlock()

	for _, id := range matchedIDs {
		vpsID := id
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			if fm.logger != nil {
				fm.logger.Logf("[vps-fleet] Подписка %s обновилась — проверяем клиентов на VPS %s для рассылки в ТГ", cfgName, vpsID)
			}
			_, _ = fm.RefreshServer(ctx, vpsID, false, true, "Ротация / изменение параметров на сервере")
		}()
	}
}

func (fm *VPSFleetManager) View() VPSFleetView {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	nameByID := make(map[string]string, len(fm.state.Servers))
	countByID := make(map[string]int, len(fm.state.Servers))
	for _, c := range fm.state.Clients {
		countByID[c.VPSID]++
	}

	servers := make([]VPSServerView, 0, len(fm.state.Servers))
	existingHosts := make(map[string]bool)
	for _, s := range fm.state.Servers {
		nameByID[s.ID] = s.Name
		existingHosts[strings.ToLower(cleanHost(s.APIHost))] = true
		if s.LastPublicIPv4 != "" {
			existingHosts[strings.ToLower(s.LastPublicIPv4)] = true
		}
		if s.LastPublicIPv6 != "" {
			existingHosts[strings.ToLower(s.LastPublicIPv6)] = true
		}
		redacted := s
		hasTok := strings.TrimSpace(s.AdminToken) != ""
		redacted.AdminToken = ""
		presets := fm.presetsMap[s.ID]
		if len(presets) == 0 {
			presets = DefaultVPSPresets
		}
		servers = append(servers, VPSServerView{
			VPSServer:     redacted,
			AdminTokenSet: hasTok,
			ClientCount:   countByID[s.ID],
			Presets:       presets,
		})
	}

	clients := make([]FleetClient, 0, len(fm.state.Clients))
	for _, c := range fm.state.Clients {
		cp := c
		cp.VPSName = nameByID[c.VPSID]
		clients = append(clients, cp)
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].VPSName != clients[j].VPSName {
			return clients[i].VPSName < clients[j].VPSName
		}
		return clients[i].ClientName < clients[j].ClientName
	})

	contacts := append([]TGContact(nil), fm.state.Contacts...)
	candidates := fm.discoverCandidatesLocked(existingHosts)

	return VPSFleetView{
		Servers:    servers,
		Clients:    clients,
		Contacts:   contacts,
		Candidates: candidates,
		Presets:    DefaultVPSPresets,
	}
}

func (fm *VPSFleetManager) discoverCandidatesLocked(existingHosts map[string]bool) []VPSDiscoveryCandidate {
	if fm.mgr == nil {
		return nil
	}
	cfgs, err := fm.mgr.ListConfigs()
	if err != nil {
		return nil
	}
	var subs map[string]SubscriptionConfig
	if fm.settings != nil {
		subs = fm.settings.Get().Subscriptions
	}
	seenHost := make(map[string]bool)
	var out []VPSDiscoveryCandidate
	for _, c := range cfgs {
		base := strings.TrimSuffix(c.Name, ".conf")
		if strings.EqualFold(base, "server") {
			continue
		}
		host := cleanHost(c.Endpoint)
		port := 8443
		if sub, ok := subs[c.Name]; ok {
			if sub.APIHost != "" {
				host = cleanHost(sub.APIHost)
			}
			if sub.APIPort > 0 {
				port = sub.APIPort
			}
		} else if sub, ok := subs[base]; ok {
			if sub.APIHost != "" {
				host = cleanHost(sub.APIHost)
			}
			if sub.APIPort > 0 {
				port = sub.APIPort
			}
		}
		if host == "" {
			continue
		}
		lk := strings.ToLower(host)
		if seenHost[lk] {
			continue
		}
		seenHost[lk] = true
		out = append(out, VPSDiscoveryCandidate{
			ConfigName: c.Name,
			Name:       base,
			APIHost:    host,
			APIPort:    port,
			AlreadySet: existingHosts[lk],
		})
	}
	return out
}

type UpsertVPSRequest struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	APIHost         string `json:"api_host"`
	APIPort         int    `json:"api_port"`
	UseHTTPS        *bool  `json:"use_https,omitempty"`
	TLSSkipVerify   *bool  `json:"tls_insecure,omitempty"`
	TLSPinSHA256    string `json:"tls_pin_sha256,omitempty"`
	AdminToken      string `json:"admin_token,omitempty"`
	ClearToken      bool   `json:"clear_admin_token,omitempty"`
	PollIntervalMin int    `json:"poll_interval_min,omitempty"`
}

func (fm *VPSFleetManager) UpsertServer(req UpsertVPSRequest) (VPSServerView, error) {
	host := cleanHost(req.APIHost)
	if host == "" {
		return VPSServerView{}, fmt.Errorf("укажите IP или домен VPS")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = host
	}
	port := req.APIPort
	if port <= 0 || port > 65535 {
		port = 8443
	}
	poll := req.PollIntervalMin
	if poll <= 0 {
		poll = 15
	}
	if poll > 10080 {
		poll = 10080
	}
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.TLSPinSHA256), ":", ""))
	if pin != "" && len(pin) != 64 {
		return VPSServerView{}, fmt.Errorf("TLS SHA256 отпечаток должен содержать 64 hex-символа")
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	idx := -1
	if req.ID != "" {
		for i := range fm.state.Servers {
			if fm.state.Servers[i].ID == req.ID {
				idx = i
				break
			}
		}
	}

	var srv VPSServer
	if idx >= 0 {
		srv = fm.state.Servers[idx]
		srv.Name = name
		srv.APIHost = host
		srv.APIPort = port
		srv.PollIntervalMin = poll
		srv.TLSPinSHA256 = pin
		if req.UseHTTPS != nil {
			srv.UseHTTPS = *req.UseHTTPS
		}
		if req.TLSSkipVerify != nil {
			srv.TLSSkipVerify = *req.TLSSkipVerify
		}
		if req.ClearToken {
			srv.AdminToken = ""
		} else if tok := strings.TrimSpace(req.AdminToken); tok != "" {
			srv.AdminToken = tok
		}
		fm.state.Servers[idx] = srv
	} else {
		useHTTPS := true
		if req.UseHTTPS != nil {
			useHTTPS = *req.UseHTTPS
		}
		skipVerify := true
		if req.TLSSkipVerify != nil {
			skipVerify = *req.TLSSkipVerify
		}
		srv = VPSServer{
			ID:              fleetRandID("vps_"),
			Name:            name,
			APIHost:         host,
			APIPort:         port,
			UseHTTPS:        useHTTPS,
			TLSSkipVerify:   skipVerify,
			TLSPinSHA256:    pin,
			AdminToken:      strings.TrimSpace(req.AdminToken),
			PollIntervalMin: poll,
		}
		fm.state.Servers = append(fm.state.Servers, srv)
	}

	if err := fm.saveLocked(); err != nil {
		return VPSServerView{}, err
	}
	redacted := srv
	hasTok := srv.AdminToken != ""
	redacted.AdminToken = ""
	return VPSServerView{VPSServer: redacted, AdminTokenSet: hasTok, Presets: DefaultVPSPresets}, nil
}

func (fm *VPSFleetManager) DeleteServer(vpsID string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	found := false
	nextSrvs := fm.state.Servers[:0]
	for _, s := range fm.state.Servers {
		if s.ID == vpsID {
			found = true
			continue
		}
		nextSrvs = append(nextSrvs, s)
	}
	if !found {
		return fmt.Errorf("сервер не найден")
	}
	fm.state.Servers = nextSrvs
	nextClients := fm.state.Clients[:0]
	for _, c := range fm.state.Clients {
		if c.VPSID == vpsID {
			continue
		}
		nextClients = append(nextClients, c)
	}
	fm.state.Clients = nextClients
	delete(fm.presetsMap, vpsID)
	return fm.saveLocked()
}

// Contacts CRUD
func (fm *VPSFleetManager) UpsertContact(c TGContact) (TGContact, error) {
	c.Name = strings.TrimSpace(c.Name)
	c.ChatID = strings.TrimSpace(c.ChatID)
	if c.Name == "" || c.ChatID == "" {
		return TGContact{}, fmt.Errorf("укажите имя и Telegram chat_id")
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if c.ID != "" {
		for i := range fm.state.Contacts {
			if fm.state.Contacts[i].ID == c.ID {
				fm.state.Contacts[i] = c
				return c, fm.saveLocked()
			}
		}
	}
	c.ID = fleetRandID("tg_")
	fm.state.Contacts = append(fm.state.Contacts, c)
	return c, fm.saveLocked()
}

func (fm *VPSFleetManager) DeleteContact(id string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	next := fm.state.Contacts[:0]
	for _, c := range fm.state.Contacts {
		if c.ID == id {
			continue
		}
		next = append(next, c)
	}
	fm.state.Contacts = next
	return fm.saveLocked()
}

func (fm *VPSFleetManager) getServer(vpsID string) (VPSServer, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	for _, s := range fm.state.Servers {
		if s.ID == vpsID {
			return s, nil
		}
	}
	return VPSServer{}, fmt.Errorf("VPS '%s' не найден", vpsID)
}

func buildVPSBaseURL(srv VPSServer) string {
	scheme := "https"
	if !srv.UseHTTPS {
		scheme = "http"
	}
	host := cleanHost(srv.APIHost)
	port := srv.APIPort
	if port <= 0 {
		port = 8443
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("%s://[%s]:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func buildVPSSubURL(srv VPSServer, token string) string {
	if token == "" {
		return ""
	}
	host := cleanHost(srv.APIHost)
	port := srv.APIPort
	if port <= 0 {
		port = 8443
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("http://[%s]:%d/sub/%s", host, port, token)
	}
	return fmt.Sprintf("http://%s:%d/sub/%s", host, port, token)
}

func newVPSHTTPClient(srv VPSServer, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: srv.TLSSkipVerify || srv.TLSPinSHA256 != "",
	}
	if pin := strings.ToLower(strings.TrimSpace(srv.TLSPinSHA256)); pin != "" {
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("сервер не прислал TLS-сертификат")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("несовпадение TLS SHA256 отпечатка: получен %s", got[:16]+"…")
			}
			return nil
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func (fm *VPSFleetManager) doVPSRequest(ctx context.Context, srv VPSServer, method, path string, reqBody any, ifNoneMatch string, timeout time.Duration) (int, []byte, string, error) {
	if strings.TrimSpace(srv.AdminToken) == "" {
		return 0, nil, "", fmt.Errorf("для VPS %s не задан Admin-токен (awg_adm_...)", srv.Name)
	}
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, "", err
		}
		bodyReader = bytes.NewReader(b)
	}
	fullURL := buildVPSBaseURL(srv) + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(srv.AdminToken))
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	cli := newVPSHTTPClient(srv, timeout)
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, "", fmt.Errorf("ошибка подключения к VPS %s: %w", srv.Name, err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	etag := strings.Trim(resp.Header.Get("ETag"), `" `)

	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil, etag, nil
	}
	if resp.StatusCode >= 400 {
		var apiErr remoteClientsResp
		_ = json.Unmarshal(respBytes, &apiErr)
		msg := strings.TrimSpace(apiErr.Message)
		if msg == "" {
			msg = strings.TrimSpace(apiErr.Error)
		}
		if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/api/v1/") {
			msg = "на VPS устаревшая версия api.py — выполните: sudo awg-manager update"
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return resp.StatusCode, respBytes, etag, fmt.Errorf("VPS %s (%d): %s", srv.Name, resp.StatusCode, msg)
	}
	return resp.StatusCode, respBytes, etag, nil
}

func (fm *VPSFleetManager) getVPSLock(vpsID string) *sync.Mutex {
	v, _ := fm.syncLocks.LoadOrStore(vpsID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (fm *VPSFleetManager) applyServerAndClientsSnapshot(vpsID string, meta *remoteServerMeta, remoteClients []remoteClientItem, reqErr error) (changedClients []FleetClient) {
	var srvName string
	var pollFail int
	var resolvedSrv bool
	fm.mu.Lock()
	now := time.Now()
	srvIdx := -1
	for i := range fm.state.Servers {
		if fm.state.Servers[i].ID == vpsID {
			srvIdx = i
			srvName = fm.state.Servers[i].Name
			break
		}
	}
	if srvIdx < 0 {
		fm.mu.Unlock()
		return nil
	}
	fm.state.Servers[srvIdx].LastCheckedAt = now
	if reqErr != nil {
		fm.state.Servers[srvIdx].LastError = reqErr.Error()
		fm.pollFailures[vpsID]++
		pollFail = fm.pollFailures[vpsID]
		_ = fm.saveLocked()
		fm.mu.Unlock()
		if pollFail >= 3 && fm.tg != nil {
			fm.tg.OpenIncident("vps:"+vpsID, TGKindWarn, "VPS-сервер недоступен",
				fmt.Sprintf("Сервер: <b>%s</b>\nОшибок опроса подряд: %d\n<code>%s</code>",
					html.EscapeString(srvName), pollFail, html.EscapeString(truncateUTF8(reqErr.Error(), 240))))
		}
		return nil
	}
	if fm.pollFailures[vpsID] > 0 {
		resolvedSrv = true
	}
	fm.pollFailures[vpsID] = 0
	fm.state.Servers[srvIdx].LastError = ""
	if meta != nil {
		fm.state.Servers[srvIdx].LastServerETag = meta.ServerETag
		fm.state.Servers[srvIdx].LastPreset = meta.Preset
		fm.state.Servers[srvIdx].LastPort = meta.ListenPort
		fm.state.Servers[srvIdx].LastEndpoint = meta.Endpoint
		fm.state.Servers[srvIdx].LastEndpointMode = meta.EndpointMode
		fm.state.Servers[srvIdx].LastPublicIPv4 = meta.PublicIPv4
		fm.state.Servers[srvIdx].LastPublicIPv6 = meta.PublicIPv6
		if len(meta.Presets) > 0 {
			fm.presetsMap[vpsID] = meta.Presets
		}
	}

	deliveryEnabled := fm.settings == nil || normalizeTGDeliveryMode(fm.settings.Get().TGDeliveryMode) != "off"
	if remoteClients != nil {
		existing := make(map[string]FleetClient)
		var others []FleetClient
		for _, c := range fm.state.Clients {
			if c.VPSID == vpsID {
				existing[c.ClientName] = c
			} else {
				others = append(others, c)
			}
		}

		merged := make([]FleetClient, 0, len(remoteClients))
		for _, rc := range remoteClients {
			cur := existing[rc.Name]
			cur.ID = fleetClientKey(vpsID, rc.Name)
			cur.VPSID = vpsID
			cur.ClientName = rc.Name
			cur.SubToken = rc.Token
			cur.IPv4 = rc.IPv4
			cur.IPv6 = rc.IPv6
			cur.Endpoint = rc.Endpoint
			cur.EndpointMode = rc.EndpointMode
			cur.EndpointHost = rc.EndpointHost
			cur.DNS = rc.DNS
			cur.MTU = rc.MTU
			cur.AllowedIPs = rc.AllowedIPs
			cur.Keepalive = rc.Keepalive
			cur.IsOnline = rc.IsOnline
			cur.HandshakeAge = rc.HandshakeAgeSec
			cur.RxBytes = rc.RxBytes
			cur.TxBytes = rc.TxBytes
			cur.LastETag = rc.ETag

			if deliveryEnabled && cur.TGAutoSend && !cur.AutoSendPaused &&
				strings.TrimSpace(cur.TGChatID) != "" &&
				cur.LastETag != "" && cur.LastETag != cur.LastSentETag &&
				(cur.AutoSendNextRetry.IsZero() || !now.Before(cur.AutoSendNextRetry)) {
				changedClients = append(changedClients, cur)
			}
			merged = append(merged, cur)
		}
		fm.state.Clients = append(others, merged...)
	}

	_ = fm.saveLocked()
	fm.mu.Unlock()

	if resolvedSrv && fm.tg != nil {
		fm.tg.ResolveIncident("vps:"+vpsID, "VPS-сервер снова доступен", "Сервер: <b>"+html.EscapeString(srvName)+"</b>")
	}
	return changedClients
}

// RefreshServer fetches server status and clients list from a VPS.
// When notifyChanges is true, any client with TGAutoSend=true whose ETag changed since LastSentETag
// automatically receives the new QR + .conf + vpn:// via the container's Telegram bot.
func (fm *VPSFleetManager) RefreshServer(ctx context.Context, vpsID string, useETag, notifyChanges bool, reason string) (int, error) {
	vmu := fm.getVPSLock(vpsID)
	vmu.Lock()
	defer vmu.Unlock()

	srv, err := fm.getServer(vpsID)
	if err != nil {
		return 0, err
	}
	ifNoneMatch := ""
	if useETag && srv.LastServerETag != "" {
		ifNoneMatch = `"` + srv.LastServerETag + `"`
	}

	status, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodGet, "/api/v1/clients", nil, ifNoneMatch, 20*time.Second)
	if err != nil {
		fm.applyServerAndClientsSnapshot(vpsID, nil, nil, err)
		return 0, err
	}
	if status == http.StatusNotModified {
		var wasDown bool
		fm.mu.Lock()
		for i := range fm.state.Servers {
			if fm.state.Servers[i].ID == vpsID {
				fm.state.Servers[i].LastCheckedAt = time.Now()
				fm.state.Servers[i].LastError = ""
				break
			}
		}
		if fm.pollFailures[vpsID] > 0 {
			wasDown = true
			fm.pollFailures[vpsID] = 0
		}
		_ = fm.saveLocked()
		fm.mu.Unlock()
		if wasDown && fm.tg != nil {
			fm.tg.ResolveIncident("vps:"+vpsID, "VPS-сервер снова доступен", "Сервер: <b>"+html.EscapeString(srv.Name)+"</b>")
		}
		return 0, nil
	}

	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		fm.applyServerAndClientsSnapshot(vpsID, nil, nil, err)
		return 0, err
	}

	changed := fm.applyServerAndClientsSnapshot(vpsID, parsed.Server, parsed.Clients, nil)
	sentCount := 0
	if notifyChanges && len(changed) > 0 {
		sentCount = fm.notifyClientsBatch(ctx, srv, changed, reason)
	}
	return sentCount, nil
}

func (fm *VPSFleetManager) notifyClientsBatch(ctx context.Context, srv VPSServer, clients []FleetClient, reason string) int {
	if fm.tg == nil {
		return 0
	}
	sent := 0
	var failedLines []string
	for i, c := range clients {
		if i > 0 {
			select {
			case <-ctx.Done():
				return sent
			case <-time.After(50 * time.Millisecond):
			}
		}
		if err := fm.sendClientToTelegramInternal(ctx, srv.ID, c.ClientName, reason, false); err == nil {
			sent++
		} else {
			failedLines = append(failedLines, fmt.Sprintf("• <code>%s</code>: %s", html.EscapeString(c.ClientName), html.EscapeString(truncateUTF8(err.Error(), 120))))
			if fm.logger != nil {
				fm.logger.Logf("[vps-fleet] WARN не удалось отправить конфиг %s (%s) в ТГ %s: %v", c.ClientName, srv.Name, c.TGChatID, err)
			}
		}
	}
	if sent > 0 && fm.logger != nil {
		fm.logger.Logf("[vps-fleet] Разосланы обновлённые конфиги в ТГ: %d клиент(ов) с VPS %s (%s)", sent, srv.Name, reason)
	}
	if len(failedLines) > 0 {
		body := fmt.Sprintf("Сервер: <b>%s</b>\nПричина: %s\nДоставлено: <b>%d/%d</b>\nОшибки:\n%s",
			html.EscapeString(srv.Name), html.EscapeString(reason), sent, len(clients), strings.Join(failedLines, "\n"))
		fm.tg.Notify(TGKindWarn, "vps_batch_err:"+srv.ID, "Ошибки массовой рассылки клиентам", body)
	} else if sent > 0 && len(clients) > 1 {
		body := fmt.Sprintf("Сервер: <b>%s</b>\nПричина: %s\nДоставлено всем: <b>%d/%d</b>",
			html.EscapeString(srv.Name), html.EscapeString(reason), sent, len(clients))
		fm.tg.Notify(TGKindConfig, "vps_batch_ok:"+srv.ID, "Массовая рассылка клиентам выполнена", body)
	}
	return sent
}

func (fm *VPSFleetManager) GetClientConfig(ctx context.Context, vpsID, clientName string) (VPSClientConfigPayload, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return VPSClientConfigPayload{}, err
	}
	path := "/api/v1/clients/" + url.PathEscape(clientName)
	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodGet, path, nil, "", 20*time.Second)
	if err != nil {
		return VPSClientConfigPayload{}, err
	}
	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return VPSClientConfigPayload{}, err
	}
	if parsed.Client == nil {
		return VPSClientConfigPayload{}, fmt.Errorf("сервер не вернул данные клиента %s", clientName)
	}
	rc := parsed.Client

	fm.mu.Lock()
	var fc FleetClient
	foundIdx := -1
	for i := range fm.state.Clients {
		if fm.state.Clients[i].VPSID == vpsID && fm.state.Clients[i].ClientName == rc.Name {
			fc = fm.state.Clients[i]
			foundIdx = i
			break
		}
	}
	fc.ID = fleetClientKey(vpsID, rc.Name)
	fc.VPSID = vpsID
	fc.VPSName = srv.Name
	fc.ClientName = rc.Name
	fc.SubToken = rc.Token
	fc.IPv4 = rc.IPv4
	fc.IPv6 = rc.IPv6
	fc.Endpoint = rc.Endpoint
	fc.EndpointMode = rc.EndpointMode
	fc.EndpointHost = rc.EndpointHost
	fc.DNS = rc.DNS
	fc.MTU = rc.MTU
	fc.AllowedIPs = rc.AllowedIPs
	fc.Keepalive = rc.Keepalive
	fc.IsOnline = rc.IsOnline
	fc.HandshakeAge = rc.HandshakeAgeSec
	fc.RxBytes = rc.RxBytes
	fc.TxBytes = rc.TxBytes
	fc.LastETag = rc.ETag
	if foundIdx >= 0 {
		fm.state.Clients[foundIdx] = fc
	} else {
		fm.state.Clients = append(fm.state.Clients, fc)
	}
	_ = fm.saveLocked()
	fm.mu.Unlock()

	return VPSClientConfigPayload{
		Client:   fc,
		Config:   rc.Config,
		VPNURL:   rc.VPNURL,
		SubURL:   buildVPSSubURL(srv, rc.Token),
		ETag:     rc.ETag,
		ServerOK: true,
	}, nil
}

func isFatalTGDeliveryErr(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "нажать /start") ||
		strings.Contains(low, "chat not found") ||
		strings.Contains(low, "bot was blocked") ||
		strings.Contains(low, "user is deactivated") ||
		strings.Contains(low, "топик")
}

func (fm *VPSFleetManager) recordClientSendOutcomeLocked(c *FleetClient, etag string, sendErr error) {
	now := time.Now()
	if sendErr == nil {
		c.LastSentETag = etag
		c.LastSentAt = now
		c.LastSendError = ""
		c.AutoSendFailures = 0
		c.AutoSendPaused = false
		c.AutoSendNextRetry = time.Time{}
		return
	}
	c.LastSendError = sendErr.Error()
	c.AutoSendFailures++
	if isFatalTGDeliveryErr(sendErr) && c.AutoSendFailures >= 3 {
		c.AutoSendPaused = true
		c.AutoSendNextRetry = time.Time{}
	} else if c.AutoSendFailures >= 5 {
		c.AutoSendPaused = true
		c.AutoSendNextRetry = time.Time{}
	} else {
		backoffMin := 15 * c.AutoSendFailures
		if backoffMin > 120 {
			backoffMin = 120
		}
		c.AutoSendNextRetry = now.Add(time.Duration(backoffMin) * time.Minute)
	}
}

func (fm *VPSFleetManager) ResetClientTGState(vpsID, clientName string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for i := range fm.state.Clients {
		if fm.state.Clients[i].VPSID == vpsID && fm.state.Clients[i].ClientName == clientName {
			fm.state.Clients[i].AutoSendFailures = 0
			fm.state.Clients[i].AutoSendPaused = false
			fm.state.Clients[i].AutoSendNextRetry = time.Time{}
			fm.state.Clients[i].LastSendError = ""
			return fm.saveLocked()
		}
	}
	return fmt.Errorf("клиент %s не найден", clientName)
}

func (fm *VPSFleetManager) SendClientToTelegram(ctx context.Context, vpsID, clientName, reason string) error {
	return fm.sendClientToTelegramInternal(ctx, vpsID, clientName, reason, true)
}

func (fm *VPSFleetManager) sendClientToTelegramInternal(ctx context.Context, vpsID, clientName, reason string, isCreation bool) error {
	if fm.tg == nil {
		return fmt.Errorf("сервис Telegram недоступен")
	}
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return err
	}
	payload, err := fm.GetClientConfig(ctx, vpsID, clientName)
	if err != nil {
		return err
	}
	chatID := strings.TrimSpace(payload.Client.TGChatID)
	if chatID == "" {
		return fmt.Errorf("для клиента '%s' не задан Telegram chat_id", clientName)
	}

	sendErr := fm.tg.SendClientConfigWithOptions(
		ctx,
		chatID,
		payload.Client.TGThreadID,
		srv.Name,
		clientName,
		reason,
		payload.Config,
		payload.VPNURL,
		payload.SubURL,
		isCreation,
	)

	fm.mu.Lock()
	for i := range fm.state.Clients {
		if fm.state.Clients[i].VPSID == vpsID && fm.state.Clients[i].ClientName == clientName {
			fm.recordClientSendOutcomeLocked(&fm.state.Clients[i], payload.ETag, sendErr)
			break
		}
	}
	_ = fm.saveLocked()
	fm.mu.Unlock()

	return sendErr
}

type CreateVPSClientRequest struct {
	Name       string `json:"name"`
	DNS        string `json:"dns,omitempty"`
	MTU        string `json:"mtu,omitempty"`
	AllowedIPs string `json:"allowed_ips,omitempty"`
	Keepalive  string `json:"keepalive,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"` // "server" | "ipv4" | "ipv6" | "<domain>"
	TGChatID   string `json:"tg_chat_id,omitempty"`
	TGThreadID int    `json:"tg_thread_id,omitempty"`
	TGLabel    string `json:"tg_label,omitempty"`
	TGAutoSend bool   `json:"tg_auto_send"`
	SendNow    bool   `json:"send_now"`
}

func (fm *VPSFleetManager) CreateClient(ctx context.Context, vpsID string, req CreateVPSClientRequest) (VPSClientConfigPayload, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return VPSClientConfigPayload{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return VPSClientConfigPayload{}, fmt.Errorf("укажите имя клиента")
	}

	remoteReq := map[string]any{"name": name}
	if strings.TrimSpace(req.DNS) != "" {
		remoteReq["dns"] = strings.TrimSpace(req.DNS)
	}
	if strings.TrimSpace(req.MTU) != "" {
		remoteReq["mtu"] = strings.TrimSpace(req.MTU)
	}
	if strings.TrimSpace(req.AllowedIPs) != "" {
		remoteReq["allowed_ips"] = strings.TrimSpace(req.AllowedIPs)
	}
	if strings.TrimSpace(req.Keepalive) != "" {
		remoteReq["keepalive"] = strings.TrimSpace(req.Keepalive)
	}
	if strings.TrimSpace(req.Endpoint) != "" {
		remoteReq["endpoint"] = strings.TrimSpace(req.Endpoint)
	}

	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodPost, "/api/v1/clients", remoteReq, "", 30*time.Second)
	if err != nil {
		return VPSClientConfigPayload{}, err
	}
	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return VPSClientConfigPayload{}, err
	}
	if parsed.Client == nil {
		return VPSClientConfigPayload{}, fmt.Errorf("сервер не вернул созданного клиента")
	}
	rc := parsed.Client

	fc := FleetClient{
		ID:           fleetClientKey(vpsID, rc.Name),
		VPSID:        vpsID,
		VPSName:      srv.Name,
		ClientName:   rc.Name,
		SubToken:     rc.Token,
		IPv4:         rc.IPv4,
		IPv6:         rc.IPv6,
		Endpoint:     rc.Endpoint,
		EndpointMode: rc.EndpointMode,
		EndpointHost: rc.EndpointHost,
		DNS:          rc.DNS,
		MTU:          rc.MTU,
		AllowedIPs:   rc.AllowedIPs,
		Keepalive:    rc.Keepalive,
		LastETag:     rc.ETag,
		TGChatID:     strings.TrimSpace(req.TGChatID),
		TGThreadID:   req.TGThreadID,
		TGLabel:      strings.TrimSpace(req.TGLabel),
		TGAutoSend:   req.TGAutoSend,
	}
	if !req.SendNow && fc.TGChatID != "" && rc.ETag != "" {
		fc.LastSentETag = rc.ETag
	}

	fm.mu.Lock()
	if parsed.Server != nil {
		for i := range fm.state.Servers {
			if fm.state.Servers[i].ID == vpsID {
				fm.state.Servers[i].LastServerETag = parsed.Server.ServerETag
				fm.state.Servers[i].LastCheckedAt = time.Now()
				break
			}
		}
	}
	replaced := false
	for i := range fm.state.Clients {
		if fm.state.Clients[i].VPSID == vpsID && fm.state.Clients[i].ClientName == rc.Name {
			fm.state.Clients[i] = fc
			replaced = true
			break
		}
	}
	if !replaced {
		fm.state.Clients = append(fm.state.Clients, fc)
	}
	_ = fm.saveLocked()
	fm.mu.Unlock()

	res := VPSClientConfigPayload{
		Client:   fc,
		Config:   rc.Config,
		VPNURL:   rc.VPNURL,
		SubURL:   buildVPSSubURL(srv, rc.Token),
		ETag:     rc.ETag,
		ServerOK: true,
	}

	if req.SendNow && fc.TGChatID != "" && fm.tg != nil {
		sErr := fm.tg.SendClientConfigWithOptions(ctx, fc.TGChatID, fc.TGThreadID, srv.Name, rc.Name, "Новый VPN-профиль", rc.Config, rc.VPNURL, res.SubURL, true)
		if sErr != nil {
			res.TGError = sErr.Error()
		} else {
			res.TGSent = true
		}
		fm.mu.Lock()
		for i := range fm.state.Clients {
			if fm.state.Clients[i].ID == fc.ID {
				fm.recordClientSendOutcomeLocked(&fm.state.Clients[i], rc.ETag, sErr)
				res.Client = fm.state.Clients[i]
				break
			}
		}
		_ = fm.saveLocked()
		fm.mu.Unlock()
	}
	return res, nil
}

type UpdateVPSClientRequest struct {
	Rename      string  `json:"rename,omitempty"`
	DNS         *string `json:"dns,omitempty"`
	MTU         *string `json:"mtu,omitempty"`
	AllowedIPs  *string `json:"allowed_ips,omitempty"`
	Keepalive   *string `json:"keepalive,omitempty"`
	Endpoint    *string `json:"endpoint,omitempty"`
	Rekey       bool    `json:"rekey,omitempty"`
	RotateToken bool    `json:"rotate_token,omitempty"`

	TGChatID   *string `json:"tg_chat_id,omitempty"`
	TGThreadID *int    `json:"tg_thread_id,omitempty"`
	TGLabel    *string `json:"tg_label,omitempty"`
	TGAutoSend *bool   `json:"tg_auto_send,omitempty"`
	SendNow    bool    `json:"send_now,omitempty"`
}

func (fm *VPSFleetManager) UpdateClient(ctx context.Context, vpsID, clientName string, req UpdateVPSClientRequest) (VPSClientConfigPayload, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return VPSClientConfigPayload{}, err
	}

	remotePatch := map[string]any{}
	if rn := strings.TrimSpace(req.Rename); rn != "" && rn != clientName {
		remotePatch["rename"] = rn
	}
	if req.DNS != nil {
		remotePatch["dns"] = strings.TrimSpace(*req.DNS)
	}
	if req.MTU != nil && strings.TrimSpace(*req.MTU) != "" {
		remotePatch["mtu"] = strings.TrimSpace(*req.MTU)
	}
	if req.AllowedIPs != nil && strings.TrimSpace(*req.AllowedIPs) != "" {
		remotePatch["allowed_ips"] = strings.TrimSpace(*req.AllowedIPs)
	}
	if req.Keepalive != nil && strings.TrimSpace(*req.Keepalive) != "" {
		remotePatch["keepalive"] = strings.TrimSpace(*req.Keepalive)
	}
	if req.Endpoint != nil {
		remotePatch["endpoint"] = strings.TrimSpace(*req.Endpoint)
	}
	if req.Rekey {
		remotePatch["rekey"] = true
	}
	if req.RotateToken {
		remotePatch["rotate_token"] = true
	}

	finalName := clientName
	var remoteItem *remoteClientItem
	var remoteMeta *remoteServerMeta
	configChanged := false

	if len(remotePatch) > 0 {
		path := "/api/v1/clients/" + url.PathEscape(clientName)
		_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodPatch, path, remotePatch, "", 30*time.Second)
		if err != nil {
			return VPSClientConfigPayload{}, err
		}
		var parsed remoteClientsResp
		if err := json.Unmarshal(body, &parsed); err != nil {
			return VPSClientConfigPayload{}, err
		}
		remoteItem = parsed.Client
		remoteMeta = parsed.Server
		if remoteItem != nil && remoteItem.Name != "" {
			finalName = remoteItem.Name
		}
		configChanged = true
	}

	fm.mu.Lock()
	if remoteMeta != nil {
		for i := range fm.state.Servers {
			if fm.state.Servers[i].ID == vpsID {
				fm.state.Servers[i].LastServerETag = remoteMeta.ServerETag
				fm.state.Servers[i].LastCheckedAt = time.Now()
				break
			}
		}
	}
	idx := -1
	for i := range fm.state.Clients {
		if fm.state.Clients[i].VPSID == vpsID && fm.state.Clients[i].ClientName == clientName {
			idx = i
			break
		}
	}
	var fc FleetClient
	if idx >= 0 {
		fc = fm.state.Clients[idx]
	} else {
		fc.VPSID = vpsID
	}
	fc.ClientName = finalName
	fc.ID = fleetClientKey(vpsID, finalName)
	fc.VPSName = srv.Name
	if remoteItem != nil {
		fc.SubToken = remoteItem.Token
		fc.IPv4 = remoteItem.IPv4
		fc.IPv6 = remoteItem.IPv6
		fc.Endpoint = remoteItem.Endpoint
		fc.EndpointMode = remoteItem.EndpointMode
		fc.EndpointHost = remoteItem.EndpointHost
		fc.DNS = remoteItem.DNS
		fc.MTU = remoteItem.MTU
		fc.AllowedIPs = remoteItem.AllowedIPs
		fc.Keepalive = remoteItem.Keepalive
		fc.LastETag = remoteItem.ETag
	}
	tgTargetChanged := false
	if req.TGChatID != nil {
		nextChat := strings.TrimSpace(*req.TGChatID)
		if nextChat != fc.TGChatID {
			tgTargetChanged = true
		}
		fc.TGChatID = nextChat
	}
	if req.TGThreadID != nil {
		if *req.TGThreadID != fc.TGThreadID {
			tgTargetChanged = true
		}
		fc.TGThreadID = *req.TGThreadID
	}
	if req.TGLabel != nil {
		fc.TGLabel = strings.TrimSpace(*req.TGLabel)
	}
	if req.TGAutoSend != nil {
		if *req.TGAutoSend && !fc.TGAutoSend {
			tgTargetChanged = true
		}
		fc.TGAutoSend = *req.TGAutoSend
	}
	if tgTargetChanged {
		fc.AutoSendFailures = 0
		fc.AutoSendPaused = false
		fc.AutoSendNextRetry = time.Time{}
		fc.LastSendError = ""
	}
	if !req.SendNow && !configChanged && fc.TGChatID != "" && fc.LastSentETag == "" && fc.LastETag != "" {
		fc.LastSentETag = fc.LastETag
	}
	if idx >= 0 {
		fm.state.Clients[idx] = fc
	} else {
		fm.state.Clients = append(fm.state.Clients, fc)
	}
	_ = fm.saveLocked()
	fm.mu.Unlock()

	var res VPSClientConfigPayload
	if remoteItem != nil && remoteItem.Config != "" {
		res = VPSClientConfigPayload{
			Client:   fc,
			Config:   remoteItem.Config,
			VPNURL:   remoteItem.VPNURL,
			SubURL:   buildVPSSubURL(srv, remoteItem.Token),
			ETag:     remoteItem.ETag,
			ServerOK: true,
		}
	} else {
		res = VPSClientConfigPayload{Client: fc, ETag: fc.LastETag, SubURL: buildVPSSubURL(srv, fc.SubToken), ServerOK: true}
	}

	shouldSend := (req.SendNow || (configChanged && fc.TGAutoSend && res.ETag != "" && res.ETag != fc.LastSentETag)) && fc.TGChatID != ""
	if shouldSend {
		if err := fm.sendClientToTelegramInternal(ctx, vpsID, finalName, "Обновление параметров профиля", req.SendNow); err != nil {
			res.TGError = err.Error()
		} else {
			res.TGSent = true
		}
	}
	return res, nil
}

func (fm *VPSFleetManager) DeleteClient(ctx context.Context, vpsID, clientName string) error {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return err
	}
	path := "/api/v1/clients/" + url.PathEscape(clientName)
	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodDelete, path, nil, "", 25*time.Second)
	if err != nil {
		return err
	}
	var parsed remoteClientsResp
	_ = json.Unmarshal(body, &parsed)

	fm.mu.Lock()
	defer fm.mu.Unlock()
	if parsed.Server != nil {
		for i := range fm.state.Servers {
			if fm.state.Servers[i].ID == vpsID {
				fm.state.Servers[i].LastServerETag = parsed.Server.ServerETag
				fm.state.Servers[i].LastCheckedAt = time.Now()
				break
			}
		}
	}
	next := fm.state.Clients[:0]
	for _, c := range fm.state.Clients {
		if c.VPSID == vpsID && c.ClientName == clientName {
			continue
		}
		next = append(next, c)
	}
	fm.state.Clients = next
	return fm.saveLocked()
}

// syncLocalTunnelsForVPS triggers immediate ForceSync on all local router tunnels pointing to this VPS.
func (fm *VPSFleetManager) syncLocalTunnelsForVPS(srv VPSServer) {
	if fm.subMgr == nil || fm.settings == nil {
		return
	}
	st := fm.settings.Get()
	matchHosts := map[string]bool{}
	for _, h := range []string{srv.APIHost, srv.LastPublicIPv4, srv.LastPublicIPv6, srv.LastEndpoint} {
		if ch := strings.ToLower(cleanHost(h)); ch != "" {
			matchHosts[ch] = true
		}
	}
	for cfgName, sub := range st.Subscriptions {
		eff := fm.subMgr.EffectiveURL(sub, cfgName)
		effHost := strings.ToLower(cleanHost(eff))
		if effHost != "" && matchHosts[effHost] {
			name := cfgName
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				_ = fm.subMgr.SyncForce(ctx, name)
			}()
		}
	}
}

type ServerActionResult struct {
	Server       *remoteServerMeta `json:"server"`
	NotifiedTG   int               `json:"notified_tg"`
	ClientCount  int               `json:"client_count"`
	LocalSynced  bool              `json:"local_synced"`
	Output       string            `json:"output,omitempty"`
}

func (fm *VPSFleetManager) SwitchServerEndpoint(ctx context.Context, vpsID, target string, resetOverrides bool) (ServerActionResult, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return ServerActionResult{}, err
	}
	payload := map[string]any{"target": strings.TrimSpace(target), "all": resetOverrides}
	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodPost, "/api/v1/server/endpoint", payload, "", 40*time.Second)
	if err != nil {
		return ServerActionResult{}, err
	}
	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ServerActionResult{}, err
	}
	changed := fm.applyServerAndClientsSnapshot(vpsID, parsed.Server, parsed.Clients, nil)
	fm.syncLocalTunnelsForVPS(srv)
	sent := fm.notifyClientsBatch(ctx, srv, changed, fmt.Sprintf("Смена внешнего Endpoint сервера (%s)", target))
	return ServerActionResult{
		Server:      parsed.Server,
		NotifiedTG:  sent,
		ClientCount: len(parsed.Clients),
		LocalSynced: true,
		Output:      parsed.Output,
	}, nil
}

func (fm *VPSFleetManager) ApplyServerPreset(ctx context.Context, vpsID, preset, customPort, customI1 string) (ServerActionResult, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return ServerActionResult{}, err
	}
	payload := map[string]any{"preset": strings.TrimSpace(preset)}
	if customPort != "" {
		payload["port"] = strings.TrimSpace(customPort)
	}
	if customI1 != "" {
		payload["i1"] = strings.TrimSpace(customI1)
	}
	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodPost, "/api/v1/server/preset", payload, "", 60*time.Second)
	if err != nil {
		return ServerActionResult{}, err
	}
	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ServerActionResult{}, err
	}
	changed := fm.applyServerAndClientsSnapshot(vpsID, parsed.Server, parsed.Clients, nil)
	fm.syncLocalTunnelsForVPS(srv)
	sent := fm.notifyClientsBatch(ctx, srv, changed, fmt.Sprintf("Смена маскировки сервера на %s", preset))
	return ServerActionResult{
		Server:      parsed.Server,
		NotifiedTG:  sent,
		ClientCount: len(parsed.Clients),
		LocalSynced: true,
		Output:      parsed.Output,
	}, nil
}

func (fm *VPSFleetManager) RotateServer(ctx context.Context, vpsID, preset string) (ServerActionResult, error) {
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return ServerActionResult{}, err
	}
	payload := map[string]any{}
	if strings.TrimSpace(preset) != "" {
		payload["preset"] = strings.TrimSpace(preset)
	}
	_, body, _, err := fm.doVPSRequest(ctx, srv, http.MethodPost, "/api/v1/server/rotate", payload, "", 60*time.Second)
	if err != nil {
		return ServerActionResult{}, err
	}
	var parsed remoteClientsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ServerActionResult{}, err
	}
	changed := fm.applyServerAndClientsSnapshot(vpsID, parsed.Server, parsed.Clients, nil)
	fm.syncLocalTunnelsForVPS(srv)
	sent := fm.notifyClientsBatch(ctx, srv, changed, "Ротация сервера (новый порт, ключи и обфускация)")
	return ServerActionResult{
		Server:      parsed.Server,
		NotifiedTG:  sent,
		ClientCount: len(parsed.Clients),
		LocalSynced: true,
		Output:      parsed.Output,
	}, nil
}

// ImportClientToRouter imports a remote VPS client as a local router tunnel profile with auto-linked Subscription.
func (fm *VPSFleetManager) ImportClientToRouter(ctx context.Context, vpsID, clientName, localName string, activate bool) (string, error) {
	if fm.mgr == nil || fm.settings == nil {
		return "", fmt.Errorf("локальный менеджер туннелей недоступен")
	}
	srv, err := fm.getServer(vpsID)
	if err != nil {
		return "", err
	}
	payload, err := fm.GetClientConfig(ctx, vpsID, clientName)
	if err != nil {
		return "", err
	}
	if err := ValidateConfig(payload.Config); err != nil {
		return "", fmt.Errorf("конфиг не прошёл валидацию: %w", err)
	}
	target := strings.TrimSpace(localName)
	if target == "" {
		target = clientName
	}
	if !strings.HasSuffix(target, ".conf") {
		target += ".conf"
	}
	if err := fm.mgr.SaveConfig(target, payload.Config); err != nil {
		return "", err
	}
	if payload.Client.SubToken != "" {
		sub := SubscriptionConfig{
			Token:         payload.Client.SubToken,
			APIPort:       srv.APIPort,
			APIHost:       srv.APIHost,
			AutoUpdate:    true,
			IntervalMin:   30,
			SyncOnFailure: true,
			LastSync:      time.Now(),
			LastStatus:    "ok",
			LastETag:      payload.ETag,
		}
		_, _ = fm.settings.SetSubscription(target, sub)
	}
	if activate {
		_ = fm.mgr.ActivateConfig(target)
	}
	return target, nil
}
