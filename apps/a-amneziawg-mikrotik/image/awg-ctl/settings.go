package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const AppVersion = "1.4.1"

const (
	DefaultGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	DefaultGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	DefaultTelegramAPI = "https://api.telegram.org"
)

type AppSettings struct {
	DefaultPolicy      string   `json:"default_policy"` // "proxy" | "direct"
	AutoRoute          bool     `json:"auto_route"`
	KillSwitch         bool     `json:"kill_switch"`
	MultiTunnel        bool     `json:"multi_tunnel"`
	TunnelOrder        []string `json:"tunnel_order,omitempty"`
	DisabledConfigs    []string `json:"disabled_configs,omitempty"`
	DirectDNS          string   `json:"direct_dns"`
	ProxyDNS           string   `json:"proxy_dns"`
	DNSBindTunnel      bool     `json:"dns_bind_tunnel"`
	GeoSiteURL         string   `json:"geosite_url"`
	GeoIPURL           string   `json:"geoip_url"`
	GeoAutoUpdateHours int      `json:"geo_auto_update_hours"`

	FailoverMode            string `json:"failover_mode"`              // "off" | "switch" | "standby"
	FailoverTrigger         string `json:"failover_trigger"`           // "hybrid" | "handshake" | "probe"
	FailoverIntervalSec     int    `json:"failover_interval_sec"`      // default 15
	FailoverThreshold       int    `json:"failover_threshold"`         // default 3
	FailoverHandshakeSec    int    `json:"failover_handshake_sec"`     // default 35 (initial no-handshake grace)
	FailoverHandshakeMaxAge int    `json:"failover_handshake_max_age"` // default 190 (stale handshake max age)
	FailoverCooldownSec     int    `json:"failover_cooldown_sec"`      // default 180
	FailoverProbeTarget     string `json:"failover_probe_target"`      // default "1.1.1.1:443"
	FailoverFailback        bool   `json:"failover_failback"`          // auto-return to Priority #1

	TGEnabled         bool   `json:"tg_enabled"`
	TGBotToken        string `json:"tg_bot_token,omitempty"`
	TGChatID          string `json:"tg_chat_id"`
	TGThreadID        int    `json:"tg_thread_id"`         // forum topic ID (0 = main/general)
	TGAlertThreadID   int    `json:"tg_alert_thread_id"`   // optional separate topic ID for critical failover/down alerts (0 = same as tg_thread_id)
	TGNodeName        string `json:"tg_node_name"`         // router/node label in alerts
	TGAPIURL          string `json:"tg_api_url"`           // custom Bot API mirror if needed
	TGVia             string `json:"tg_via"`               // "auto" | "direct" | "tunnel"
	TGOnStart         bool   `json:"tg_on_start"`          // notify on startup / tunnel up
	TGOnFailover      bool   `json:"tg_on_failover"`       // notify on failover switch / failback
	TGOnDown          bool   `json:"tg_on_down"`           // notify on tunnel down / error / lost handshake
	TGOnConfig        bool   `json:"tg_on_config"`         // notify on config / rules / settings changes
	TGSilent          bool   `json:"tg_silent"`            // disable_notification=true
	TGDailyDigestHour int    `json:"tg_daily_digest_hour"` // -1 = off, 0..23 = UTC/local container hour

	ROSURL           string `json:"ros_url"`
	ROSUser          string `json:"ros_user"`
	ROSPass          string `json:"ros_pass,omitempty"`
	ROSTLSSkipVerify bool   `json:"ros_tls_insecure"`
	ROSContainerIP   string `json:"ros_container_ip"`
	ROSRouteTable    string `json:"ros_route_table"`
	ROSForwardDNS    string `json:"ros_forward_dns"`
	ROSAddressList   string `json:"ros_address_list"`
	ROSSyncRoutes    bool   `json:"ros_sync_routes"`
	ROSSyncDomains   bool   `json:"ros_sync_domains"`
}

type SettingsView struct {
	AppSettings
	ROSPassSet bool `json:"ros_pass_set"`
	TGTokenSet bool `json:"tg_token_set"`
}

type SettingsUpdate struct {
	AppSettings
	ClearROSPass bool `json:"clear_ros_pass,omitempty"`
	ClearTGToken bool `json:"clear_tg_token,omitempty"`
}

type SettingsStore struct {
	path string
	mu   sync.RWMutex
	val  AppSettings
}

func defaultSettingsFromEnv() AppSettings {
	defPol := strings.ToLower(envOr("AWG_DEFAULT_POLICY", "proxy"))
	if defPol != "direct" {
		defPol = "proxy"
	}
	foMode := strings.ToLower(envOr("AWG_FAILOVER_MODE", "off"))
	if foMode != "switch" && foMode != "standby" {
		foMode = "off"
	}
	multi := envOr("AWG_MULTI_TUNNEL", "off") == "on" || foMode == "standby"
	foTrig := strings.ToLower(envOr("AWG_FAILOVER_TRIGGER", "hybrid"))
	if foTrig != "handshake" && foTrig != "probe" {
		foTrig = "hybrid"
	}
	tgThread, _ := strconv.Atoi(envOr("TG_THREAD_ID", "0"))
	tgAlertThread, _ := strconv.Atoi(envOr("TG_ALERT_THREAD_ID", "0"))
	tgToken := strings.TrimSpace(os.Getenv("TG_BOT_TOKEN"))
	tgChat := strings.TrimSpace(os.Getenv("TG_CHAT_ID"))
	tgEnabled := envOr("TG_ENABLE", "") == "on" || (tgToken != "" && tgChat != "" && envOr("TG_ENABLE", "") != "off")
	nodeName, _ := os.Hostname()
	if n := strings.TrimSpace(os.Getenv("TG_NODE_NAME")); n != "" {
		nodeName = n
	}

	return AppSettings{
		DefaultPolicy:      defPol,
		AutoRoute:          envOr("AWG_AUTO_ROUTE", "on") == "on",
		KillSwitch:         envOr("AWG_KILLSWITCH", "on") == "on",
		MultiTunnel:        multi,
		DirectDNS:          envOr("DNS_DIRECT_UPSTREAM", "77.88.8.8:53,1.1.1.1:53"),
		ProxyDNS:           envOr("DNS_UPSTREAM", "1.1.1.1:53,8.8.8.8:53"),
		DNSBindTunnel:      envOr("DNS_BIND_TUNNEL", "on") == "on",
		GeoSiteURL:         envOr("GEOSITE_URL", DefaultGeoSiteURL),
		GeoIPURL:           envOr("GEOIP_URL", DefaultGeoIPURL),
		GeoAutoUpdateHours: 0,

		FailoverMode:            foMode,
		FailoverTrigger:         foTrig,
		FailoverIntervalSec:     15,
		FailoverThreshold:       3,
		FailoverHandshakeSec:    35,
		FailoverHandshakeMaxAge: 190,
		FailoverCooldownSec:     180,
		FailoverProbeTarget:     envOr("AWG_FAILOVER_PROBE", "1.1.1.1:443"),
		FailoverFailback:        envOr("AWG_FAILOVER_FAILBACK", "off") == "on",

		TGEnabled:         tgEnabled,
		TGBotToken:        tgToken,
		TGChatID:          tgChat,
		TGThreadID:        tgThread,
		TGAlertThreadID:   tgAlertThread,
		TGNodeName:        nodeName,
		TGAPIURL:          envOr("TG_API_URL", DefaultTelegramAPI),
		TGVia:             envOr("TG_VIA", "auto"),
		TGOnStart:         true,
		TGOnFailover:      true,
		TGOnDown:          true,
		TGOnConfig:        false,
		TGSilent:          false,
		TGDailyDigestHour: -1,

		ROSURL:           normalizeROSBaseURL(os.Getenv("ROS_URL")),
		ROSUser:          strings.TrimSpace(os.Getenv("ROS_USER")),
		ROSPass:          os.Getenv("ROS_PASS"),
		ROSTLSSkipVerify: envOr("ROS_TLS_INSECURE", "true") == "true",
		ROSContainerIP:   normalizeROSContainerIP(os.Getenv("ROS_CONTAINER_IP")),
		ROSRouteTable:    strings.TrimSpace(os.Getenv("ROS_ROUTE_TABLE")),
		ROSForwardDNS:    envOr("ROS_FORWARD_DNS", "AmneziaWGRoS"),
		ROSAddressList:   envOr("ROS_ADDRESS_LIST", "AmneziaWGRoS"),
		ROSSyncRoutes:    envOr("ROS_SYNC_ROUTES", "on") == "on",
		ROSSyncDomains:   envOr("ROS_SYNC_DOMAINS", "on") == "on",
	}
}

func NewSettingsStore(cfgDir string) (*SettingsStore, error) {
	path := filepath.Join(cfgDir, "settings.json")
	st := &SettingsStore{
		path: path,
		val:  defaultSettingsFromEnv(),
	}
	b, err := os.ReadFile(path)
	if err == nil {
		loaded := st.val
		if jerr := json.Unmarshal(b, &loaded); jerr == nil {
			st.val = normalizeSettings(loaded, st.val)
		}
	} else if !os.IsNotExist(err) {
		return st, err
	}
	return st, nil
}

func clampInt(v, minV, maxV, defV int) int {
	if v == 0 {
		return defV
	}
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func normalizeSettings(s, fallback AppSettings) AppSettings {
	s.DefaultPolicy = strings.ToLower(strings.TrimSpace(s.DefaultPolicy))
	if s.DefaultPolicy != "direct" {
		s.DefaultPolicy = "proxy"
	}
	s.TunnelOrder = dedupStrings(s.TunnelOrder)
	s.DisabledConfigs = dedupStrings(s.DisabledConfigs)

	if strings.TrimSpace(s.DirectDNS) == "" {
		s.DirectDNS = fallback.DirectDNS
	}
	if strings.TrimSpace(s.ProxyDNS) == "" {
		s.ProxyDNS = fallback.ProxyDNS
	}
	if strings.TrimSpace(s.GeoSiteURL) == "" {
		s.GeoSiteURL = fallback.GeoSiteURL
	}
	if strings.TrimSpace(s.GeoIPURL) == "" {
		s.GeoIPURL = fallback.GeoIPURL
	}
	if s.GeoAutoUpdateHours < 0 {
		s.GeoAutoUpdateHours = 0
	}

	s.FailoverMode = strings.ToLower(strings.TrimSpace(s.FailoverMode))
	switch s.FailoverMode {
	case "switch":
		s.MultiTunnel = false
	case "standby":
		s.MultiTunnel = true
	default:
		s.FailoverMode = "off"
	}
	s.FailoverTrigger = strings.ToLower(strings.TrimSpace(s.FailoverTrigger))
	if s.FailoverTrigger != "handshake" && s.FailoverTrigger != "probe" {
		s.FailoverTrigger = "hybrid"
	}
	s.FailoverIntervalSec = clampInt(s.FailoverIntervalSec, 5, 300, 15)
	s.FailoverThreshold = clampInt(s.FailoverThreshold, 1, 20, 3)
	s.FailoverHandshakeSec = clampInt(s.FailoverHandshakeSec, 10, 300, 35)
	s.FailoverHandshakeMaxAge = clampInt(s.FailoverHandshakeMaxAge, 60, 600, 190)
	s.FailoverCooldownSec = clampInt(s.FailoverCooldownSec, 30, 3600, 180)
	s.FailoverProbeTarget = strings.TrimSpace(s.FailoverProbeTarget)
	if s.FailoverProbeTarget == "" {
		s.FailoverProbeTarget = "1.1.1.1:443"
	} else if _, _, err := net.SplitHostPort(s.FailoverProbeTarget); err != nil {
		s.FailoverProbeTarget = net.JoinHostPort(s.FailoverProbeTarget, "443")
	}

	s.TGBotToken = strings.TrimSpace(s.TGBotToken)
	s.TGChatID = strings.TrimSpace(s.TGChatID)
	if s.TGThreadID < 0 {
		s.TGThreadID = 0
	}
	if s.TGAlertThreadID < 0 {
		s.TGAlertThreadID = 0
	}
	s.TGNodeName = strings.TrimSpace(s.TGNodeName)
	if s.TGNodeName == "" {
		s.TGNodeName = fallback.TGNodeName
	}
	s.TGAPIURL = strings.TrimRight(strings.TrimSpace(s.TGAPIURL), "/")
	if s.TGAPIURL == "" {
		s.TGAPIURL = DefaultTelegramAPI
	}
	s.TGVia = strings.ToLower(strings.TrimSpace(s.TGVia))
	if s.TGVia != "direct" && s.TGVia != "tunnel" {
		s.TGVia = "auto"
	}
	if s.TGDailyDigestHour < -1 || s.TGDailyDigestHour > 23 {
		s.TGDailyDigestHour = -1
	}

	s.ROSURL = normalizeROSBaseURL(s.ROSURL)
	s.ROSUser = strings.TrimSpace(s.ROSUser)
	s.ROSContainerIP = normalizeROSContainerIP(s.ROSContainerIP)
	if s.ROSContainerIP == "" {
		s.ROSContainerIP = fallback.ROSContainerIP
	}
	s.ROSRouteTable = strings.TrimSpace(s.ROSRouteTable)
	if strings.TrimSpace(s.ROSForwardDNS) == "" {
		s.ROSForwardDNS = fallback.ROSForwardDNS
	}
	if strings.TrimSpace(s.ROSAddressList) == "" {
		s.ROSAddressList = fallback.ROSAddressList
	}
	return s
}

func (s *SettingsStore) Get() AppSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.val
}

func (s *SettingsStore) View() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := SettingsView{
		AppSettings: s.val,
		ROSPassSet:  s.val.ROSPass != "",
		TGTokenSet:  s.val.TGBotToken != "",
	}
	v.ROSPass = ""
	v.TGBotToken = ""
	return v
}

func (s *SettingsStore) saveLocked(next AppSettings) (AppSettings, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return s.val, err
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return s.val, err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return s.val, err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return s.val, err
	}
	s.val = next
	return s.val, nil
}

func (s *SettingsStore) Update(upd SettingsUpdate) (AppSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(upd.TunnelOrder) == 0 && len(s.val.TunnelOrder) > 0 {
		upd.TunnelOrder = append([]string(nil), s.val.TunnelOrder...)
	}
	if len(upd.DisabledConfigs) == 0 && len(s.val.DisabledConfigs) > 0 && upd.AppSettings.DisabledConfigs == nil {
		upd.DisabledConfigs = append([]string(nil), s.val.DisabledConfigs...)
	}

	next := normalizeSettings(upd.AppSettings, defaultSettingsFromEnv())
	if upd.ClearROSPass {
		next.ROSPass = ""
	} else if next.ROSPass == "" {
		next.ROSPass = s.val.ROSPass
	}
	if upd.ClearTGToken {
		next.TGBotToken = ""
	} else if next.TGBotToken == "" {
		next.TGBotToken = s.val.TGBotToken
	}

	return s.saveLocked(next)
}

func (s *SettingsStore) UpdateTunnelPlan(order, disabled []string) (AppSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.val
	if order != nil {
		next.TunnelOrder = dedupStrings(order)
	}
	if disabled != nil {
		next.DisabledConfigs = dedupStrings(disabled)
	}
	next = normalizeSettings(next, defaultSettingsFromEnv())
	return s.saveLocked(next)
}
