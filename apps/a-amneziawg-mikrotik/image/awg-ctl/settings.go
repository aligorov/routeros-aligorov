package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const AppVersion = "1.7.5"

const (
	ROSModeGateway     = "gateway"
	ROSModeAddressList = "address_list"
	ROSModeBGP         = "bgp"
	ROSModeManual      = "manual"
)

const (
	DefaultGeoSiteURL  = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	DefaultGeoIPURL    = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
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
	FailoverProbeMethod     string `json:"failover_probe_method"`      // "tcp" | "ping" | "any" | "both"
	FailoverProbeTarget     string `json:"failover_probe_target"`      // default "1.1.1.1:443" (or host for ping)
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

	ROSURL               string `json:"ros_url"`
	ROSUser              string `json:"ros_user"`
	ROSPass              string `json:"ros_pass,omitempty"`
	ROSTLSSkipVerify     bool   `json:"ros_tls_insecure"`
	ROSContainerIP       string `json:"ros_container_ip"`
	ROSRouteTable        string `json:"ros_route_table"`
	ROSForwardDNS        string `json:"ros_forward_dns"`
	ROSAddressList       string `json:"ros_address_list"`
	ROSSyncRoutes        bool   `json:"ros_sync_routes"`
	ROSSyncDomains       bool   `json:"ros_sync_domains"`
	ROSMode              string `json:"ros_mode"`                // "gateway" | "address_list" | "bgp" | "manual"
	ROSUseBinaryAPI      bool   `json:"ros_use_binary_api"`      // prefer Binary API (:8728/:8729) with REST fallback
	ROSAPIPort           int    `json:"ros_api_port"`            // default 8728 (or 8729 when ros_api_tls)
	ROSAPITLS            bool   `json:"ros_api_tls"`             // enable TLS on Binary API
	ROSDynamicTimeout    string `json:"ros_dynamic_timeout"`     // RAM-only timeout for DNS-learned IPs in address-list
	ROSSyncPolicyCIDRs   bool   `json:"ros_sync_policy_cidrs"`   // sync static PROXY cidr:/geoip: into address-list
	ROSStaticPrefixLimit int    `json:"ros_static_prefix_limit"` // cap on static address-list prefixes
	ROSBGPLocalAS        uint32 `json:"ros_bgp_local_as"`        // container ASN for BGP mode
	ROSBGPRemoteAS       uint32 `json:"ros_bgp_remote_as"`       // RouterOS ASN for BGP mode
	ROSBGPPeerIP         string `json:"ros_bgp_peer_ip"`         // RouterOS BGP peer IP (empty = auto)
	ROSBGPRouteTable     string `json:"ros_bgp_route_table"`     // target routing table on RouterOS (default "main")

	AllowConfigHooks bool   `json:"allow_config_hooks"`         // permit PreUp/PostUp/PreDown/PostDown when saving .conf
	TermEnabled      bool   `json:"term_enabled"`               // enable WebUI shell terminal (/api/term/*)
	UIUser           string `json:"ui_user,omitempty"`          // WebUI username (first-run setup / override)
	UIPassHash       string `json:"ui_password_hash,omitempty"` // PBKDF2-HMAC-SHA256 WebUI password hash (never returned in View)

	Subscriptions map[string]SubscriptionConfig `json:"subscriptions,omitempty"`
}

type SubscriptionConfig struct {
	Token         string    `json:"token"`                     // Токен клиента awg_tok_...
	APIPort       int       `json:"api_port"`                  // Порт API сервера (стандартный 8443)
	APIHost       string    `json:"api_host,omitempty"`        // Кастомный IP/хост сервера (если пустой, берётся из Endpoint)
	URL           string    `json:"url,omitempty"`             // Полный URL или vpn://
	AutoUpdate    bool      `json:"auto_update"`               // Автоматическое обновление по графику
	IntervalMin   int       `json:"interval_min,omitempty"`    // График проверки в минутах (по умолчанию 30)
	SyncOnFailure bool      `json:"sync_on_failure"`           // Опрос при сбое handshake / UNHEALTHY
	LastSync      time.Time `json:"last_sync,omitempty"`       // Время последней синхронизации
	LastStatus    string    `json:"last_status,omitempty"`     // "ok", "not_modified", "error: ..."
	LastETag      string    `json:"last_etag,omitempty"`       // ETag ответа сервера
}

type SettingsView struct {
	AppSettings
	ROSPassSet       bool   `json:"ros_pass_set"`
	TGTokenSet       bool   `json:"tg_token_set"`
	UIAuthConfigured bool   `json:"ui_auth_configured"`
	UIAuthSource     string `json:"ui_auth_source,omitempty"`
	UINeedsSetup     bool   `json:"ui_needs_setup"`
	TermEnvDisabled  bool   `json:"term_env_disabled,omitempty"`
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
	foProbeRaw := envOr("AWG_FAILOVER_PROBE", "1.1.1.1:443")
	foProbeMethod := normalizeProbeMethod(envOr("AWG_FAILOVER_PROBE_METHOD", ProbeMethodTCP), foProbeRaw)
	tgThread, _ := strconv.Atoi(envOr("TG_THREAD_ID", "0"))
	tgAlertThread, _ := strconv.Atoi(envOr("TG_ALERT_THREAD_ID", "0"))
	tgToken := strings.TrimSpace(os.Getenv("TG_BOT_TOKEN"))
	tgChat := strings.TrimSpace(os.Getenv("TG_CHAT_ID"))
	tgEnabled := envOr("TG_ENABLE", "") == "on" || (tgToken != "" && tgChat != "" && envOr("TG_ENABLE", "") != "off")
	nodeName, _ := os.Hostname()
	if n := strings.TrimSpace(os.Getenv("TG_NODE_NAME")); n != "" {
		nodeName = n
	}

	rosAPITLS := envOr("ROS_API_TLS", "off") == "on"
	defAPIPort := 8728
	if rosAPITLS {
		defAPIPort = 8729
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
		FailoverProbeMethod:     foProbeMethod,
		FailoverProbeTarget:     foProbeRaw,
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

		ROSURL:               normalizeROSBaseURL(os.Getenv("ROS_URL")),
		ROSUser:              strings.TrimSpace(os.Getenv("ROS_USER")),
		ROSPass:              os.Getenv("ROS_PASS"),
		ROSTLSSkipVerify:     envOr("ROS_TLS_INSECURE", "true") == "true",
		ROSContainerIP:       normalizeROSContainerIP(os.Getenv("ROS_CONTAINER_IP")),
		ROSRouteTable:        strings.TrimSpace(os.Getenv("ROS_ROUTE_TABLE")),
		ROSForwardDNS:        envOr("ROS_FORWARD_DNS", "AmneziaWGRoS"),
		ROSAddressList:       envOr("ROS_ADDRESS_LIST", "AmneziaWGRoS"),
		ROSSyncRoutes:        envOr("ROS_SYNC_ROUTES", "on") == "on",
		ROSSyncDomains:       envOr("ROS_SYNC_DOMAINS", "on") == "on",
		ROSMode:              normalizeROSMode(envOr("ROS_MODE", ROSModeGateway)),
		ROSUseBinaryAPI:      envOr("ROS_BINARY_API", "on") != "off",
		ROSAPIPort:           clampInt(atoiDef(os.Getenv("ROS_API_PORT"), defAPIPort), 1, 65535, defAPIPort),
		ROSAPITLS:            rosAPITLS,
		ROSDynamicTimeout:    normalizeROSDynamicTimeout(envOr("ROS_DYNAMIC_TIMEOUT", "12:00:00")),
		ROSSyncPolicyCIDRs:   envOr("ROS_SYNC_POLICY_CIDRS", "on") != "off",
		ROSStaticPrefixLimit: clampInt(atoiDef(os.Getenv("ROS_STATIC_PREFIX_LIMIT"), 2500), 10, 100000, 2500),
		ROSBGPLocalAS:        uint32(clampInt(atoiDef(os.Getenv("ROS_BGP_LOCAL_AS"), 65511), 1, 2147483647, 65511)),
		ROSBGPRemoteAS:       uint32(clampInt(atoiDef(os.Getenv("ROS_BGP_REMOTE_AS"), 65510), 1, 2147483647, 65510)),
		ROSBGPPeerIP:         normalizeROSContainerIP(os.Getenv("ROS_BGP_PEER_IP")),
		ROSBGPRouteTable:     envOr("ROS_BGP_ROUTE_TABLE", "main"),

		AllowConfigHooks: envOr("AWG_ALLOW_HOOKS", "off") == "on",
		TermEnabled:      termEnvFlag() == "on",
		UIUser:           envOr("UI_USER", "admin"),
		Subscriptions:    make(map[string]SubscriptionConfig),
	}
}

func termEnvFlag() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("TERM_ENABLE")))
}

// validateHTTPURL verifies that raw uses http:// or https:// with a non-empty host and no embedded credentials.
func validateHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("допустимы только схемы http:// или https://")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("не указан хост в URL")
	}
	if u.User != nil {
		return fmt.Errorf("учётные данные в URL запрещены")
	}
	return nil
}

func atoiDef(raw string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n == 0 {
		return def
	}
	return n
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
			var rawKeys map[string]any
			if json.Unmarshal(b, &rawKeys) == nil {
				// Preserve legacy behavior when upgrading settings.json created before ros_mode existed.
				if _, ok := rawKeys["ros_mode"]; !ok && strings.TrimSpace(loaded.ROSURL) != "" {
					loaded.ROSMode = ROSModeManual
				}
				if _, ok := rawKeys["ros_use_binary_api"]; !ok {
					loaded.ROSUseBinaryAPI = st.val.ROSUseBinaryAPI
				}
				if _, ok := rawKeys["ros_sync_policy_cidrs"]; !ok {
					loaded.ROSSyncPolicyCIDRs = st.val.ROSSyncPolicyCIDRs
				}
			}
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
	if strings.TrimSpace(s.GeoSiteURL) == "" || validateHTTPURL(s.GeoSiteURL) != nil {
		s.GeoSiteURL = fallback.GeoSiteURL
	} else {
		s.GeoSiteURL = strings.TrimSpace(s.GeoSiteURL)
	}
	if strings.TrimSpace(s.GeoIPURL) == "" || validateHTTPURL(s.GeoIPURL) != nil {
		s.GeoIPURL = fallback.GeoIPURL
	} else {
		s.GeoIPURL = strings.TrimSpace(s.GeoIPURL)
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
	s.FailoverProbeMethod = normalizeProbeMethod(s.FailoverProbeMethod, s.FailoverProbeTarget)
	rawProbeTarget := strings.TrimSpace(s.FailoverProbeTarget)
	if rawProbeTarget == "" {
		if s.FailoverProbeMethod == ProbeMethodPing {
			s.FailoverProbeTarget = "1.1.1.1"
		} else {
			s.FailoverProbeTarget = "1.1.1.1:443"
		}
	} else if s.FailoverProbeMethod == ProbeMethodPing {
		if h := extractProbeHost(rawProbeTarget); h != "" {
			s.FailoverProbeTarget = h
		} else {
			s.FailoverProbeTarget = "1.1.1.1"
		}
	} else {
		s.FailoverProbeTarget = normalizeTCPProbeTarget(rawProbeTarget)
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
	if s.TGAPIURL == "" || validateHTTPURL(s.TGAPIURL) != nil {
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
	s.ROSMode = normalizeROSMode(s.ROSMode)
	defAPIPort := 8728
	if s.ROSAPITLS {
		defAPIPort = 8729
	}
	s.ROSAPIPort = clampInt(s.ROSAPIPort, 1, 65535, defAPIPort)
	s.ROSDynamicTimeout = normalizeROSDynamicTimeout(s.ROSDynamicTimeout)
	s.ROSStaticPrefixLimit = clampInt(s.ROSStaticPrefixLimit, 10, 100000, 2500)
	if s.ROSBGPLocalAS == 0 {
		s.ROSBGPLocalAS = fallback.ROSBGPLocalAS
		if s.ROSBGPLocalAS == 0 {
			s.ROSBGPLocalAS = 65511
		}
	}
	if s.ROSBGPRemoteAS == 0 {
		s.ROSBGPRemoteAS = fallback.ROSBGPRemoteAS
		if s.ROSBGPRemoteAS == 0 {
			s.ROSBGPRemoteAS = 65510
		}
	}
	s.ROSBGPPeerIP = normalizeROSContainerIP(s.ROSBGPPeerIP)
	s.ROSBGPRouteTable = strings.TrimSpace(s.ROSBGPRouteTable)
	if s.ROSBGPRouteTable == "" {
		s.ROSBGPRouteTable = "main"
	}
	if termEnvFlag() == "off" {
		s.TermEnabled = false
	} else if termEnvFlag() == "on" {
		s.TermEnabled = true
	}
	s.UIUser = strings.TrimSpace(s.UIUser)
	if s.UIUser == "" {
		s.UIUser = fallback.UIUser
		if s.UIUser == "" {
			s.UIUser = "admin"
		}
	}
	if s.Subscriptions == nil {
		if fallback.Subscriptions != nil {
			s.Subscriptions = fallback.Subscriptions
		} else {
			s.Subscriptions = make(map[string]SubscriptionConfig)
		}
	}
	return s
}

func normalizeROSMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ROSModeAddressList, "address-list", "mangle":
		return ROSModeAddressList
	case ROSModeBGP:
		return ROSModeBGP
	case ROSModeManual, "custom":
		return ROSModeManual
	case ROSModeGateway, "full":
		return ROSModeGateway
	default:
		return ROSModeGateway
	}
}

func normalizeROSDynamicTimeout(raw string) string {
	d, ok := parseROSDuration(raw)
	if !ok || d < time.Minute {
		return "12:00:00"
	}
	if d > 30*24*time.Hour {
		d = 30 * 24 * time.Hour
	}
	return formatROSDuration(d)
}

// parseROSDuration parses RouterOS timeouts (12:00:00, 1d, 2w3d, 12h30m) and clamps within bounds.
func parseROSDuration(raw string) (time.Duration, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return 0, false
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, true
	}
	// Support RouterOS compact day+time strings like "1d12:00:00" or "1w2d03:04:05"
	if colon := strings.IndexByte(s, ':'); colon > 0 {
		for idx := colon - 1; idx >= 0; idx-- {
			if s[idx] == 'd' || s[idx] == 'w' {
				s = s[:idx+1] + " " + s[idx+1:]
				break
			}
		}
	}
	var total time.Duration
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	for _, part := range fields {
		if strings.Contains(part, ":") {
			hms := strings.Split(part, ":")
			if len(hms) != 3 {
				return 0, false
			}
			hh, err1 := strconv.Atoi(hms[0])
			mm, err2 := strconv.Atoi(hms[1])
			ss, err3 := strconv.Atoi(hms[2])
			if err1 != nil || err2 != nil || err3 != nil || hh < 0 || mm < 0 || ss < 0 || mm >= 60 || ss >= 60 {
				return 0, false
			}
			total += time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute + time.Duration(ss)*time.Second
			continue
		}
		// RouterOS compact form like 1w2d3h4m5s
		idx := 0
		for idx < len(part) {
			j := idx
			for j < len(part) && part[j] >= '0' && part[j] <= '9' {
				j++
			}
			if j == idx || j >= len(part) {
				return 0, false
			}
			val, err := strconv.Atoi(part[idx:j])
			if err != nil {
				return 0, false
			}
			switch part[j] {
			case 'w':
				total += time.Duration(val) * 7 * 24 * time.Hour
			case 'd':
				total += time.Duration(val) * 24 * time.Hour
			case 'h':
				total += time.Duration(val) * time.Hour
			case 'm':
				total += time.Duration(val) * time.Minute
			case 's':
				total += time.Duration(val) * time.Second
			default:
				return 0, false
			}
			idx = j + 1
		}
	}
	return total, total > 0
}

func formatROSDuration(d time.Duration) string {
	sec := int64(d.Seconds())
	if sec < 60 {
		sec = 60
	}
	days := sec / 86400
	rem := sec % 86400
	hh := rem / 3600
	mm := (rem % 3600) / 60
	ss := rem % 60
	if days > 0 {
		if hh == 0 && mm == 0 && ss == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hh, mm, ss)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hh, mm, ss)
}

const pbkdf2Iterations = 100000

// HashPassword derives a salted PBKDF2-HMAC-SHA256 hash using only the Go stdlib.
func HashPassword(password string) (string, error) {
	if len(password) < 6 {
		return "", fmt.Errorf("пароль должен быть не короче 6 символов")
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt[:], pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt[:]),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPasswordHash checks a plaintext password against an encoded PBKDF2-HMAC-SHA256 hash.
func VerifyPasswordHash(encoded, password string) bool {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 10000 || iters > 1000000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) == 0 || len(want) == 0 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iters, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(data []byte) []byte {
		mac := hmac.New(sha256.New, password)
		mac.Write(data)
		return mac.Sum(nil)
	}
	numBlocks := (keyLen + sha256.Size - 1) / sha256.Size
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		var buf [4]byte
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		in := make([]byte, len(salt)+4)
		copy(in, salt)
		copy(in[len(salt):], buf[:])
		u := prf(in)
		out := make([]byte, len(u))
		copy(out, u)
		for i := 2; i <= iter; i++ {
			u = prf(u)
			for j := range out {
				out[j] ^= u[j]
			}
		}
		dk = append(dk, out...)
	}
	return dk[:keyLen]
}

func (s *SettingsStore) Get() AppSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.val
}

func (s *SettingsStore) View() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	envPass := strings.TrimSpace(os.Getenv("UI_PASSWORD"))
	authSource := ""
	if envPass != "" {
		authSource = "env"
	} else if s.val.UIPassHash != "" {
		authSource = "setup"
	}
	v := SettingsView{
		AppSettings:      s.val,
		ROSPassSet:       s.val.ROSPass != "",
		TGTokenSet:       s.val.TGBotToken != "",
		UIAuthConfigured: authSource != "",
		UIAuthSource:     authSource,
		UINeedsSetup:     authSource == "",
		TermEnvDisabled:  termEnvFlag() == "off",
	}
	v.ROSPass = ""
	v.TGBotToken = ""
	v.UIPassHash = ""
	return v
}

func (s *SettingsStore) SetWebAuth(user, password string) (AppSettings, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return s.val, err
	}
	user = strings.TrimSpace(user)
	if user == "" {
		user = envOr("UI_USER", "admin")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.val
	next.UIUser = user
	next.UIPassHash = hash
	next = normalizeSettings(next, defaultSettingsFromEnv())
	return s.saveLocked(next)
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
	// Auto-switch default RouterOS Binary API port 8728 <-> 8729 when TLS toggle changes.
	if !s.val.ROSAPITLS && next.ROSAPITLS && next.ROSAPIPort == 8728 {
		next.ROSAPIPort = 8729
	} else if s.val.ROSAPITLS && !next.ROSAPITLS && next.ROSAPIPort == 8729 {
		next.ROSAPIPort = 8728
	}
	// Always preserve credentials not edited directly by settings forms.
	next.UIPassHash = s.val.UIPassHash
	if strings.TrimSpace(upd.UIUser) == "" {
		next.UIUser = s.val.UIUser
	}
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

func (s *SettingsStore) SetSubscription(cfgName string, sub SubscriptionConfig) (AppSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.val
	if next.Subscriptions == nil {
		next.Subscriptions = make(map[string]SubscriptionConfig)
	}
	next.Subscriptions[cfgName] = sub
	return s.saveLocked(next)
}

func (s *SettingsStore) DeleteSubscription(cfgName string) (AppSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.val
	if next.Subscriptions != nil {
		delete(next.Subscriptions, cfgName)
	}
	return s.saveLocked(next)
}

