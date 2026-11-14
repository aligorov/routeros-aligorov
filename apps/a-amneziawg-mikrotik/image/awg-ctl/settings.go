package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const AppVersion = "1.3.0"

const (
	DefaultGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	DefaultGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
)

type AppSettings struct {
	DefaultPolicy      string `json:"default_policy"` // "proxy" | "direct"
	AutoRoute          bool   `json:"auto_route"`
	KillSwitch         bool   `json:"kill_switch"`
	MultiTunnel        bool   `json:"multi_tunnel"`
	DirectDNS          string `json:"direct_dns"`
	ProxyDNS           string `json:"proxy_dns"`
	DNSBindTunnel      bool   `json:"dns_bind_tunnel"`
	GeoSiteURL         string `json:"geosite_url"`
	GeoIPURL           string `json:"geoip_url"`
	GeoAutoUpdateHours int    `json:"geo_auto_update_hours"`

	ROSURL           string `json:"ros_url"`
	ROSUser          string `json:"ros_user"`
	ROSPass          string `json:"ros_pass,omitempty"`
	ROSTLSSkipVerify bool   `json:"ros_tls_insecure"`
	ROSContainerIP   string `json:"ros_container_ip"`
	ROSForwardDNS    string `json:"ros_forward_dns"`
	ROSAddressList   string `json:"ros_address_list"`
	ROSSyncRoutes    bool   `json:"ros_sync_routes"`
	ROSSyncDomains   bool   `json:"ros_sync_domains"`
}

type SettingsView struct {
	AppSettings
	ROSPassSet bool `json:"ros_pass_set"`
}

type SettingsUpdate struct {
	AppSettings
	ClearROSPass bool `json:"clear_ros_pass,omitempty"`
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
	return AppSettings{
		DefaultPolicy:      defPol,
		AutoRoute:          envOr("AWG_AUTO_ROUTE", "on") == "on",
		KillSwitch:         envOr("AWG_KILLSWITCH", "on") == "on",
		MultiTunnel:        envOr("AWG_MULTI_TUNNEL", "off") == "on",
		DirectDNS:          envOr("DNS_DIRECT_UPSTREAM", "77.88.8.8:53,1.1.1.1:53"),
		ProxyDNS:           envOr("DNS_UPSTREAM", "1.1.1.1:53,8.8.8.8:53"),
		DNSBindTunnel:      envOr("DNS_BIND_TUNNEL", "on") == "on",
		GeoSiteURL:         envOr("GEOSITE_URL", DefaultGeoSiteURL),
		GeoIPURL:           envOr("GEOIP_URL", DefaultGeoIPURL),
		GeoAutoUpdateHours: 0,
		ROSURL:             strings.TrimRight(strings.TrimSpace(os.Getenv("ROS_URL")), "/"),
		ROSUser:            strings.TrimSpace(os.Getenv("ROS_USER")),
		ROSPass:            os.Getenv("ROS_PASS"),
		ROSTLSSkipVerify:   envOr("ROS_TLS_INSECURE", "true") == "true",
		ROSContainerIP:     envOr("ROS_CONTAINER_IP", "192.168.253.2"),
		ROSForwardDNS:      envOr("ROS_FORWARD_DNS", "AmneziaWGRoS"),
		ROSAddressList:     envOr("ROS_ADDRESS_LIST", "AmneziaWGRoS"),
		ROSSyncRoutes:      envOr("ROS_SYNC_ROUTES", "on") == "on",
		ROSSyncDomains:     envOr("ROS_SYNC_DOMAINS", "on") == "on",
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
		var loaded AppSettings
		if jerr := json.Unmarshal(b, &loaded); jerr == nil {
			st.val = normalizeSettings(loaded, st.val)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return st, nil
}

func normalizeSettings(s, fallback AppSettings) AppSettings {
	s.DefaultPolicy = strings.ToLower(strings.TrimSpace(s.DefaultPolicy))
	if s.DefaultPolicy != "direct" {
		s.DefaultPolicy = "proxy"
	}
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
	s.ROSURL = strings.TrimRight(strings.TrimSpace(s.ROSURL), "/")
	s.ROSUser = strings.TrimSpace(s.ROSUser)
	if strings.TrimSpace(s.ROSContainerIP) == "" {
		s.ROSContainerIP = fallback.ROSContainerIP
	}
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
	}
	v.ROSPass = ""
	return v
}

func (s *SettingsStore) Update(upd SettingsUpdate) (AppSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := normalizeSettings(upd.AppSettings, defaultSettingsFromEnv())
	if upd.ClearROSPass {
		next.ROSPass = ""
	} else if next.ROSPass == "" {
		next.ROSPass = s.val.ROSPass
	}

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
