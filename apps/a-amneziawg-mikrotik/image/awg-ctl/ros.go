package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ROSSyncStatus struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url,omitempty"`
	LastSync  string `json:"last_sync,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Routes    int    `json:"routes_synced"`
	Domains   int    `json:"domains_synced"`
}

type ROSClient struct {
	baseURL     string
	user        string
	pass        string
	gatewayIP   string
	forwardDNS  string
	addrList    string
	syncRoutes  bool
	syncDomains bool
	httpClient  *http.Client
	domainsFile string
	logger      *RingLogger

	mu     sync.Mutex
	status ROSSyncStatus
}

func NewROSClient(cfgDir string, logger *RingLogger) *ROSClient {
	rawURL := strings.TrimRight(strings.TrimSpace(os.Getenv("ROS_URL")), "/")
	user := strings.TrimSpace(os.Getenv("ROS_USER"))
	pass := os.Getenv("ROS_PASS")
	insecure := envOr("ROS_TLS_INSECURE", "true") == "true"

	c := &ROSClient{
		baseURL:     rawURL,
		user:        user,
		pass:        pass,
		gatewayIP:   envOr("ROS_CONTAINER_IP", "192.168.253.2"),
		forwardDNS:  envOr("ROS_FORWARD_DNS", "AmneziaWGRoS"),
		addrList:    envOr("ROS_ADDRESS_LIST", "AmneziaWGRoS"),
		syncRoutes:  envOr("ROS_SYNC_ROUTES", "on") == "on",
		syncDomains: envOr("ROS_SYNC_DOMAINS", "on") == "on",
		domainsFile: filepath.Join(cfgDir, "domains.txt"),
		logger:      logger,
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
			},
		},
	}
	if rawURL != "" && user != "" {
		c.status.Enabled = true
		c.status.URL = rawURL
	}
	return c
}

func (c *ROSClient) Configure(s AppSettings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = strings.TrimRight(strings.TrimSpace(s.ROSURL), "/")
	c.user = strings.TrimSpace(s.ROSUser)
	c.pass = s.ROSPass
	if strings.TrimSpace(s.ROSContainerIP) != "" {
		c.gatewayIP = strings.TrimSpace(s.ROSContainerIP)
	}
	if strings.TrimSpace(s.ROSForwardDNS) != "" {
		c.forwardDNS = strings.TrimSpace(s.ROSForwardDNS)
	}
	if strings.TrimSpace(s.ROSAddressList) != "" {
		c.addrList = strings.TrimSpace(s.ROSAddressList)
	}
	c.syncRoutes = s.ROSSyncRoutes
	c.syncDomains = s.ROSSyncDomains
	c.httpClient = &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: s.ROSTLSSkipVerify}, //nolint:gosec
		},
	}
	c.status.Enabled = c.baseURL != "" && c.user != ""
	c.status.URL = c.baseURL
}

func (c *ROSClient) Status() ROSSyncStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *ROSClient) ReadDomains() ([]string, error) {
	b, err := os.ReadFile(c.domainsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(normalizeLF(string(b)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	return out, nil
}

func (c *ROSClient) SaveDomains(raw string) error {
	var clean []string
	seen := map[string]bool{}
	for _, line := range strings.Split(normalizeLF(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if !seen[line] {
			seen[line] = true
			clean = append(clean, line)
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.domainsFile), 0o700); err != nil {
		return err
	}
	data := strings.Join(clean, "\n")
	if data != "" {
		data += "\n"
	}
	return os.WriteFile(c.domainsFile, []byte(data), 0o600)
}

func (c *ROSClient) do(method, path string, body any) ([]byte, int, error) {
	c.mu.Lock()
	baseURL := c.baseURL
	user := c.user
	pass := c.pass
	client := c.httpClient
	c.mu.Unlock()

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	url := baseURL + "/rest" + path
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(user, pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return data, resp.StatusCode, fmt.Errorf("REST %s %s -> HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, resp.StatusCode, nil
}

func (c *ROSClient) SyncAll(mgr *TunnelManager) error {
	if !c.Status().Enabled {
		return nil
	}
	var routesCount, domainsCount int
	var errs []string

	if c.syncRoutes {
		n, err := c.syncAllowedRoutes(mgr.AllNonDefaultAllowedIPs())
		routesCount = n
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if c.syncDomains {
		domains, err := c.ReadDomains()
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			n, err := c.syncDNSDomains(domains)
			domainsCount = n
			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	c.mu.Lock()
	c.status.LastSync = time.Now().UTC().Format(time.RFC3339)
	c.status.Routes = routesCount
	c.status.Domains = domainsCount
	c.status.LastError = strings.Join(errs, "; ")
	c.mu.Unlock()

	if len(errs) > 0 {
		err := fmt.Errorf("%s", strings.Join(errs, "; "))
		c.logger.Logf("ROS sync error: %v", err)
		return err
	}
	c.logger.Logf("ROS sync OK (routes=%d, domains=%d)", routesCount, domainsCount)
	return nil
}

func (c *ROSClient) syncAllowedRoutes(byIface map[string][]string) (int, error) {
	raw, _, err := c.do(http.MethodGet, "/ip/route", nil)
	if err != nil {
		return 0, err
	}
	var existing []map[string]any
	if err := json.Unmarshal(raw, &existing); err != nil {
		return 0, err
	}

	desired := map[string]string{} // dst-address -> comment
	for iface, cidrs := range byIface {
		comment := "awg-ctl:" + iface
		for _, cidr := range cidrs {
			desired[cidr] = comment
		}
	}

	present := map[string]bool{}
	for _, r := range existing {
		comment, _ := r["comment"].(string)
		if !strings.HasPrefix(comment, "awg-ctl:") {
			continue
		}
		id, _ := r[".id"].(string)
		dst, _ := r["dst-address"].(string)
		gw, _ := r["gateway"].(string)
		wantComment, ok := desired[dst]
		if ok && wantComment == comment && gw == c.gatewayIP {
			present[dst] = true
			continue
		}
		if id != "" {
			_, _, _ = c.do(http.MethodDelete, "/ip/route/"+id, nil)
		}
	}

	for dst, comment := range desired {
		if present[dst] {
			continue
		}
		_, _, err := c.do(http.MethodPut, "/ip/route", map[string]any{
			"dst-address": dst,
			"gateway":     c.gatewayIP,
			"comment":     comment,
		})
		if err != nil {
			return len(present), err
		}
		present[dst] = true
	}
	return len(desired), nil
}

func (c *ROSClient) syncDNSDomains(domains []string) (int, error) {
	raw, _, err := c.do(http.MethodGet, "/ip/dns/static", nil)
	if err != nil {
		return 0, err
	}
	var existing []map[string]any
	if err := json.Unmarshal(raw, &existing); err != nil {
		return 0, err
	}

	desired := map[string]bool{}
	for _, d := range domains {
		desired[d] = true
	}

	present := map[string]bool{}
	for _, r := range existing {
		comment, _ := r["comment"].(string)
		if comment != "awg-ctl" {
			continue
		}
		id, _ := r[".id"].(string)
		name, _ := r["name"].(string)
		fwd, _ := r["forward-to"].(string)
		if desired[name] && fwd == c.gatewayIP {
			present[name] = true
			continue
		}
		if id != "" {
			_, _, _ = c.do(http.MethodDelete, "/ip/dns/static/"+id, nil)
		}
	}

	for _, name := range domains {
		if present[name] {
			continue
		}
		payload := map[string]any{
			"name":            name,
			"type":            "FWD",
			"forward-to":      c.gatewayIP,
			"match-subdomain": "yes",
			"address-list":    c.addrList,
			"comment":         "awg-ctl",
		}
		_, _, err := c.do(http.MethodPut, "/ip/dns/static", payload)
		if err != nil {
			// Fallback for RouterOS < 7.15 without address-list on FWD
			delete(payload, "address-list")
			if _, _, err2 := c.do(http.MethodPut, "/ip/dns/static", payload); err2 != nil {
				return len(present), err2
			}
		}
		present[name] = true
	}
	return len(domains), nil
}
