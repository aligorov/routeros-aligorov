package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type DomainMatchKind uint8

const (
	DomainPlain      DomainMatchKind = 0
	DomainRegex      DomainMatchKind = 1
	DomainRootDomain DomainMatchKind = 2
	DomainFull       DomainMatchKind = 3
)

type GeoSiteCategory struct {
	Full     map[string]struct{}
	Root     map[string]struct{}
	Plains   []string
	Regexes  []*regexp.Regexp
	Count    int
}

func (c *GeoSiteCategory) Match(host string) bool {
	if c == nil {
		return false
	}
	if _, ok := c.Full[host]; ok {
		return true
	}
	if len(c.Root) > 0 {
		h := host
		for {
			if _, ok := c.Root[h]; ok {
				return true
			}
			idx := strings.IndexByte(h, '.')
			if idx < 0 || idx+1 >= len(h) {
				break
			}
			h = h[idx+1:]
		}
	}
	for _, sub := range c.Plains {
		if strings.Contains(host, sub) {
			return true
		}
	}
	for _, re := range c.Regexes {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

type GeoIPCategory struct {
	Prefixes     []netip.Prefix
	InverseMatch bool
}

func (c *GeoIPCategory) Match(addr netip.Addr) bool {
	if c == nil {
		return false
	}
	matched := false
	for _, p := range c.Prefixes {
		if p.Contains(addr) {
			matched = true
			break
		}
	}
	if c.InverseMatch {
		return !matched
	}
	return matched
}

type GeoStatus struct {
	GeoSiteLoaded     bool           `json:"geosite_loaded"`
	GeoSiteSize       int64          `json:"geosite_size"`
	GeoSiteUpdated    string         `json:"geosite_updated,omitempty"`
	GeoSiteCategories []string       `json:"geosite_categories"`
	GeoSiteCounts     map[string]int `json:"geosite_counts,omitempty"`
	GeoIPLoaded       bool           `json:"geoip_loaded"`
	GeoIPSize         int64          `json:"geoip_size"`
	GeoIPUpdated      string         `json:"geoip_updated,omitempty"`
	GeoIPCategories   []string       `json:"geoip_categories"`
	GeoIPCounts       map[string]int `json:"geoip_counts,omitempty"`
	LastError         string         `json:"last_error,omitempty"`
}

type GeoStore struct {
	dir    string
	logger *RingLogger
	client *http.Client

	mu         sync.RWMutex
	siteCounts map[string]int
	ipCounts   map[string]int
	sites      map[string]*GeoSiteCategory
	ips        map[string]*GeoIPCategory
	meta       geoMeta
	lastErr    string
}

type geoMeta struct {
	GeoSiteUpdated string `json:"geosite_updated,omitempty"`
	GeoIPUpdated   string `json:"geoip_updated,omitempty"`
}

func NewGeoStore(cfgDir string, logger *RingLogger) *GeoStore {
	dir := filepath.Join(cfgDir, "geo")
	gs := &GeoStore{
		dir:    dir,
		logger: logger,
		client: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
		siteCounts: map[string]int{},
		ipCounts:   map[string]int{},
		sites:      map[string]*GeoSiteCategory{},
		ips:        map[string]*GeoIPCategory{},
	}
	gs.loadMeta()
	return gs
}

func (g *GeoStore) sitePath() string { return filepath.Join(g.dir, "geosite.dat") }
func (g *GeoStore) ipPath() string   { return filepath.Join(g.dir, "geoip.dat") }
func (g *GeoStore) metaPath() string { return filepath.Join(g.dir, "meta.json") }

func (g *GeoStore) loadMeta() {
	b, err := os.ReadFile(g.metaPath())
	if err == nil {
		_ = json.Unmarshal(b, &g.meta)
	}
}

func (g *GeoStore) saveMeta() {
	_ = os.MkdirAll(g.dir, 0o700)
	b, err := json.MarshalIndent(g.meta, "", "  ")
	if err == nil {
		_ = os.WriteFile(g.metaPath(), b, 0o600)
	}
}

func (g *GeoStore) Status() GeoStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var siteSize, ipSize int64
	if st, err := os.Stat(g.sitePath()); err == nil {
		siteSize = st.Size()
	}
	if st, err := os.Stat(g.ipPath()); err == nil {
		ipSize = st.Size()
	}

	siteCats := make([]string, 0, len(g.siteCounts))
	for k := range g.siteCounts {
		siteCats = append(siteCats, k)
	}
	sort.Strings(siteCats)

	ipCats := make([]string, 0, len(g.ipCounts))
	for k := range g.ipCounts {
		ipCats = append(ipCats, k)
	}
	sort.Strings(ipCats)

	activeSiteCounts := map[string]int{}
	for k, v := range g.sites {
		activeSiteCounts[k] = v.Count
	}
	activeIPCounts := map[string]int{}
	for k, v := range g.ips {
		activeIPCounts[k] = len(v.Prefixes)
	}

	return GeoStatus{
		GeoSiteLoaded:     len(g.siteCounts) > 0,
		GeoSiteSize:       siteSize,
		GeoSiteUpdated:    g.meta.GeoSiteUpdated,
		GeoSiteCategories: siteCats,
		GeoSiteCounts:     activeSiteCounts,
		GeoIPLoaded:       len(g.ipCounts) > 0,
		GeoIPSize:         ipSize,
		GeoIPUpdated:      g.meta.GeoIPUpdated,
		GeoIPCategories:   ipCats,
		GeoIPCounts:       activeIPCounts,
		LastError:         g.lastErr,
	}
}

func (g *GeoStore) Reload(needSites, needIPs map[string]bool) error {
	var errs []string
	siteCounts := map[string]int{}
	sites := map[string]*GeoSiteCategory{}
	if data, err := os.ReadFile(g.sitePath()); err == nil {
		sc, parsed, perr := parseGeoSiteBlob(data, needSites)
		if perr != nil {
			errs = append(errs, fmt.Sprintf("geosite: %v", perr))
		} else {
			siteCounts = sc
			sites = parsed
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("geosite read: %v", err))
	}

	ipCounts := map[string]int{}
	ips := map[string]*GeoIPCategory{}
	if data, err := os.ReadFile(g.ipPath()); err == nil {
		ic, parsed, perr := parseGeoIPBlob(data, needIPs)
		if perr != nil {
			errs = append(errs, fmt.Sprintf("geoip: %v", perr))
		} else {
			ipCounts = ic
			ips = parsed
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("geoip read: %v", err))
	}

	g.mu.Lock()
	g.siteCounts = siteCounts
	g.sites = sites
	g.ipCounts = ipCounts
	g.ips = ips
	g.lastErr = strings.Join(errs, "; ")
	g.mu.Unlock()

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (g *GeoStore) DownloadAndReload(siteURL, ipURL string, needSites, needIPs map[string]bool) error {
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var siteErr, ipErr error
	var wg sync.WaitGroup
	if strings.TrimSpace(siteURL) != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			siteErr = g.downloadFile(siteURL, g.sitePath())
		}()
	}
	if strings.TrimSpace(ipURL) != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipErr = g.downloadFile(ipURL, g.ipPath())
		}()
	}
	wg.Wait()

	var errs []string
	g.mu.Lock()
	if strings.TrimSpace(siteURL) != "" {
		if siteErr != nil {
			errs = append(errs, fmt.Sprintf("geosite download: %v", siteErr))
		} else {
			g.meta.GeoSiteUpdated = now
		}
	}
	if strings.TrimSpace(ipURL) != "" {
		if ipErr != nil {
			errs = append(errs, fmt.Sprintf("geoip download: %v", ipErr))
		} else {
			g.meta.GeoIPUpdated = now
		}
	}
	g.mu.Unlock()
	g.saveMeta()

	if err := g.Reload(needSites, needIPs); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		g.mu.Lock()
		g.lastErr = msg
		g.mu.Unlock()
		return errors.New(msg)
	}
	g.logger.Logf("Geo databases updated (%d geosite cats, %d geoip cats)", len(g.siteCounts), len(g.ipCounts))
	return nil
}

func (g *GeoStore) downloadFile(url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "awg-ctl/"+AppVersion)
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, io.LimitReader(resp.Body, 128<<20))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (g *GeoStore) MatchSite(cat, host string) bool {
	g.mu.RLock()
	c := g.sites[strings.ToLower(cat)]
	g.mu.RUnlock()
	return c.Match(host)
}

func (g *GeoStore) MatchIP(cat string, addr netip.Addr) bool {
	g.mu.RLock()
	c := g.ips[strings.ToLower(cat)]
	g.mu.RUnlock()
	return c.Match(addr)
}

func (g *GeoStore) CategoryIPs(cat string) *GeoIPCategory {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ips[strings.ToLower(cat)]
}

// SiteSeedDomains returns a deterministic bounded sample of concrete domains from a GeoSite category.
func (g *GeoStore) SiteSeedDomains(cat string, limit int) []string {
	if g == nil || limit <= 0 {
		return nil
	}
	g.mu.RLock()
	c := g.sites[strings.ToLower(strings.TrimSpace(cat))]
	if c == nil {
		g.mu.RUnlock()
		return nil
	}
	roots := make([]string, 0, len(c.Root))
	for d := range c.Root {
		if strings.Contains(d, ".") && !strings.HasPrefix(d, ".") {
			roots = append(roots, d)
		}
	}
	fulls := make([]string, 0, len(c.Full))
	for d := range c.Full {
		if strings.Contains(d, ".") && !strings.HasPrefix(d, ".") {
			fulls = append(fulls, d)
		}
	}
	g.mu.RUnlock()

	sort.Strings(roots)
	sort.Strings(fulls)

	seen := make(map[string]struct{}, limit)
	out := make([]string, 0, limit)
	for _, list := range [][]string{roots, fulls} {
		for _, d := range list {
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// --- Zero-dependency Protobuf wire reader & plain-list fallback ---

func readVarint(b []byte) (uint64, int, bool) {
	var x uint64
	var s uint
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1, true
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0, false
}

func readProtoField(b []byte) (fieldNum int, wireType int, val []byte, varint uint64, rest []byte, ok bool) {
	tag, n, good := readVarint(b)
	if !good {
		return 0, 0, nil, 0, nil, false
	}
	b = b[n:]
	fieldNum = int(tag >> 3)
	wireType = int(tag & 0x7)
	switch wireType {
	case 0:
		v, m, g := readVarint(b)
		if !g {
			return 0, 0, nil, 0, nil, false
		}
		return fieldNum, wireType, nil, v, b[m:], true
	case 1:
		if len(b) < 8 {
			return 0, 0, nil, 0, nil, false
		}
		return fieldNum, wireType, b[:8], 0, b[8:], true
	case 2:
		l, m, g := readVarint(b)
		if !g || l > uint64(len(b)-m) {
			return 0, 0, nil, 0, nil, false
		}
		return fieldNum, wireType, b[m : m+int(l)], 0, b[m+int(l):], true
	case 5:
		if len(b) < 4 {
			return 0, 0, nil, 0, nil, false
		}
		return fieldNum, wireType, b[:4], 0, b[4:], true
	default:
		return 0, 0, nil, 0, nil, false
	}
}

func parseGeoSiteBlob(data []byte, needed map[string]bool) (map[string]int, map[string]*GeoSiteCategory, error) {
	if isLikelyTextList(data) {
		cat := parsePlainGeoSiteText(data)
		counts := map[string]int{"custom": cat.Count}
		out := map[string]*GeoSiteCategory{}
		if needed["custom"] {
			out["custom"] = cat
		}
		return counts, out, nil
	}

	counts := map[string]int{}
	out := map[string]*GeoSiteCategory{}
	rem := data
	for len(rem) > 0 {
		num, wt, val, _, next, ok := readProtoField(rem)
		if !ok {
			return nil, nil, errors.New("corrupt geosite protobuf")
		}
		rem = next
		if num != 1 || wt != 2 {
			continue
		}
		code, domCount, cat, err := parseGeoSiteEntry(val, needed)
		if err != nil {
			return nil, nil, err
		}
		if code != "" {
			counts[code] = domCount
			if cat != nil {
				out[code] = cat
			}
		}
	}
	return counts, out, nil
}

func parseGeoSiteEntry(entry []byte, needed map[string]bool) (string, int, *GeoSiteCategory, error) {
	var code string
	var domBlobs [][]byte
	rem := entry
	for len(rem) > 0 {
		num, wt, val, _, next, ok := readProtoField(rem)
		if !ok {
			return "", 0, nil, errors.New("corrupt GeoSite entry")
		}
		rem = next
		switch {
		case num == 1 && wt == 2:
			code = strings.ToLower(strings.TrimSpace(string(val)))
		case num == 2 && wt == 2:
			domBlobs = append(domBlobs, val)
		}
	}
	if code == "" {
		return "", 0, nil, nil
	}
	if !needed[code] {
		return code, len(domBlobs), nil, nil
	}
	cat := &GeoSiteCategory{
		Full:  make(map[string]struct{}),
		Root:  make(map[string]struct{}),
		Count: len(domBlobs),
	}
	for _, db := range domBlobs {
		kind, value := parseDomainMsg(db)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if kind == DomainRegex {
			if re, err := regexp.Compile(value); err == nil {
				cat.Regexes = append(cat.Regexes, re)
			}
			continue
		}
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if value == "" {
			continue
		}
		switch kind {
		case DomainFull:
			cat.Full[value] = struct{}{}
		case DomainRootDomain:
			cat.Root[value] = struct{}{}
		case DomainPlain:
			cat.Plains = append(cat.Plains, value)
		}
	}
	return code, len(domBlobs), cat, nil
}

func parseDomainMsg(b []byte) (DomainMatchKind, string) {
	var kind DomainMatchKind
	var val string
	rem := b
	for len(rem) > 0 {
		num, wt, bytesVal, uVal, next, ok := readProtoField(rem)
		if !ok {
			break
		}
		rem = next
		switch {
		case num == 1 && wt == 0:
			kind = DomainMatchKind(uVal)
		case num == 2 && wt == 2:
			val = string(bytesVal)
		}
	}
	return kind, val
}

func parseGeoIPBlob(data []byte, needed map[string]bool) (map[string]int, map[string]*GeoIPCategory, error) {
	if isLikelyTextList(data) {
		cat := parsePlainGeoIPText(data)
		counts := map[string]int{"custom": len(cat.Prefixes)}
		out := map[string]*GeoIPCategory{}
		if needed["custom"] {
			out["custom"] = cat
		}
		return counts, out, nil
	}

	counts := map[string]int{}
	out := map[string]*GeoIPCategory{}
	rem := data
	for len(rem) > 0 {
		num, wt, val, _, next, ok := readProtoField(rem)
		if !ok {
			return nil, nil, errors.New("corrupt geoip protobuf")
		}
		rem = next
		if num != 1 || wt != 2 {
			continue
		}
		code, cidrCount, cat, err := parseGeoIPEntry(val, needed)
		if err != nil {
			return nil, nil, err
		}
		if code != "" {
			counts[code] = cidrCount
			if cat != nil {
				out[code] = cat
			}
		}
	}
	return counts, out, nil
}

func parseGeoIPEntry(entry []byte, needed map[string]bool) (string, int, *GeoIPCategory, error) {
	var code string
	var cidrBlobs [][]byte
	var inverse bool
	rem := entry
	for len(rem) > 0 {
		num, wt, val, uVal, next, ok := readProtoField(rem)
		if !ok {
			return "", 0, nil, errors.New("corrupt GeoIP entry")
		}
		rem = next
		switch {
		case num == 1 && wt == 2:
			code = strings.ToLower(strings.TrimSpace(string(val)))
		case num == 2 && wt == 2:
			cidrBlobs = append(cidrBlobs, val)
		case num == 3 && wt == 0:
			inverse = uVal != 0
		}
	}
	if code == "" {
		return "", 0, nil, nil
	}
	if !needed[code] {
		return code, len(cidrBlobs), nil, nil
	}
	cat := &GeoIPCategory{
		Prefixes:     make([]netip.Prefix, 0, len(cidrBlobs)),
		InverseMatch: inverse,
	}
	for _, cb := range cidrBlobs {
		if p, ok := parseCIDRMsg(cb); ok {
			cat.Prefixes = append(cat.Prefixes, p)
		}
	}
	return code, len(cidrBlobs), cat, nil
}

func parseCIDRMsg(b []byte) (netip.Prefix, bool) {
	var ipBytes []byte
	var prefixLen uint64
	var hasPrefix bool
	rem := b
	for len(rem) > 0 {
		num, wt, val, uVal, next, ok := readProtoField(rem)
		if !ok {
			return netip.Prefix{}, false
		}
		rem = next
		switch {
		case num == 1 && wt == 2:
			ipBytes = val
		case num == 2 && wt == 0:
			prefixLen = uVal
			hasPrefix = true
		}
	}
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.Prefix{}, false
	}
	if !hasPrefix {
		prefixLen = uint64(addr.BitLen())
	}
	p := netip.PrefixFrom(addr, int(prefixLen))
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

func isLikelyTextList(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	// Protobuf GeoSiteList/GeoIPList starts with field 1 wireType 2 => tag 0x0a, wait: 0x0a is '\n'!
	// So check printable ASCII ratio when tag != 0x0a or contains newlines/hashes/dots of text.
	printable := 0
	for _, c := range sample {
		if (c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return printable == len(sample) && (bytes.Contains(sample, []byte(".")) || bytes.Contains(sample, []byte("#")))
}

func parsePlainGeoSiteText(data []byte) *GeoSiteCategory {
	cat := &GeoSiteCategory{
		Full: make(map[string]struct{}),
		Root: make(map[string]struct{}),
	}
	for _, line := range strings.Split(normalizeLF(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(line, "."), "domain:"))
		if strings.HasPrefix(line, "full:") {
			cat.Full[strings.TrimPrefix(line, "full:")] = struct{}{}
		} else {
			cat.Root[line] = struct{}{}
		}
		cat.Count++
	}
	return cat
}

func parsePlainGeoIPText(data []byte) *GeoIPCategory {
	cat := &GeoIPCategory{}
	for _, line := range strings.Split(normalizeLF(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			cat.Prefixes = append(cat.Prefixes, p.Masked())
		} else if a, err := netip.ParseAddr(line); err == nil {
			cat.Prefixes = append(cat.Prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return cat
}
