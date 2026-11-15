package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type DNSForwarder struct {
	listenAddr string
	fallback   []string
	mu         sync.RWMutex
	upstreams  []string
	proxyUps   []string
	directUps  []string
	policy     *PolicyEngine
	settings   *SettingsStore
	logger     *RingLogger
}

func isDoHUpstream(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://")
}

func normalizeDoHURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/dns-query"
	}
	return u.String()
}

func parseUpstreamList(raw string) []string {
	var list []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if isDoHUpstream(s) {
			list = append(list, normalizeDoHURL(s))
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		list = append(list, s)
	}
	return list
}

func NewDNSForwarder(listenAddr string, fallbackRaw string, logger *RingLogger) *DNSForwarder {
	fb := parseUpstreamList(fallbackRaw)
	if len(fb) == 0 {
		fb = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return &DNSForwarder{
		listenAddr: listenAddr,
		fallback:   fb,
		upstreams:  append([]string(nil), fb...),
		directUps:  []string{"77.88.8.8:53", "1.1.1.1:53"},
		logger:     logger,
	}
}

func (d *DNSForwarder) SetPolicy(policy *PolicyEngine, settings *SettingsStore) {
	d.mu.Lock()
	d.policy = policy
	d.settings = settings
	d.mu.Unlock()
}

func (d *DNSForwarder) ConfigureFromSettings(s AppSettings) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p := parseUpstreamList(s.ProxyDNS); len(p) > 0 {
		d.proxyUps = p
	} else {
		d.proxyUps = nil
	}
	if dir := parseUpstreamList(s.DirectDNS); len(dir) > 0 {
		d.directUps = dir
	}
}

func (d *DNSForwarder) SetUpstreams(list []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(list) > 0 {
		d.upstreams = append([]string(nil), list...)
	} else {
		d.upstreams = append([]string(nil), d.fallback...)
	}
}

func (d *DNSForwarder) Upstreams() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.upstreams) > 0 {
		out := make([]string, len(d.upstreams))
		copy(out, d.upstreams)
		return out
	}
	out := make([]string, len(d.fallback))
	copy(out, d.fallback)
	return out
}

func (d *DNSForwarder) getProxyUpstreams() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.proxyUps) > 0 {
		return append([]string(nil), d.proxyUps...)
	}
	if len(d.upstreams) > 0 {
		return append([]string(nil), d.upstreams...)
	}
	return append([]string(nil), d.fallback...)
}

func (d *DNSForwarder) getDirectUpstreams() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.directUps) > 0 {
		return append([]string(nil), d.directUps...)
	}
	return append([]string(nil), d.fallback...)
}

func (d *DNSForwarder) Start() error {
	pc, err := net.ListenPacket("udp", d.listenAddr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", d.listenAddr)
	if err != nil {
		_ = pc.Close()
		return err
	}
	d.logger.Logf("DNS forwarder listening on %s (udp+tcp), proxy=%v, direct=%v", d.listenAddr, d.getProxyUpstreams(), d.getDirectUpstreams())

	go d.serveUDP(pc)
	go d.serveTCP(ln)
	return nil
}

func (d *DNSForwarder) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func() {
			resp, err := d.handleDNSQuery(pkt, "udp")
			if err != nil || len(resp) == 0 {
				return
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

func (d *DNSForwarder) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handleTCP(conn)
	}
}

func (d *DNSForwarder) handleTCP(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
		return
	}
	qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if qLen <= 0 || qLen > 65535 {
		return
	}
	query := make([]byte, qLen)
	if _, err := io.ReadFull(client, query); err != nil {
		return
	}
	resp, err := d.handleDNSQuery(query, "tcp")
	if err != nil || len(resp) == 0 {
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	_, _ = client.Write(lenBuf[:])
	_, _ = client.Write(resp)
}

func (d *DNSForwarder) handleDNSQuery(query []byte, proto string) ([]byte, error) {
	d.mu.RLock()
	policy := d.policy
	settings := d.settings
	d.mu.RUnlock()

	qname, _, qEnd, ok := parseDNSQuestion(query)
	ups := d.Upstreams()
	action := PolicyAction("")
	matchedBy := ""
	targetTun := ""
	fwmark := 0

	if ok && policy != nil && qname != "" {
		action, matchedBy, targetTun = policy.MatchDomainTarget(qname)
		policy.NoteDNSStats(action)

		switch action {
		case ActionDrop:
			return buildDNSReplyError(query, qEnd, 3), nil // NXDOMAIN
		case ActionDirect:
			ups = d.getDirectUpstreams()
			fwmark = 0
		case ActionProxy:
			ups = d.getProxyUpstreams()
			bindTun := true
			killSwitch := false
			if settings != nil {
				st := settings.Get()
				bindTun = st.DNSBindTunnel
				killSwitch = st.KillSwitch
			}
			tun := policy.activeTunnelIface()
			if targetTun != "" && policy.activeIfaceSet()[targetTun] {
				tun = targetTun
			}
			if tun != "" && bindTun {
				fwmark = ProxyDNSFwmark
				if targetTun != "" && policy.mgr != nil {
					if m := policy.mgr.ProbeMarkForInterface(tun); m != 0 {
						fwmark = m
					}
				}
			} else if tun == "" && killSwitch && matchedBy != "default" {
				return buildDNSReplyError(query, qEnd, 2), nil // SERVFAIL: prevent leak when proxy-only domain and tunnel down
			} else if tun == "" && killSwitch {
				return buildDNSReplyError(query, qEnd, 2), nil
			}
		}
	}

	resp, err := exchangeUpstream(query, ups, fwmark, proto)
	if err != nil {
		return nil, err
	}

	if policy != nil && qname != "" && (action == ActionDirect || action == ActionProxy) {
		if ips := extractDNSAnswerIPv4s(resp); len(ips) > 0 {
			policy.RecordResolvedIPsForTarget(qname, action, matchedBy, targetTun, ips)
		}
	}
	return resp, nil
}

func exchangeUpstream(query []byte, ups []string, fwmark int, proto string) ([]byte, error) {
	var lastErr error
	for _, up := range ups {
		var resp []byte
		var err error
		if isDoHUpstream(up) {
			resp, err = exchangeSingleDoH(query, up, ups, fwmark)
		} else if proto == "tcp" {
			resp, err = exchangeSingleTCP(query, up, fwmark)
		} else {
			resp, err = exchangeSingleUDP(query, up, fwmark)
		}
		if err == nil && len(resp) >= 12 {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS upstreams succeeded")
	}
	return nil, lastErr
}

func exchangeSingleUDP(query []byte, up string, fwmark int) ([]byte, error) {
	dialer := sockMarkDialer(fwmark)
	conn, err := dialer.Dial("udp", up)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func exchangeSingleTCP(query []byte, up string, fwmark int) ([]byte, error) {
	dialer := sockMarkDialer(fwmark)
	conn, err := dialer.Dial("tcp", up)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	rLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if rLen <= 0 || rLen > 65535 {
		return nil, fmt.Errorf("invalid TCP DNS frame length %d", rLen)
	}
	resp := make([]byte, rLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type dohCacheItem struct {
	ip  string
	exp time.Time
}

var (
	dohClientMu sync.Mutex
	dohClients  = map[int]*http.Client{}
	dohBootMu   sync.Mutex
	dohBootIPs  = map[string]dohCacheItem{}
	// Overridable TLS root/skip verify only for self-signed unit test servers
	dohTestTLSConfig *tls.Config
)

func getDoHClient(bootstrapUps []string, fwmark int) *http.Client {
	dohClientMu.Lock()
	defer dohClientMu.Unlock()
	if cli, ok := dohClients[fwmark]; ok {
		return cli
	}
	baseDialer := sockBindDialer("", fwmark, 4*time.Second)
	var tlsCfg *tls.Config
	if dohTestTLSConfig != nil {
		tlsCfg = dohTestTLSConfig.Clone()
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 4 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && net.ParseIP(host) == nil {
				if resolved := bootstrapResolveDoHHost(host, bootstrapUps, fwmark); resolved != "" {
					addr = net.JoinHostPort(resolved, port)
				}
			}
			return baseDialer.DialContext(ctx, network, addr)
		},
	}
	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	dohClients[fwmark] = cli
	return cli
}

func bootstrapResolveDoHHost(host string, ups []string, fwmark int) string {
	now := time.Now()
	dohBootMu.Lock()
	if it, ok := dohBootIPs[host]; ok && now.Before(it.exp) {
		dohBootMu.Unlock()
		return it.ip
	}
	dohBootMu.Unlock()

	q := buildBootstrapAQuery(host)
	if len(q) == 0 {
		return ""
	}
	var boot []string
	for _, u := range ups {
		if !isDoHUpstream(u) {
			boot = append(boot, u)
		}
	}
	boot = append(boot, "1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53")
	for _, b := range boot {
		if resp, err := exchangeSingleUDP(q, b, fwmark); err == nil {
			if ips := extractDNSAnswerIPv4s(resp); len(ips) > 0 {
				ip := ips[0].String()
				dohBootMu.Lock()
				dohBootIPs[host] = dohCacheItem{ip: ip, exp: now.Add(5 * time.Minute)}
				dohBootMu.Unlock()
				return ip
			}
		}
	}
	// Last resort: try direct fwmark=0 bootstrap if tunnel hasn't learned route yet
	if fwmark != 0 {
		for _, b := range boot {
			if resp, err := exchangeSingleUDP(q, b, 0); err == nil {
				if ips := extractDNSAnswerIPv4s(resp); len(ips) > 0 {
					ip := ips[0].String()
					dohBootMu.Lock()
					dohBootIPs[host] = dohCacheItem{ip: ip, exp: now.Add(2 * time.Minute)}
					dohBootMu.Unlock()
					return ip
				}
			}
		}
	}
	return ""
}

func buildBootstrapAQuery(host string) []byte {
	host = strings.Trim(strings.ToLower(host), ". ")
	if host == "" {
		return nil
	}
	var buf bytes.Buffer
	var id [2]byte
	_, _ = rand.Read(id[:])
	buf.Write(id[:])
	buf.Write([]byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, lbl := range strings.Split(host, ".") {
		if len(lbl) == 0 || len(lbl) > 63 {
			return nil
		}
		buf.WriteByte(byte(len(lbl)))
		buf.WriteString(lbl)
	}
	buf.WriteByte(0)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN
	return buf.Bytes()
}

func exchangeSingleDoH(query []byte, endpoint string, allUps []string, fwmark int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	cli := getDoHClient(allUps, fwmark)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s returned HTTP %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("doh %s returned short response (%dB)", endpoint, len(body))
	}
	return body, nil
}

// --- Zero-dependency RFC1035 helpers ---

func parseDNSQuestion(pkt []byte) (qname string, qtype uint16, qEnd int, ok bool) {
	if len(pkt) < 12 {
		return "", 0, 0, false
	}
	qd := binary.BigEndian.Uint16(pkt[4:6])
	if qd == 0 {
		return "", 0, 0, false
	}
	off := 12
	var labels []string
	steps := 0
	for off < len(pkt) && steps < 128 {
		steps++
		l := int(pkt[off])
		if l == 0 {
			off++
			if off+4 > len(pkt) {
				return "", 0, 0, false
			}
			qt := binary.BigEndian.Uint16(pkt[off : off+2])
			return strings.ToLower(strings.Join(labels, ".")), qt, off + 4, true
		}
		if l&0xC0 != 0 {
			// Unusual pointer in question; bail cleanly
			return "", 0, 0, false
		}
		if l > 63 || off+1+l > len(pkt) {
			return "", 0, 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, 0, false
}

func buildDNSReplyError(query []byte, qEnd int, rcode byte) []byte {
	if len(query) < 12 || qEnd < 12 || qEnd > len(query) {
		return nil
	}
	resp := make([]byte, qEnd)
	copy(resp, query[:qEnd])
	// Preserve ID (bytes 0..1)
	// Flags: QR=1, preserve Opcode(bits 3..6) and RD(bit 0) -> byte 2 = 0x80 | (query[2] & 0x79)
	resp[2] = 0x80 | (query[2] & 0x79)
	// RA=1, Z=0, RCODE=rcode -> byte 3 = 0x80 | (rcode & 0x0f)
	resp[3] = 0x80 | (rcode & 0x0f)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT = 0
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func skipDNSName(pkt []byte, off int) (int, bool) {
	steps := 0
	for off < len(pkt) && steps < 128 {
		steps++
		l := int(pkt[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(pkt) {
				return 0, false
			}
			return off + 2, true
		}
		if l&0xC0 != 0 || l > 63 || off+1+l > len(pkt) {
			return 0, false
		}
		off += 1 + l
	}
	return 0, false
}

func extractDNSAnswerIPv4s(resp []byte) []netip.Addr {
	if len(resp) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	var ok bool
	for i := 0; i < qd; i++ {
		off, ok = skipDNSName(resp, off)
		if !ok || off+4 > len(resp) {
			return nil
		}
		off += 4
	}
	var out []netip.Addr
	for i := 0; i < an; i++ {
		off, ok = skipDNSName(resp, off)
		if !ok || off+10 > len(resp) {
			break
		}
		rrType := binary.BigEndian.Uint16(resp[off : off+2])
		rrClass := binary.BigEndian.Uint16(resp[off+2 : off+4])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10
		if off+rdLen > len(resp) {
			break
		}
		if rrType == 1 && rrClass == 1 && rdLen == 4 {
			if a, ok := netip.AddrFromSlice(resp[off : off+4]); ok {
				out = append(out, a)
			}
		}
		off += rdLen
	}
	return out
}
