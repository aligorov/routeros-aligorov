package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	bgpPort           = 179
	bgpHeaderLen      = 19
	bgpMaxMsgLen      = 4096
	bgpChunkMaxBytes  = 3750
	bgpDefaultHoldSec = 90

	bgpMsgOpen         byte = 1
	bgpMsgUpdate       byte = 2
	bgpMsgNotification byte = 3
	bgpMsgKeepalive    byte = 4
	bgpMsgRouteRefresh byte = 5
)

type ROSBGPConfig struct {
	Enabled   bool
	PeerIP    string
	PeerPort  int
	LocalAS   uint32
	RemoteAS  uint32
	NextHop   netip.Addr
	RouterID  netip.Addr
	HoldTimeS uint16
}

type ROSBGPStatus struct {
	Enabled         bool   `json:"bgp_enabled"`
	State           string `json:"bgp_state"`
	Peer            string `json:"bgp_peer,omitempty"`
	LocalAS         uint32 `json:"bgp_local_as,omitempty"`
	RemoteAS        uint32 `json:"bgp_remote_as,omitempty"`
	NextHop         string `json:"bgp_next_hop,omitempty"`
	DesiredRoutes   int    `json:"bgp_desired_routes"`
	AnnouncedRoutes int    `json:"bgp_routes"`
	UptimeSec       int64  `json:"bgp_uptime_sec"`
	LastError       string `json:"bgp_last_error,omitempty"`
	LastTransition  string `json:"bgp_last_transition,omitempty"`
}

// ROSBGPSpeaker is a pure-stdlib RFC 4271 + RFC 6793 (4-byte AS) BGP speaker
// that dials MikroTik RouterOS and incrementally announces/withdraws IPv4 prefixes.
type ROSBGPSpeaker struct {
	logger *RingLogger

	mu      sync.Mutex
	cfg     ROSBGPConfig
	desired map[netip.Prefix]struct{}

	stopCh   chan struct{}
	doneCh   chan struct{}
	notifyCh chan struct{}
	running  bool

	state          string
	establishedAt  time.Time
	announcedCount int
	lastErr        string
	lastTransition time.Time
}

func NewROSBGPSpeaker(logger *RingLogger) *ROSBGPSpeaker {
	return &ROSBGPSpeaker{
		logger:  logger,
		desired: make(map[netip.Prefix]struct{}),
		state:   "disabled",
	}
}

func (s *ROSBGPSpeaker) Configure(cfg ROSBGPConfig) {
	if cfg.PeerPort <= 0 {
		cfg.PeerPort = bgpPort
	}
	if cfg.HoldTimeS == 0 {
		cfg.HoldTimeS = bgpDefaultHoldSec
	}
	if !cfg.RouterID.IsValid() || !cfg.RouterID.Is4() {
		if cfg.NextHop.IsValid() && cfg.NextHop.Is4() {
			cfg.RouterID = cfg.NextHop
		} else {
			cfg.RouterID = netip.MustParseAddr("127.0.0.1")
		}
	}

	validCfg := cfg.Enabled && strings.TrimSpace(cfg.PeerIP) != "" && cfg.LocalAS > 0 && cfg.RemoteAS > 0 && cfg.NextHop.IsValid() && cfg.NextHop.Is4()
	if !validCfg {
		cfg.Enabled = false
	}

	s.mu.Lock()
	same := s.running == cfg.Enabled && s.cfg == cfg
	if same {
		s.mu.Unlock()
		return
	}
	prevStop := s.stopCh
	prevDone := s.doneCh
	prevRunning := s.running
	s.stopCh = nil
	s.doneCh = nil
	s.running = false
	s.cfg = cfg
	s.announcedCount = 0
	s.establishedAt = time.Time{}
	if !cfg.Enabled {
		s.state = "disabled"
		s.lastErr = ""
		s.lastTransition = time.Now().UTC()
	} else {
		s.state = "connecting"
		s.lastErr = ""
		s.lastTransition = time.Now().UTC()
	}
	s.mu.Unlock()

	if prevRunning && prevStop != nil {
		close(prevStop)
		if prevDone != nil {
			<-prevDone
		}
	}

	if !cfg.Enabled {
		return
	}

	s.mu.Lock()
	// Recheck in case Configure was called concurrently while shutting down.
	if !s.cfg.Enabled || s.cfg != cfg || s.running {
		s.mu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	notifyCh := make(chan struct{}, 1)
	s.stopCh = stopCh
	s.doneCh = doneCh
	s.notifyCh = notifyCh
	s.running = true
	s.mu.Unlock()

	go s.runLoop(cfg, stopCh, doneCh, notifyCh)
}

func (s *ROSBGPSpeaker) Close() {
	s.Configure(ROSBGPConfig{Enabled: false})
}

func (s *ROSBGPSpeaker) SetDesiredPrefixes(prefixes []netip.Prefix) {
	next := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		m := p.Masked()
		if !m.Addr().Is4() || m.Bits() <= 0 || m.Bits() > 32 {
			continue
		}
		next[m] = struct{}{}
	}

	s.mu.Lock()
	s.desired = next
	notify := s.notifyCh
	s.mu.Unlock()

	if notify != nil {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
}

func (s *ROSBGPSpeaker) Status() ROSBGPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := ""
	if s.cfg.PeerIP != "" {
		peer = net.JoinHostPort(s.cfg.PeerIP, strconv.Itoa(s.cfg.PeerPort))
	}
	nh := ""
	if s.cfg.NextHop.IsValid() {
		nh = s.cfg.NextHop.String()
	}
	var upSec int64
	if s.state == "established" && !s.establishedAt.IsZero() {
		upSec = int64(time.Since(s.establishedAt).Seconds())
	}
	trans := ""
	if !s.lastTransition.IsZero() {
		trans = s.lastTransition.UTC().Format(time.RFC3339)
	}
	return ROSBGPStatus{
		Enabled:         s.cfg.Enabled,
		State:           s.state,
		Peer:            peer,
		LocalAS:         s.cfg.LocalAS,
		RemoteAS:        s.cfg.RemoteAS,
		NextHop:         nh,
		DesiredRoutes:   len(s.desired),
		AnnouncedRoutes: s.announcedCount,
		UptimeSec:       upSec,
		LastError:       s.lastErr,
		LastTransition:  trans,
	}
}

func (s *ROSBGPSpeaker) setState(state string, announced int, errStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != state {
		s.lastTransition = time.Now().UTC()
		if state == "established" {
			s.establishedAt = time.Now().UTC()
		} else {
			s.establishedAt = time.Time{}
		}
	}
	s.state = state
	s.announcedCount = announced
	s.lastErr = errStr
}

func (s *ROSBGPSpeaker) desiredSnapshot() map[netip.Prefix]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[netip.Prefix]struct{}, len(s.desired))
	for p := range s.desired {
		out[p] = struct{}{}
	}
	return out
}

func (s *ROSBGPSpeaker) runLoop(cfg ROSBGPConfig, stopCh <-chan struct{}, doneCh chan struct{}, notifyCh <-chan struct{}) {
	defer close(doneCh)
	peerAddr := net.JoinHostPort(cfg.PeerIP, strconv.Itoa(cfg.PeerPort))
	backoff := 2 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		s.setState("connecting", 0, "")
		err := s.runSession(cfg, peerAddr, stopCh, notifyCh)
		if isStopClosed(stopCh) {
			return
		}
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
			if s.logger != nil {
				s.logger.Logf("BGP session (%s): %v", peerAddr, err)
			}
		}
		s.setState("error", 0, errMsg)

		timer := time.NewTimer(backoff)
		select {
		case <-stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 15*time.Second {
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
		}
	}
}

func isStopClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (s *ROSBGPSpeaker) runSession(cfg ROSBGPConfig, peerAddr string, stopCh <-chan struct{}, notifyCh <-chan struct{}) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", peerAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", peerAddr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}

	sessionDone := make(chan struct{})
	defer close(sessionDone)
	go func() {
		select {
		case <-stopCh:
			_ = writeAll(conn, buildBGPNotification(6, 0, nil))
			_ = conn.Close()
		case <-sessionDone:
		}
	}()
	defer conn.Close()

	// Send OPEN.
	s.setState("open_sent", 0, "")
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeAll(conn, buildBGPOpen(cfg.LocalAS, cfg.HoldTimeS, cfg.RouterID)); err != nil {
		return fmt.Errorf("send OPEN: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read peer OPEN.
	msgType, payload, err := readBGPMessage(conn, 10*time.Second)
	if err != nil {
		return fmt.Errorf("read peer OPEN: %w", err)
	}
	if msgType == bgpMsgNotification {
		return formatBGPNotification(payload)
	}
	if msgType != bgpMsgOpen {
		_ = writeAll(conn, buildBGPNotification(5, 0, nil))
		return fmt.Errorf("expected OPEN (1), got msg type %d", msgType)
	}
	peerOpen, err := parseBGPOpen(payload)
	if err != nil {
		_ = writeAll(conn, buildBGPNotification(2, 0, nil))
		return fmt.Errorf("parse peer OPEN: %w", err)
	}
	if peerOpen.Version != 4 {
		_ = writeAll(conn, buildBGPNotification(2, 1, []byte{0, 4}))
		return fmt.Errorf("unsupported peer BGP version %d", peerOpen.Version)
	}
	if cfg.RemoteAS != 0 && peerOpen.ASN != cfg.RemoteAS {
		_ = writeAll(conn, buildBGPNotification(2, 2, nil))
		return fmt.Errorf("peer AS mismatch: got %d, expected %d", peerOpen.ASN, cfg.RemoteAS)
	}

	negHold := cfg.HoldTimeS
	if peerOpen.HoldTime < negHold {
		negHold = peerOpen.HoldTime
	}
	useAS4 := peerOpen.SupportsAS4
	isIBGP := cfg.LocalAS == peerOpen.ASN

	// Send initial KEEPALIVE.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeAll(conn, buildBGPKeepalive()); err != nil {
		return fmt.Errorf("send initial KEEPALIVE: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Wait for peer KEEPALIVE to enter ESTABLISHED.
	readTimeout := 15 * time.Second
	if negHold > 0 {
		readTimeout = time.Duration(negHold) * time.Second
	}
	for {
		mType, mPayload, err := readBGPMessage(conn, readTimeout)
		if err != nil {
			return fmt.Errorf("wait KEEPALIVE: %w", err)
		}
		if mType == bgpMsgKeepalive {
			break
		}
		if mType == bgpMsgNotification {
			return formatBGPNotification(mPayload)
		}
		if mType == bgpMsgUpdate || mType == bgpMsgRouteRefresh {
			break
		}
		return fmt.Errorf("unexpected msg type %d before ESTABLISHED", mType)
	}

	if s.logger != nil {
		s.logger.Logf("BGP established with %s (peer AS%d, local AS%d, as4=%v, ibgp=%v)",
			peerAddr, peerOpen.ASN, cfg.LocalAS, useAS4, isIBGP)
	}

	announced := make(map[netip.Prefix]struct{})
	s.setState("established", 0, "")

	type incomingMsg struct {
		msgType byte
		payload []byte
		err     error
	}
	readCh := make(chan incomingMsg, 4)
	go func() {
		for {
			t, p, rErr := readBGPMessage(conn, readTimeout)
			select {
			case readCh <- incomingMsg{msgType: t, payload: p, err: rErr}:
			case <-stopCh:
				return
			case <-sessionDone:
				return
			}
			if rErr != nil {
				return
			}
		}
	}()

	var keepTicker *time.Ticker
	var keepC <-chan time.Time
	if negHold >= 3 {
		interval := time.Duration(negHold/3) * time.Second
		if interval < time.Second {
			interval = time.Second
		}
		keepTicker = time.NewTicker(interval)
		defer keepTicker.Stop()
		keepC = keepTicker.C
	}

	// Sync initial prefixes immediately upon ESTABLISHED.
	syncDiff := func(forceRefresh bool) error {
		want := s.desiredSnapshot()
		if forceRefresh {
			announced = make(map[netip.Prefix]struct{})
		}
		var withdraw []netip.Prefix
		for p := range announced {
			if _, ok := want[p]; !ok {
				withdraw = append(withdraw, p)
			}
		}
		var announce []netip.Prefix
		for p := range want {
			if _, ok := announced[p]; !ok {
				announce = append(announce, p)
			}
		}
		sortPrefixes(withdraw)
		sortPrefixes(announce)

		if len(withdraw) > 0 {
			frames := buildBGPUpdateChunks(nil, withdraw, cfg.LocalAS, cfg.NextHop, useAS4, isIBGP)
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			for _, f := range frames {
				if err := writeAll(conn, f); err != nil {
					return fmt.Errorf("write BGP withdraw UPDATE: %w", err)
				}
			}
			_ = conn.SetWriteDeadline(time.Time{})
			for _, p := range withdraw {
				delete(announced, p)
			}
		}

		if len(announce) > 0 {
			frames := buildBGPUpdateChunks(announce, nil, cfg.LocalAS, cfg.NextHop, useAS4, isIBGP)
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			for _, f := range frames {
				if err := writeAll(conn, f); err != nil {
					return fmt.Errorf("write BGP announce UPDATE: %w", err)
				}
			}
			_ = conn.SetWriteDeadline(time.Time{})
			for _, p := range announce {
				announced[p] = struct{}{}
			}
		}
		s.setState("established", len(announced), "")
		return nil
	}

	if err := syncDiff(false); err != nil {
		return err
	}

	for {
		select {
		case <-stopCh:
			return nil
		case <-notifyCh:
			if err := syncDiff(false); err != nil {
				return err
			}
		case <-keepC:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writeAll(conn, buildBGPKeepalive()); err != nil {
				return fmt.Errorf("send KEEPALIVE: %w", err)
			}
			_ = conn.SetWriteDeadline(time.Time{})
		case in := <-readCh:
			if in.err != nil {
				return fmt.Errorf("read loop: %w", in.err)
			}
			switch in.msgType {
			case bgpMsgKeepalive:
				// Healthy heartbeat.
			case bgpMsgNotification:
				return formatBGPNotification(in.payload)
			case bgpMsgRouteRefresh:
				if err := syncDiff(true); err != nil {
					return err
				}
			case bgpMsgUpdate:
				// Peer routes are ignored (speaker only announces policy routes to RouterOS).
			}
		}
	}
}

// --- Pure RFC 4271 / 4760 / 6793 Wire Encoding & Decoding ---

func wrapBGPFrame(msgType byte, payload []byte) []byte {
	total := bgpHeaderLen + len(payload)
	buf := make([]byte, total)
	for i := 0; i < 16; i++ {
		buf[i] = 0xFF
	}
	binary.BigEndian.PutUint16(buf[16:18], uint16(total))
	buf[18] = msgType
	copy(buf[bgpHeaderLen:], payload)
	return buf
}

func buildBGPKeepalive() []byte {
	return wrapBGPFrame(bgpMsgKeepalive, nil)
}

func buildBGPNotification(code, subcode byte, data []byte) []byte {
	p := make([]byte, 2+len(data))
	p[0] = code
	p[1] = subcode
	copy(p[2:], data)
	return wrapBGPFrame(bgpMsgNotification, p)
}

func buildBGPOpen(localAS uint32, holdTime uint16, routerID netip.Addr) []byte {
	var caps []byte
	// Cap 1: Multiprotocol IPv4 Unicast (AFI=1, SAFI=1)
	caps = append(caps, 1, 4, 0, 1, 0, 1)
	// Cap 2: Route Refresh (RFC 2918)
	caps = append(caps, 2, 0)
	// Cap 65: Support for 4-octet AS number (RFC 6793)
	caps = append(caps, 65, 4, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(caps[len(caps)-4:], localAS)

	optParam := make([]byte, 2+len(caps))
	optParam[0] = 2 // Capabilities Optional Parameter
	optParam[1] = byte(len(caps))
	copy(optParam[2:], caps)

	var as2 uint16
	if localAS <= 0xFFFF {
		as2 = uint16(localAS)
	} else {
		as2 = 23456 // AS_TRANS (RFC 6793)
	}

	rid4 := [4]byte{127, 0, 0, 1}
	if routerID.IsValid() && routerID.Is4() {
		rid4 = routerID.As4()
	}

	body := make([]byte, 10+len(optParam))
	body[0] = 4 // BGPv4
	binary.BigEndian.PutUint16(body[1:3], as2)
	binary.BigEndian.PutUint16(body[3:5], holdTime)
	copy(body[5:9], rid4[:])
	body[9] = byte(len(optParam))
	copy(body[10:], optParam)
	return wrapBGPFrame(bgpMsgOpen, body)
}

type bgpPeerOpen struct {
	Version     byte
	ASN         uint32
	HoldTime    uint16
	RouterID    netip.Addr
	SupportsAS4 bool
}

func parseBGPOpen(payload []byte) (bgpPeerOpen, error) {
	if len(payload) < 10 {
		return bgpPeerOpen{}, errors.New("OPEN payload too short")
	}
	out := bgpPeerOpen{
		Version:  payload[0],
		ASN:      uint32(binary.BigEndian.Uint16(payload[1:3])),
		HoldTime: binary.BigEndian.Uint16(payload[3:5]),
		RouterID: netip.AddrFrom4([4]byte{payload[5], payload[6], payload[7], payload[8]}),
	}
	optLen := int(payload[9])
	if len(payload) < 10+optLen {
		return out, errors.New("truncated OPEN optional parameters")
	}
	opts := payload[10 : 10+optLen]
	for len(opts) >= 2 {
		pType := opts[0]
		pLen := int(opts[1])
		opts = opts[2:]
		if pLen > len(opts) {
			break
		}
		pVal := opts[:pLen]
		opts = opts[pLen:]
		if pType == 2 { // Capabilities
			for len(pVal) >= 2 {
				cCode := pVal[0]
				cLen := int(pVal[1])
				pVal = pVal[2:]
				if cLen > len(pVal) {
					break
				}
				cVal := pVal[:cLen]
				pVal = pVal[cLen:]
				if cCode == 65 && cLen == 4 {
					out.SupportsAS4 = true
					out.ASN = binary.BigEndian.Uint32(cVal)
				}
			}
		}
	}
	return out, nil
}

func encodeBGPPfx(p netip.Prefix) []byte {
	m := p.Masked()
	bits := m.Bits()
	nbytes := (bits + 7) / 8
	a4 := m.Addr().As4()
	out := make([]byte, 1+nbytes)
	out[0] = byte(bits)
	copy(out[1:], a4[:nbytes])
	return out
}

func buildBGPPathAttrs(localAS uint32, nextHop netip.Addr, useAS4, isIBGP bool) []byte {
	var attrs []byte
	// 1. ORIGIN (well-known mandatory, flags=0x40, code=1, len=1, IGP=0)
	attrs = append(attrs, 0x40, 1, 1, 0)

	// 2. AS_PATH (well-known mandatory, flags=0x40, code=2)
	if isIBGP {
		attrs = append(attrs, 0x40, 2, 0)
	} else if useAS4 {
		var seg [9]byte
		seg[0] = 0x40
		seg[1] = 2
		seg[2] = 6 // 1 (type) + 1 (count) + 4 (AS4)
		seg[3] = 2 // AS_SEQUENCE
		seg[4] = 1
		binary.BigEndian.PutUint32(seg[5:9], localAS)
		attrs = append(attrs, seg[:]...)
	} else {
		as2 := uint16(localAS)
		if localAS > 0xFFFF {
			as2 = 23456
		}
		attrs = append(attrs, 0x40, 2, 4, 2, 1, byte(as2>>8), byte(as2))
	}

	// 3. NEXT_HOP (well-known mandatory, flags=0x40, code=3, len=4)
	nh := nextHop.As4()
	attrs = append(attrs, 0x40, 3, 4, nh[0], nh[1], nh[2], nh[3])

	// 4. LOCAL_PREF (required for iBGP, flags=0x40, code=5, len=4, val=100)
	if isIBGP {
		attrs = append(attrs, 0x40, 5, 4, 0, 0, 0, 100)
	}
	return attrs
}

func buildBGPUpdateChunks(announce, withdraw []netip.Prefix, localAS uint32, nextHop netip.Addr, useAS4, isIBGP bool) [][]byte {
	var frames [][]byte

	// Chunked WITHDRAW updates.
	for i := 0; i < len(withdraw); {
		var wBuf []byte
		for i < len(withdraw) {
			enc := encodeBGPPfx(withdraw[i])
			if len(wBuf)+len(enc) > bgpChunkMaxBytes && len(wBuf) > 0 {
				break
			}
			wBuf = append(wBuf, enc...)
			i++
		}
		payload := make([]byte, 4+len(wBuf))
		binary.BigEndian.PutUint16(payload[0:2], uint16(len(wBuf)))
		copy(payload[2:], wBuf)
		binary.BigEndian.PutUint16(payload[2+len(wBuf):4+len(wBuf)], 0) // Total Path Attr Len = 0
		frames = append(frames, wrapBGPFrame(bgpMsgUpdate, payload))
	}

	// Chunked ANNOUNCE updates.
	if len(announce) > 0 {
		attrs := buildBGPPathAttrs(localAS, nextHop, useAS4, isIBGP)
		maxNLRI := bgpChunkMaxBytes - len(attrs)
		if maxNLRI < 16 {
			maxNLRI = 16
		}
		for i := 0; i < len(announce); {
			var nlriBuf []byte
			for i < len(announce) {
				enc := encodeBGPPfx(announce[i])
				if len(nlriBuf)+len(enc) > maxNLRI && len(nlriBuf) > 0 {
					break
				}
				nlriBuf = append(nlriBuf, enc...)
				i++
			}
			payload := make([]byte, 4+len(attrs)+len(nlriBuf))
			binary.BigEndian.PutUint16(payload[0:2], 0) // Withdrawn Routes Len = 0
			binary.BigEndian.PutUint16(payload[2:4], uint16(len(attrs)))
			copy(payload[4:], attrs)
			copy(payload[4+len(attrs):], nlriBuf)
			frames = append(frames, wrapBGPFrame(bgpMsgUpdate, payload))
		}
	}
	return frames
}

func readBGPMessage(conn net.Conn, timeout time.Duration) (byte, []byte, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}
	var hdr [bgpHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	for i := 0; i < 16; i++ {
		if hdr[i] != 0xFF {
			return 0, nil, errors.New("invalid BGP marker")
		}
	}
	msgLen := int(binary.BigEndian.Uint16(hdr[16:18]))
	if msgLen < bgpHeaderLen || msgLen > bgpMaxMsgLen {
		return 0, nil, fmt.Errorf("invalid BGP message length %d", msgLen)
	}
	payloadLen := msgLen - bgpHeaderLen
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[18], payload, nil
}

func formatBGPNotification(payload []byte) error {
	if len(payload) < 2 {
		return errors.New("peer sent BGP NOTIFICATION")
	}
	codeName := map[byte]string{
		1: "Message Header Error",
		2: "OPEN Message Error",
		3: "UPDATE Message Error",
		4: "Hold Timer Expired",
		5: "FSM Error",
		6: "Cease",
	}[payload[0]]
	if codeName == "" {
		codeName = fmt.Sprintf("Code %d", payload[0])
	}
	return fmt.Errorf("peer BGP NOTIFICATION (%s, subcode=%d)", codeName, payload[1])
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func sortPrefixes(list []netip.Prefix) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].Masked(), list[j].Masked()
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})
}

func (s *ROSBGPSpeaker) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func parseBGPPort(v string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 65535 {
		return n
	}
	return bgpPort
}
