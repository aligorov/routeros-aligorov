package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	ProbeMethodTCP  = "tcp"
	ProbeMethodPing = "ping"
	ProbeMethodAny  = "any"
	ProbeMethodBoth = "both"
)

// normalizeProbeMethod normalizes failover probe method names and inspects optional target schemes.
func normalizeProbeMethod(method, target string) string {
	lowT := strings.ToLower(strings.TrimSpace(target))
	if strings.HasPrefix(lowT, "ping://") || strings.HasPrefix(lowT, "icmp://") {
		return ProbeMethodPing
	}
	switch strings.ToLower(strings.TrimSpace(method)) {
	case ProbeMethodPing, "icmp", "icmp_ping":
		return ProbeMethodPing
	case ProbeMethodAny, "auto", "tcp_or_ping", "either":
		return ProbeMethodAny
	case ProbeMethodBoth, "all", "tcp_ping", "tcp+ping", "both_ping":
		return ProbeMethodBoth
	default:
		return ProbeMethodTCP
	}
}

func stripProbeSchemeAndPath(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	for _, pref := range []string{"ping://", "icmp://", "tcp://", "http://", "https://"} {
		if strings.HasPrefix(low, pref) {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				return strings.TrimSpace(u.Host)
			}
			s = strings.TrimSpace(s[len(pref):])
			break
		}
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// extractProbeHost extracts a bare host or IP from target (removing scheme, path, port, and brackets).
func extractProbeHost(target string) string {
	s := stripProbeSchemeAndPath(target)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return strings.TrimSpace(s)
}

// normalizeTCPProbeTarget returns a host:port target suitable for TCP dial probes (default port 443).
func normalizeTCPProbeTarget(target string) string {
	s := stripProbeSchemeAndPath(target)
	if s == "" {
		return "1.1.1.1:443"
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return net.JoinHostPort(s, "443")
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildICMPEchoRequest builds an IPv4 ICMP Echo Request packet (8-byte header + nonce + timestamp/payload).
func buildICMPEchoRequest(id, seq uint16, nonce, extra []byte) []byte {
	payloadLen := len(nonce) + len(extra)
	pkt := make([]byte, 8+payloadLen)
	pkt[0] = 8 // ICMP Echo Request
	pkt[1] = 0 // Code 0
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], nonce)
	if len(extra) > 0 {
		copy(pkt[8+len(nonce):], extra)
	}
	csum := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], csum)
	return pkt
}

// parseICMPReplyPacket validates an incoming ICMPv4 packet for a specific Echo Request.
func parseICMPReplyPacket(pkt []byte, hasIPHeader bool, fromAddr, wantDst [4]byte, wantID, wantSeq uint16, wantNonce []byte, dgramMode bool) (echoReply bool, icmpErr error) {
	icmp := pkt
	if hasIPHeader {
		if len(pkt) < 20 {
			return false, nil
		}
		if (pkt[0] >> 4) != 4 {
			return false, nil
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+8 {
			return false, nil
		}
		icmp = pkt[ihl:]
	} else if len(icmp) < 8 {
		return false, nil
	}

	typ := icmp[0]
	code := icmp[1]

	switch typ {
	case 0: // Echo Reply
		if code != 0 || fromAddr != wantDst {
			return false, nil
		}
		gotID := binary.BigEndian.Uint16(icmp[4:6])
		gotSeq := binary.BigEndian.Uint16(icmp[6:8])
		if gotSeq != wantSeq {
			return false, nil
		}
		if !dgramMode && gotID != wantID {
			return false, nil
		}
		if len(wantNonce) > 0 {
			if len(icmp) < 8+len(wantNonce) || !bytes.Equal(icmp[8:8+len(wantNonce)], wantNonce) {
				return false, nil
			}
		}
		return true, nil

	case 3, 11: // Destination Unreachable, Time Exceeded
		// Payload after 8-byte ICMP error header contains original IPv4 header + 8 bytes of original ICMP header
		inner := icmp[8:]
		if len(inner) < 20+8 || (inner[0]>>4) != 4 || inner[9] != 1 {
			return false, nil
		}
		innerIHL := int(inner[0]&0x0f) * 4
		if innerIHL < 20 || len(inner) < innerIHL+8 {
			return false, nil
		}
		var innerDst [4]byte
		copy(innerDst[:], inner[16:20])
		if innerDst != wantDst {
			return false, nil
		}
		innerICMP := inner[innerIHL:]
		if innerICMP[0] != 8 || innerICMP[1] != 0 {
			return false, nil
		}
		innerID := binary.BigEndian.Uint16(innerICMP[4:6])
		innerSeq := binary.BigEndian.Uint16(innerICMP[6:8])
		if innerSeq != wantSeq || (!dgramMode && innerID != wantID) {
			return false, nil
		}
		return false, icmpErrorDescription(typ, code, fromAddr)
	}

	return false, nil
}

func icmpErrorDescription(typ, code uint8, fromAddr [4]byte) error {
	src := net.IP(fromAddr[:]).String()
	switch typ {
	case 3:
		switch code {
		case 0:
			return fmt.Errorf("сеть недостижима (ICMP net unreachable от %s)", src)
		case 1:
			return fmt.Errorf("хост недостижим (ICMP host unreachable от %s)", src)
		case 3:
			return fmt.Errorf("порт/протокол недостижим (%s)", src)
		case 13:
			return fmt.Errorf("запрещено фильтром ICMP (admin prohibited от %s)", src)
		default:
			return fmt.Errorf("ICMP unreachable type=3 code=%d от %s", code, src)
		}
	case 11:
		return fmt.Errorf("ICMP TTL exceeded от %s", src)
	default:
		return fmt.Errorf("ICMP ошибка type=%d code=%d от %s", typ, code, src)
	}
}
