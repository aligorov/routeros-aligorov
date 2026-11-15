//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

var icmpSeqCounter atomic.Uint32

func firstIPv4OfIface(iface string) ([4]byte, bool) {
	var zero [4]byte
	if iface == "" {
		return zero, false
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return zero, false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return zero, false
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			var b [4]byte
			copy(b[:], ip4)
			return b, true
		}
	}
	return zero, false
}

func resolvePingIPv4(ctx context.Context, iface string, mark int, host string, timeout time.Duration) ([4]byte, string, error) {
	var zero [4]byte
	host = extractProbeHost(host)
	if host == "" {
		return zero, "", fmt.Errorf("пустой хост для ping")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			copy(zero[:], ip4)
			return zero, ip4.String(), nil
		}
		return zero, "", fmt.Errorf("IPv6 (%s) не поддерживается для ICMP ping через туннель", host)
	}

	rCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// When binding to a specific tunnel/interface, resolve over that interface first so
	// broken tunnels also test or respect isolated routing when DNS is needed.
	if iface != "" || mark != 0 {
		tunTimeout := timeout / 2
		if tunTimeout < 800*time.Millisecond {
			tunTimeout = 800 * time.Millisecond
		}
		tunCtx, tunCancel := context.WithTimeout(rCtx, tunTimeout)
		dialer := sockBindDialer(iface, mark, tunTimeout)
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(c context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(c, network, "1.1.1.1:53")
			},
		}
		ips, err := res.LookupIP(tunCtx, "ip4", host)
		tunCancel()
		if err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					copy(zero[:], ip4)
					return zero, ip4.String(), nil
				}
			}
		}
	}

	ips, err := net.DefaultResolver.LookupIP(rCtx, "ip4", host)
	if err != nil {
		return zero, "", fmt.Errorf("DNS не смог разрешить %s: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			copy(zero[:], ip4)
			return zero, ip4.String(), nil
		}
	}
	return zero, "", fmt.Errorf("не найден IPv4-адрес для %s", host)
}

func icmpPingHost(ctx context.Context, iface string, mark int, host string, timeout time.Duration) (int64, string, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dst4, dstStr, err := resolvePingIPv4(ctx, iface, mark, host, timeout)
	if err != nil {
		return 0, "", err
	}

	dgramMode := false
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
			if err != nil {
				return 0, dstStr, fmt.Errorf("icmp socket: %w", err)
			}
			dgramMode = true
		} else {
			return 0, dstStr, fmt.Errorf("icmp socket: %w", err)
		}
	}
	defer syscall.Close(fd)

	if iface != "" {
		if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); err != nil {
			return 0, dstStr, fmt.Errorf("SO_BINDTODEVICE(%s): %w", iface, err)
		}
		// Binding the raw socket to the interface's IPv4 guarantees source IP cannot leak to veth.
		if !dgramMode {
			if src4, ok := firstIPv4OfIface(iface); ok {
				if bErr := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: src4}); bErr != nil {
					return 0, dstStr, fmt.Errorf("bind(%s): %w", iface, bErr)
				}
			}
		}
	}
	if mark != 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
			return 0, dstStr, fmt.Errorf("SO_MARK(0x%x): %w", mark, err)
		}
	}

	seqNum := icmpSeqCounter.Add(1)
	reqID := uint16((os.Getpid()&0xff)<<8) ^ uint16(seqNum>>16) ^ 0x4157
	reqSeq := uint16(seqNum)
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
	pkt := buildICMPEchoRequest(reqID, reqSeq, nonce[:], ts[:])

	t0 := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst4}); err != nil {
		return 0, dstStr, fmt.Errorf("icmp send(%s): %w", dstStr, err)
	}

	deadline := t0.Add(timeout)
	if ctxDl, ok := ctx.Deadline(); ok && ctxDl.Before(deadline) {
		deadline = ctxDl
	}
	buf := make([]byte, 1500)

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, dstStr, ctxErr
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return 0, dstStr, fmt.Errorf("ping timeout (%s)", dstStr)
		}
		slice := rem
		if slice > 200*time.Millisecond {
			slice = 200 * time.Millisecond
		}
		tv := syscall.NsecToTimeval(slice.Nanoseconds())
		if tv.Sec == 0 && tv.Usec < 1000 {
			tv.Usec = 1000
		}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, from, rErr := syscall.Recvfrom(fd, buf, 0)
		if rErr != nil {
			if errors.Is(rErr, syscall.EAGAIN) || errors.Is(rErr, syscall.EWOULDBLOCK) || errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.ETIMEDOUT) {
				continue
			}
			return 0, dstStr, fmt.Errorf("icmp recv(%s): %w", dstStr, rErr)
		}
		sa, ok := from.(*syscall.SockaddrInet4)
		if !ok {
			continue
		}
		matched, icmpErr := parseICMPReplyPacket(buf[:n], !dgramMode, sa.Addr, dst4, reqID, reqSeq, nonce[:], dgramMode)
		if icmpErr != nil {
			return 0, dstStr, icmpErr
		}
		if matched {
			rtt := time.Since(t0).Milliseconds()
			if rtt < 1 {
				rtt = 1
			}
			return rtt, dstStr, nil
		}
	}
}
