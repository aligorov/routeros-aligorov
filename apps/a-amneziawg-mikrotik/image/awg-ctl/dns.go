package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type DNSForwarder struct {
	listenAddr string
	fallback   []string
	mu         sync.RWMutex
	upstreams  []string
	logger     *RingLogger
}

func NewDNSForwarder(listenAddr string, fallbackRaw string, logger *RingLogger) *DNSForwarder {
	var fb []string
	for _, s := range strings.Split(fallbackRaw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		fb = append(fb, s)
	}
	if len(fb) == 0 {
		fb = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return &DNSForwarder{
		listenAddr: listenAddr,
		fallback:   fb,
		upstreams:  fb,
		logger:     logger,
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
	out := make([]string, len(d.upstreams))
	copy(out, d.upstreams)
	return out
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
	d.logger.Logf("DNS forwarder listening on %s (udp+tcp), upstreams=%v", d.listenAddr, d.Upstreams())

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
			resp, err := d.exchangeUDP(pkt)
			if err != nil || len(resp) == 0 {
				return
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

func (d *DNSForwarder) exchangeUDP(query []byte) ([]byte, error) {
	var lastErr error
	for _, up := range d.Upstreams() {
		conn, err := net.DialTimeout("udp", up, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		resp := make([]byte, 4096)
		n, err := conn.Read(resp)
		_ = conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return resp[:n], nil
	}
	return nil, lastErr
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
	resp, err := d.exchangeTCP(query)
	if err != nil || len(resp) == 0 {
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	_, _ = client.Write(lenBuf[:])
	_, _ = client.Write(resp)
}

func (d *DNSForwarder) exchangeTCP(query []byte) ([]byte, error) {
	var lastErr error
	for _, up := range d.Upstreams() {
		conn, err := net.DialTimeout("tcp", up, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		if _, err := conn.Write(query); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		rLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if rLen <= 0 || rLen > 65535 {
			_ = conn.Close()
			continue
		}
		resp := make([]byte, rLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		_ = conn.Close()
		return resp, nil
	}
	return nil, lastErr
}
