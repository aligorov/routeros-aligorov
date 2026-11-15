package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const rosBinMaxWordLen = 16 << 20 // 16 MiB sanity limit

type rosBinConfig struct {
	Addr        string
	User        string
	Pass        string
	UseTLS      bool
	InsecureTLS bool
}

type rosBinTrapError struct {
	Category string
	Message  string
}

func (e *rosBinTrapError) Error() string {
	if e == nil {
		return ""
	}
	if e.Category != "" {
		return fmt.Sprintf("ros api trap (cat=%s): %s", e.Category, e.Message)
	}
	return fmt.Sprintf("ros api trap: %s", e.Message)
}

func (e *rosBinTrapError) IsAlreadyExists() bool {
	if e == nil {
		return false
	}
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "already have such entry") || strings.Contains(m, "already exists")
}

func isROSAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	var trap *rosBinTrapError
	if errors.As(err, &trap) && trap.IsAlreadyExists() {
		return true
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "already have such entry") || strings.Contains(low, "already exists")
}

// ROSBinClient implements MikroTik RouterOS Binary API (:8728 / :8729 TLS)
// with a persistent reconnecting TCP socket and pure-stdlib framing.
type ROSBinClient struct {
	mu   sync.Mutex
	cfg  rosBinConfig
	conn net.Conn
	r    *bufio.Reader
}

func NewROSBinClient() *ROSBinClient {
	return &ROSBinClient{}
}

func (c *ROSBinClient) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *ROSBinClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.r = nil
}

func rosBinEndpointFromSettings(s AppSettings) (rosBinConfig, bool) {
	base := strings.TrimSpace(s.ROSURL)
	if base == "" || !s.ROSUseBinaryAPI {
		return rosBinConfig{}, false
	}
	u, err := url.Parse(base)
	host := ""
	if err == nil && u.Hostname() != "" {
		host = u.Hostname()
	} else {
		host = strings.TrimPrefix(base, "https://")
		host = strings.TrimPrefix(host, "http://")
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if idx := strings.IndexByte(host, '/'); idx >= 0 {
			host = host[:idx]
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return rosBinConfig{}, false
	}
	port := s.ROSAPIPort
	if port <= 0 || port > 65535 {
		if s.ROSAPITLS {
			port = 8729
		} else {
			port = 8728
		}
	}
	return rosBinConfig{
		Addr:        net.JoinHostPort(host, strconv.Itoa(port)),
		User:        s.ROSUser,
		Pass:        s.ROSPass,
		UseTLS:      s.ROSAPITLS,
		InsecureTLS: s.ROSTLSSkipVerify,
	}, true
}

func (c *ROSBinClient) Exec(ctx context.Context, cfg rosBinConfig, cmd string, args ...string) ([]map[string]string, error) {
	if c == nil {
		return nil, errors.New("binary api client is nil")
	}
	if cfg.Addr == "" {
		return nil, errors.New("binary api address is empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil && c.cfg != cfg {
		c.closeLocked()
	}

	words := make([]string, 0, 1+len(args))
	words = append(words, cmd)
	words = append(words, args...)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hadConn := c.conn != nil
		if !hadConn {
			if err := c.dialAndLoginLocked(ctx, cfg); err != nil {
				c.closeLocked()
				return nil, err
			}
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(8 * time.Second)
		}
		_ = c.conn.SetDeadline(deadline)
		res, err := c.runSentenceLocked(words)
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
		if err == nil {
			return res, nil
		}
		lastErr = err

		// Do not retry logical API traps/fatal errors on a freshly opened connection.
		var trap *rosBinTrapError
		if errors.As(err, &trap) {
			return nil, err
		}
		c.closeLocked()
		if !hadConn {
			return nil, err
		}
		// Existing persistent socket may have been closed remotely after idle timeout; retry once.
	}
	return nil, lastErr
}

func (c *ROSBinClient) dialAndLoginLocked(ctx context.Context, cfg rosBinConfig) error {
	dialTimeout := 4 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialTimeout {
			dialTimeout = rem
		}
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	var rawConn net.Conn
	var err error
	if cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
			MinVersion:         tls.VersionTLS12,
		}
		rawConn, err = tls.DialWithDialer(dialer, "tcp", cfg.Addr, tlsCfg)
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", cfg.Addr)
	}
	if err != nil {
		return fmt.Errorf("binary api dial %s: %w", cfg.Addr, err)
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}

	c.cfg = cfg
	c.conn = rawConn
	c.r = bufio.NewReaderSize(rawConn, 16*1024)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = c.conn.SetDeadline(deadline)
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()

	if err := c.loginLocked(cfg.User, cfg.Pass); err != nil {
		return err
	}
	return nil
}

func (c *ROSBinClient) loginLocked(user, pass string) error {
	words := []string{"/login", "=name=" + user, "=password=" + pass}
	if err := writeAPISentence(c.conn, words); err != nil {
		return fmt.Errorf("binary api login send: %w", err)
	}
	rows, doneAttrs, err := readAPIReply(c.r)
	_ = rows
	if err != nil {
		return fmt.Errorf("binary api login: %w", err)
	}
	// Legacy pre-6.43 challenge-response login fallback.
	if retHex := doneAttrs["ret"]; retHex != "" {
		chall, hexErr := hex.DecodeString(retHex)
		if hexErr != nil {
			return fmt.Errorf("binary api invalid login challenge: %w", hexErr)
		}
		sumInput := make([]byte, 0, 1+len(pass)+len(chall))
		sumInput = append(sumInput, 0)
		sumInput = append(sumInput, pass...)
		sumInput = append(sumInput, chall...)
		sum := md5.Sum(sumInput)
		respWords := []string{"/login", "=name=" + user, "=response=00" + hex.EncodeToString(sum[:])}
		if err := writeAPISentence(c.conn, respWords); err != nil {
			return fmt.Errorf("binary api challenge login send: %w", err)
		}
		if _, _, err := readAPIReply(c.r); err != nil {
			return fmt.Errorf("binary api challenge login: %w", err)
		}
	}
	return nil
}

func (c *ROSBinClient) runSentenceLocked(words []string) ([]map[string]string, error) {
	if err := writeAPISentence(c.conn, words); err != nil {
		return nil, err
	}
	rows, _, err := readAPIReply(c.r)
	return rows, err
}

func encodeAPILen(l int) []byte {
	switch {
	case l < 0x80:
		return []byte{byte(l)}
	case l < 0x4000:
		v := uint16(l) | 0x8000
		return []byte{byte(v >> 8), byte(v)}
	case l < 0x200000:
		v := uint32(l) | 0xC00000
		return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	case l < 0x10000000:
		v := uint32(l) | 0xE0000000
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		var b [5]byte
		b[0] = 0xF0
		binary.BigEndian.PutUint32(b[1:], uint32(l))
		return b[:]
	}
}

func readAPILen(r *bufio.Reader) (int, error) {
	c0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch {
	case (c0 & 0x80) == 0:
		return int(c0), nil
	case (c0 & 0xC0) == 0x80:
		c1, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return (int(c0&0x3F) << 8) | int(c1), nil
	case (c0 & 0xE0) == 0xC0:
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return (int(c0&0x1F) << 16) | (int(buf[0]) << 8) | int(buf[1]), nil
	case (c0 & 0xF0) == 0xE0:
		var buf [3]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return (int(c0&0x0F) << 24) | (int(buf[0]) << 16) | (int(buf[1]) << 8) | int(buf[2]), nil
	case c0 == 0xF0:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint32(buf[:])), nil
	default:
		return 0, fmt.Errorf("invalid api control byte 0x%02x", c0)
	}
}

func writeAPISentence(w io.Writer, words []string) error {
	var buf []byte
	for _, word := range words {
		buf = append(buf, encodeAPILen(len(word))...)
		buf = append(buf, word...)
	}
	buf = append(buf, 0)
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func readAPIWord(r *bufio.Reader) (string, error) {
	n, err := readAPILen(r)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	if n < 0 || n > rosBinMaxWordLen {
		return "", fmt.Errorf("invalid api word length %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func readAPISentence(r *bufio.Reader) (string, map[string]string, error) {
	var kind string
	attrs := make(map[string]string)
	for {
		w, err := readAPIWord(r)
		if err != nil {
			return "", nil, err
		}
		if w == "" {
			if kind == "" {
				continue
			}
			return kind, attrs, nil
		}
		if kind == "" {
			kind = w
			continue
		}
		if strings.HasPrefix(w, "=") {
			kv := w[1:]
			if eq := strings.IndexByte(kv, '='); eq >= 0 {
				attrs[kv[:eq]] = kv[eq+1:]
			} else {
				attrs[kv] = ""
			}
		} else if strings.HasPrefix(w, ".") {
			kv := w[1:]
			if eq := strings.IndexByte(kv, '='); eq >= 0 {
				attrs["."+kv[:eq]] = kv[eq+1:]
			}
		} else if kind == "!fatal" {
			attrs["message"] = strings.TrimSpace(attrs["message"] + " " + w)
		}
	}
}

func readAPIReply(r *bufio.Reader) ([]map[string]string, map[string]string, error) {
	var rows []map[string]string
	var trapErr *rosBinTrapError
	for {
		kind, attrs, err := readAPISentence(r)
		if err != nil {
			return nil, nil, err
		}
		switch kind {
		case "!re":
			rows = append(rows, attrs)
		case "!trap":
			trapErr = &rosBinTrapError{
				Category: attrs["category"],
				Message:  attrs["message"],
			}
		case "!fatal":
			msg := attrs["message"]
			if msg == "" {
				msg = "fatal session close"
			}
			return nil, nil, fmt.Errorf("ros api fatal: %s", msg)
		case "!done":
			if trapErr != nil {
				return nil, attrs, trapErr
			}
			return rows, attrs, nil
		}
	}
}
