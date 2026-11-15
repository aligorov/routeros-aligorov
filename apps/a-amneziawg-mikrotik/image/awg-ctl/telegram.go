package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var reTGBotURLToken = regexp.MustCompile(`/bot[0-9]{4,}:[A-Za-z0-9_-]{8,}`)

func redactTelegramSecrets(msg, token string) string {
	out := reTGBotURLToken.ReplaceAllString(msg, "/bot***REDACTED***")
	if tok := strings.TrimSpace(token); tok != "" {
		out = strings.ReplaceAll(out, tok, "***REDACTED***")
	}
	return out
}

type TGEventKind string

const (
	TGKindStart    TGEventKind = "start"
	TGKindFailover TGEventKind = "failover"
	TGKindDown     TGEventKind = "down"
	TGKindConfig   TGEventKind = "config"
	TGKindDigest   TGEventKind = "digest"
	TGKindTest     TGEventKind = "test"
)

type TGStatus struct {
	Enabled     bool   `json:"enabled"`
	ChatID      string `json:"chat_id,omitempty"`
	ThreadID    int    `json:"thread_id,omitempty"`
	AlertThread int    `json:"alert_thread_id,omitempty"`
	Via         string `json:"via"`
	SentTotal   int    `json:"sent_total"`
	FailedTotal int    `json:"failed_total"`
	LastSentAt  int64  `json:"last_sent_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type tgEvent struct {
	kind     TGEventKind
	title    string
	body     string
	dedupKey string
}

type TGNotifier struct {
	settings *SettingsStore
	mgr      *TunnelManager
	logger   *RingLogger
	queue    chan tgEvent
	stopCh   chan struct{}

	mu            sync.Mutex
	lastError     string
	lastSentAt    int64
	sentTotal     int
	failedTotal   int
	lastDigestDay string
	lastDedup     map[string]time.Time

	// Injectable for tests
	sendHTTPFn func(ctx context.Context, via, apiURL, token string, payload []byte) (int, []byte, error)
}

func NewTGNotifier(settings *SettingsStore, mgr *TunnelManager, logger *RingLogger) *TGNotifier {
	n := &TGNotifier{
		settings:  settings,
		mgr:       mgr,
		logger:    logger,
		queue:     make(chan tgEvent, 64),
		stopCh:    make(chan struct{}),
		lastDedup: map[string]time.Time{},
	}
	n.sendHTTPFn = n.defaultSendHTTP
	go n.worker()
	return n
}

func (n *TGNotifier) Stop() {
	select {
	case <-n.stopCh:
	default:
		close(n.stopCh)
	}
}

func (n *TGNotifier) Status() TGStatus {
	var st AppSettings
	if n.settings != nil {
		st = n.settings.Get()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return TGStatus{
		Enabled:     st.TGEnabled && st.TGBotToken != "" && st.TGChatID != "",
		ChatID:      st.TGChatID,
		ThreadID:    st.TGThreadID,
		AlertThread: st.TGAlertThreadID,
		Via:         st.TGVia,
		SentTotal:   n.sentTotal,
		FailedTotal: n.failedTotal,
		LastSentAt:  n.lastSentAt,
		LastError:   n.lastError,
	}
}

func (n *TGNotifier) Notify(kind TGEventKind, dedupKey, title, body string) {
	if n.settings == nil {
		return
	}
	st := n.settings.Get()
	if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" {
		return
	}
	switch kind {
	case TGKindStart:
		if !st.TGOnStart {
			return
		}
	case TGKindFailover:
		if !st.TGOnFailover {
			return
		}
	case TGKindDown:
		if !st.TGOnDown {
			return
		}
	case TGKindConfig:
		if !st.TGOnConfig {
			return
		}
	}

	if dedupKey != "" {
		now := time.Now()
		n.mu.Lock()
		if prev, ok := n.lastDedup[dedupKey]; ok && now.Sub(prev) < 20*time.Second {
			n.mu.Unlock()
			return
		}
		n.lastDedup[dedupKey] = now
		if len(n.lastDedup) > 128 {
			for k, ts := range n.lastDedup {
				if now.Sub(ts) > 5*time.Minute {
					delete(n.lastDedup, k)
				}
			}
		}
		n.mu.Unlock()
	}

	select {
	case n.queue <- tgEvent{kind: kind, title: title, body: body, dedupKey: dedupKey}:
	default:
		if n.logger != nil {
			n.logger.Logf("WARN Telegram queue full, dropping alert %q", title)
		}
	}
}

func (n *TGNotifier) SendTest(override *AppSettings) (int64, error) {
	st := n.settings.Get()
	if override != nil {
		merged := *override
		if merged.TGBotToken == "" {
			merged.TGBotToken = st.TGBotToken
		}
		if merged.TGAPIURL == "" {
			merged.TGAPIURL = st.TGAPIURL
		}
		if merged.TGNodeName == "" {
			merged.TGNodeName = st.TGNodeName
		}
		if merged.TGVia == "" {
			merged.TGVia = st.TGVia
		}
		st = merged
	}
	primary := "нет"
	if n.mgr != nil {
		if p := n.mgr.PrimaryInterface(); p != "" {
			primary = p
		}
	}
	threadInfo := "основной чат"
	if st.TGThreadID > 0 {
		threadInfo = fmt.Sprintf("топик #%d", st.TGThreadID)
	}
	if st.TGAlertThreadID > 0 {
		threadInfo += fmt.Sprintf(" (алерты → топик #%d)", st.TGAlertThreadID)
	}
	body := fmt.Sprintf("Маршрут бота: <code>%s</code>\nНазначение: %s\nАктивный туннель: <code>%s</code>",
		html.EscapeString(st.TGVia), html.EscapeString(threadInfo), html.EscapeString(primary))
	return n.sendSyncWithSettings(st, TGKindTest, "Тест уведомлений AmneziaWG", body)
}

func (n *TGNotifier) MaybeSendDigest(now time.Time) {
	if n.settings == nil || n.mgr == nil {
		return
	}
	st := n.settings.Get()
	if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" || st.TGDailyDigestHour < 0 {
		return
	}
	if now.Hour() != st.TGDailyDigestHour {
		return
	}
	day := now.Format("2006-01-02")
	n.mu.Lock()
	if n.lastDigestDay == day {
		n.mu.Unlock()
		return
	}
	n.lastDigestDay = day
	n.mu.Unlock()

	ifaces, _ := n.mgr.ShowInterfaces()
	var lines []string
	if len(ifaces) == 0 {
		lines = append(lines, "Активные туннели: нет")
	} else {
		for _, ifc := range ifaces {
			var rx, tx uint64
			var hs int64 = -1
			for _, p := range ifc.Peers {
				rx += p.RxBytes
				tx += p.TxBytes
				if p.HandshakeAgeSec >= 0 && (hs < 0 || p.HandshakeAgeSec < hs) {
					hs = p.HandshakeAgeSec
				}
			}
			hsStr := "нет"
			if hs >= 0 {
				hsStr = fmt.Sprintf("%ds", hs)
			}
			lines = append(lines, fmt.Sprintf("• <code>%s</code>: HS %s, RX %.1f MiB / TX %.1f MiB",
				html.EscapeString(ifc.Name), hsStr, float64(rx)/1048576, float64(tx)/1048576))
		}
	}
	n.Notify(TGKindDigest, "digest:"+day, "Ежедневная сводка AmneziaWG", strings.Join(lines, "\n"))
}

func (n *TGNotifier) worker() {
	for {
		select {
		case <-n.stopCh:
			return
		case ev := <-n.queue:
			st := n.settings.Get()
			if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" {
				continue
			}
			if _, err := n.sendSyncWithSettings(st, ev.kind, ev.title, ev.body); err != nil && n.logger != nil {
				n.logger.Logf("WARN Telegram send failed (%s): %v", ev.title, err)
			}
		}
	}
}

func (n *TGNotifier) sendSyncWithSettings(st AppSettings, kind TGEventKind, title, body string) (int64, error) {
	if st.TGBotToken == "" || st.TGChatID == "" {
		return 0, fmt.Errorf("tg_bot_token and tg_chat_id are required")
	}
	icon := "ℹ️"
	switch kind {
	case TGKindStart:
		icon = "✅"
	case TGKindFailover:
		icon = "🔁"
	case TGKindDown:
		icon = "🔴"
	case TGKindConfig:
		icon = "⚙️"
	case TGKindDigest:
		icon = "📊"
	case TGKindTest:
		icon = "🔔"
	}

	node := strings.TrimSpace(st.TGNodeName)
	if node == "" {
		node = "routeros-awg"
	}
	text := fmt.Sprintf("%s <b>[%s] %s</b>", icon, html.EscapeString(node), html.EscapeString(title))
	if strings.TrimSpace(body) != "" {
		text += "\n" + body
	}

	threadID := st.TGThreadID
	if (kind == TGKindFailover || kind == TGKindDown) && st.TGAlertThreadID > 0 {
		threadID = st.TGAlertThreadID
	}

	reqObj := map[string]any{
		"chat_id":                  st.TGChatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if threadID > 0 {
		reqObj["message_thread_id"] = threadID
	}
	if st.TGSilent {
		reqObj["disable_notification"] = true
	}

	payload, err := json.Marshal(reqObj)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	status, respBody, err := n.sendHTTPFn(ctx, st.TGVia, st.TGAPIURL, st.TGBotToken, payload)
	if err != nil {
		cleanErr := errors.New(redactTelegramSecrets(err.Error(), st.TGBotToken))
		n.recordResult(cleanErr)
		return 0, cleanErr
	}

	var apiResp struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
		Result      struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	_ = json.Unmarshal(respBody, &apiResp)
	if status >= 400 || !apiResp.OK {
		msg := apiResp.Description
		if msg == "" {
			msg = strings.TrimSpace(string(respBody))
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		err = fmt.Errorf("telegram api (%d): %s", status, msg)
		n.recordResult(err)
		return 0, err
	}

	n.recordResult(nil)
	return apiResp.Result.MessageID, nil
}

func (n *TGNotifier) recordResult(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		n.failedTotal++
		n.lastError = err.Error()
		return
	}
	n.sentTotal++
	n.lastSentAt = time.Now().Unix()
	n.lastError = ""
}

func (n *TGNotifier) defaultSendHTTP(ctx context.Context, via, apiURL, token string, payload []byte) (int, []byte, error) {
	if apiURL == "" {
		apiURL = DefaultTelegramAPI
	}
	if err := validateHTTPURL(apiURL); err != nil {
		return 0, nil, fmt.Errorf("некорректный tg_api_url: %w", err)
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/bot" + token + "/sendMessage"

	doPost := func(dialer netDialFunc) (int, []byte, error) {
		tr := &http.Transport{DialContext: dialer}
		defer tr.CloseIdleConnections()
		cli := &http.Client{Transport: tr, Timeout: 8 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, errors.New(redactTelegramSecrets(err.Error(), token))
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := cli.Do(req)
		if err != nil {
			return 0, nil, errors.New(redactTelegramSecrets(err.Error(), token))
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, b, nil
	}

	directDialer := sockBindDialer("", 0, 5*time.Second)
	tunDialer := sockBindDialer("", ProxyDNSFwmark, 5*time.Second)

	switch via {
	case "direct":
		return doPost(directDialer.DialContext)
	case "tunnel":
		return doPost(tunDialer.DialContext)
	default: // "auto": try direct first (works when VPN is down!), fallback to tunnel if network blocked & tunnel UP
		st, b, err := doPost(directDialer.DialContext)
		if err == nil {
			return st, b, nil
		}
		if n.mgr != nil && n.mgr.PrimaryInterface() != "" {
			if st2, b2, err2 := doPost(tunDialer.DialContext); err2 == nil {
				return st2, b2, nil
			}
		}
		return st, b, err
	}
}

type netDialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)
