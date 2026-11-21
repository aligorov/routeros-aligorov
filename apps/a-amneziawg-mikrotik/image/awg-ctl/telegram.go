package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

var (
	reTGBotURLToken = regexp.MustCompile(`/bot[0-9]{4,}:[A-Za-z0-9_-]{8,}`)
	reHTMLTagStrip  = regexp.MustCompile(`<[^>]+>`)
)

func redactTelegramSecrets(msg, token string) string {
	out := reTGBotURLToken.ReplaceAllString(msg, "/bot***REDACTED***")
	if tok := strings.TrimSpace(token); tok != "" {
		out = strings.ReplaceAll(out, tok, "***REDACTED***")
	}
	return out
}

func stripHTMLTags(s string) string {
	clean := reHTMLTagStrip.ReplaceAllString(s, "")
	return html.UnescapeString(clean)
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes - 3
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func formatHumanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := int64(d.Seconds())
	if sec < 60 {
		return fmt.Sprintf("%dс", sec)
	}
	days := sec / 86400
	rem := sec % 86400
	hours := rem / 3600
	mins := (rem % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dч %dм", hours, mins)
	}
	secs := rem % 60
	if mins < 5 && secs > 0 {
		return fmt.Sprintf("%dм %dс", mins, secs)
	}
	return fmt.Sprintf("%dм", mins)
}

type TGEventKind string

const (
	TGKindStart    TGEventKind = "start"
	TGKindFailover TGEventKind = "failover"
	TGKindDown     TGEventKind = "down"
	TGKindRecovery TGEventKind = "recovery"
	TGKindWarn     TGEventKind = "warn"
	TGKindConfig   TGEventKind = "config"
	TGKindSecurity TGEventKind = "security"
	TGKindDigest   TGEventKind = "digest"
	TGKindTest     TGEventKind = "test"
)

type TGIncidentView struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	OpenedAt int64  `json:"opened_at"`
}

type TGStatus struct {
	Enabled         bool             `json:"enabled"`
	AlertsEnabled   bool             `json:"alerts_enabled"`
	DeliveryEnabled bool             `json:"delivery_enabled"`
	DeliveryMode    string           `json:"delivery_mode,omitempty"`
	ChatID          string           `json:"chat_id,omitempty"`
	ThreadID        int              `json:"thread_id,omitempty"`
	AlertThread     int              `json:"alert_thread_id,omitempty"`
	Via             string           `json:"via"`
	StickyVia       string           `json:"sticky_via,omitempty"`
	SentTotal       int              `json:"sent_total"`
	FailedTotal     int              `json:"failed_total"`
	QueueLen        int              `json:"queue_len"`
	LastSentAt      int64            `json:"last_sent_at,omitempty"`
	LastError       string           `json:"last_error,omitempty"`
	TopicError      string           `json:"topic_error,omitempty"`
	OpenIncidents   []TGIncidentView `json:"open_incidents,omitempty"`
}

type TGTestSuiteResult struct {
	OK             bool     `json:"ok"`
	MessageID      int64    `json:"message_id,omitempty"`
	AlertMessageID int64    `json:"alert_message_id,omitempty"`
	AlertError     string   `json:"alert_error,omitempty"`
	Error          string   `json:"error,omitempty"`
	TG             TGStatus `json:"tg"`
}

type tgEvent struct {
	kind             TGEventKind
	title            string
	body             string
	dedupKey         string
	replyToMsgID     int64
	incidentKey      string
	attempt          int
	notBefore        time.Time
	noThreadFallback bool
	onSent           func(msgID int64)
}

type tgIncident struct {
	Key          string
	Kind         TGEventKind
	Title        string
	OpenedAt     time.Time
	LastReminded time.Time
	MessageID    int64
}

type tgChatBucket struct {
	tokens     float64
	lastRefill time.Time
}

type tgAPIError struct {
	Status     int
	Code       int
	Desc       string
	RetryAfter time.Duration
	Friendly   string
}

func (e *tgAPIError) Error() string {
	if e.Friendly != "" {
		return e.Friendly
	}
	return fmt.Sprintf("telegram api (%d): %s", e.Status, e.Desc)
}

type TGNotifier struct {
	settings *SettingsStore
	mgr      *TunnelManager
	logger   *RingLogger
	queue    chan tgEvent
	stopCh   chan struct{}
	stateDir string

	directClient *http.Client
	tunClient    *http.Client

	mu            sync.Mutex
	lastError     string
	topicError    string
	lastSentAt    int64
	sentTotal     int
	failedTotal   int
	lastDigestDay string
	lastDedup     map[string]time.Time
	incidents     map[string]*tgIncident
	chatBuckets   map[string]*tgChatBucket
	stickyVia     string
	stickyAt      time.Time
	digestExtraFn func() []string

	// Injectable for tests
	nowFn             func() time.Time
	sendHTTPFn        func(ctx context.Context, via, apiURL, token string, payload []byte) (int, []byte, error)
	sendMethodFn      func(ctx context.Context, via, apiURL, token, method, contentType string, payload []byte) (int, []byte, error)
	origSendHTTPPtr   uintptr
	origSendMethodPtr uintptr
	forcePace         bool
}

func newTGDedicatedHTTPClient(mark int) *http.Client {
	dialer := sockBindDialer("", mark, 4*time.Second)
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		IdleConnTimeout:     60 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
	}
}

func NewTGNotifier(settings *SettingsStore, mgr *TunnelManager, logger *RingLogger) *TGNotifier {
	stateDir := ""
	if settings != nil && settings.path != "" {
		stateDir = filepath.Dir(settings.path)
	}
	n := &TGNotifier{
		settings:     settings,
		mgr:          mgr,
		logger:       logger,
		queue:        make(chan tgEvent, 128),
		stopCh:       make(chan struct{}),
		stateDir:     stateDir,
		directClient: newTGDedicatedHTTPClient(0),
		tunClient:    newTGDedicatedHTTPClient(ProxyDNSFwmark),
		lastDedup:    map[string]time.Time{},
		incidents:    map[string]*tgIncident{},
		chatBuckets:  map[string]*tgChatBucket{},
		nowFn:        time.Now,
	}
	n.sendHTTPFn = n.defaultSendHTTP
	n.sendMethodFn = n.callMethodHTTP
	n.origSendHTTPPtr = reflect.ValueOf(n.sendHTTPFn).Pointer()
	n.origSendMethodPtr = reflect.ValueOf(n.sendMethodFn).Pointer()
	n.loadDigestDayFromDisk()
	go n.worker()
	return n
}

func (n *TGNotifier) SetNowFnForTest(fn func() time.Time) {
	n.mu.Lock()
	n.nowFn = fn
	n.mu.Unlock()
}

func (n *TGNotifier) currentNow() time.Time {
	n.mu.Lock()
	fn := n.nowFn
	n.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return time.Now()
}

func (n *TGNotifier) SetDigestExtrasProvider(fn func() []string) {
	n.mu.Lock()
	n.digestExtraFn = fn
	n.mu.Unlock()
}

func (n *TGNotifier) Stop() {
	select {
	case <-n.stopCh:
	default:
		close(n.stopCh)
	}
	if n.directClient != nil {
		n.directClient.CloseIdleConnections()
	}
	if n.tunClient != nil {
		n.tunClient.CloseIdleConnections()
	}
}

func (n *TGNotifier) loadDigestDayFromDisk() {
	if n.stateDir == "" {
		return
	}
	if b, err := os.ReadFile(filepath.Join(n.stateDir, ".tg_digest_day")); err == nil {
		n.lastDigestDay = strings.TrimSpace(string(b))
	}
}

func (n *TGNotifier) saveDigestDayToDisk(day string) {
	if n.stateDir == "" || day == "" {
		return
	}
	_ = os.MkdirAll(n.stateDir, 0o700)
	_ = os.WriteFile(filepath.Join(n.stateDir, ".tg_digest_day"), []byte(day), 0o600)
}

func (n *TGNotifier) Status() TGStatus {
	var st AppSettings
	if n.settings != nil {
		st = n.settings.Get()
	}
	now := n.currentNow()
	alertsOn := st.TGEnabled && st.TGBotToken != "" && st.TGChatID != ""
	delivMode := normalizeTGDeliveryMode(st.TGDeliveryMode)
	delivOn := st.TGBotToken != "" && delivMode != "off"

	n.mu.Lock()
	defer n.mu.Unlock()
	sticky := ""
	if n.stickyVia != "" && now.Sub(n.stickyAt) < 5*time.Minute {
		sticky = n.stickyVia
	}
	var incList []TGIncidentView
	for _, inc := range n.incidents {
		incList = append(incList, TGIncidentView{
			Key:      inc.Key,
			Title:    inc.Title,
			OpenedAt: inc.OpenedAt.Unix(),
		})
	}
	sort.Slice(incList, func(i, j int) bool { return incList[i].OpenedAt < incList[j].OpenedAt })

	return TGStatus{
		Enabled:         alertsOn,
		AlertsEnabled:   alertsOn,
		DeliveryEnabled: delivOn,
		DeliveryMode:    delivMode,
		ChatID:          st.TGChatID,
		ThreadID:        st.TGThreadID,
		AlertThread:     st.TGAlertThreadID,
		Via:             st.TGVia,
		StickyVia:       sticky,
		SentTotal:       n.sentTotal,
		FailedTotal:     n.failedTotal,
		QueueLen:        len(n.queue),
		LastSentAt:      n.lastSentAt,
		LastError:       n.lastError,
		TopicError:      n.topicError,
		OpenIncidents:   incList,
	}
}

func isKindAllowed(st AppSettings, kind TGEventKind) bool {
	if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" {
		return false
	}
	switch kind {
	case TGKindStart:
		return st.TGOnStart
	case TGKindFailover:
		return st.TGOnFailover
	case TGKindDown:
		return st.TGOnDown
	case TGKindRecovery:
		return st.TGOnRecovery
	case TGKindWarn:
		return st.TGOnIntegrations
	case TGKindConfig:
		return st.TGOnConfig
	case TGKindSecurity:
		return st.TGOnSecurity
	case TGKindDigest, TGKindTest:
		return true
	default:
		return true
	}
}

func isCriticalEventKind(kind TGEventKind) bool {
	return kind == TGKindDown || kind == TGKindFailover
}

func isInQuietHours(quietSpec string, tzOffsetMin int, utcNow time.Time) bool {
	spec := normalizeTGQuietHours(quietSpec)
	if spec == "" {
		return false
	}
	parts := strings.Split(spec, "-")
	parseMins := func(hm string) int {
		p := strings.Split(hm, ":")
		h, _ := strconv.Atoi(p[0])
		m, _ := strconv.Atoi(p[1])
		return h*60 + m
	}
	startMin := parseMins(parts[0])
	endMin := parseMins(parts[1])
	locNow := utcNow.UTC().Add(time.Duration(tzOffsetMin) * time.Minute)
	curMin := locNow.Hour()*60 + locNow.Minute()
	if startMin < endMin {
		return curMin >= startMin && curMin < endMin
	}
	return curMin >= startMin || curMin < endMin
}

func shouldSilenceNotification(st AppSettings, kind TGEventKind, now time.Time) bool {
	if st.TGSilent {
		return true
	}
	if isCriticalEventKind(kind) {
		return false
	}
	if st.TGSilentInfo {
		return true
	}
	if st.TGQuietHours != "" && isInQuietHours(st.TGQuietHours, st.TGDigestTZOffset, now) {
		return true
	}
	return false
}

func (n *TGNotifier) enqueueEvent(ev tgEvent) {
	select {
	case n.queue <- ev:
	default:
		if n.logger != nil {
			n.logger.Logf("WARN Telegram queue full, dropping alert %q", ev.title)
		}
	}
}

func (n *TGNotifier) Notify(kind TGEventKind, dedupKey, title, body string) {
	if n.settings == nil {
		return
	}
	st := n.settings.Get()
	if !isKindAllowed(st, kind) {
		return
	}

	if dedupKey != "" {
		now := n.currentNow()
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

	n.enqueueEvent(tgEvent{kind: kind, title: title, body: body, dedupKey: dedupKey})
}

// OpenIncident opens a stateful alert once and suppresses duplicate pings until recovery
// (sending at most one reminder every 2 hours while still unhealthy).
func (n *TGNotifier) OpenIncident(key string, kind TGEventKind, title, body string) {
	if n.settings == nil || strings.TrimSpace(key) == "" {
		return
	}
	st := n.settings.Get()
	now := n.currentNow()

	n.mu.Lock()
	inc, exists := n.incidents[key]
	if exists {
		if now.Sub(inc.LastReminded) < 2*time.Hour {
			n.mu.Unlock()
			return
		}
		inc.LastReminded = now
		msgID := inc.MessageID
		opened := inc.OpenedAt
		n.mu.Unlock()

		if !isKindAllowed(st, kind) {
			return
		}
		remBody := fmt.Sprintf("⏱ Всё ещё активно (длительность: <b>%s</b>)", html.EscapeString(formatHumanDuration(now.Sub(opened))))
		if strings.TrimSpace(body) != "" {
			remBody += "\n" + body
		}
		n.enqueueEvent(tgEvent{
			kind:         kind,
			title:        title + " (напоминание)",
			body:         remBody,
			replyToMsgID: msgID,
			incidentKey:  key,
		})
		return
	}

	if len(n.incidents) >= 256 {
		n.mu.Unlock()
		return
	}
	inc = &tgIncident{
		Key:          key,
		Kind:         kind,
		Title:        title,
		OpenedAt:     now,
		LastReminded: now,
	}
	n.incidents[key] = inc
	n.mu.Unlock()

	if !isKindAllowed(st, kind) {
		return
	}

	n.enqueueEvent(tgEvent{
		kind:        kind,
		title:       title,
		body:        body,
		incidentKey: key,
		onSent: func(msgID int64) {
			if msgID <= 0 {
				return
			}
			n.mu.Lock()
			if cur, ok := n.incidents[key]; ok {
				cur.MessageID = msgID
			}
			n.mu.Unlock()
		},
	})
}

// ResolveIncident closes an open incident and sends a green recovery notice (replying to the alert if possible).
func (n *TGNotifier) ResolveIncident(key, title, body string) {
	if n.settings == nil || strings.TrimSpace(key) == "" {
		return
	}
	now := n.currentNow()

	n.mu.Lock()
	inc, exists := n.incidents[key]
	if !exists {
		n.mu.Unlock()
		return
	}
	delete(n.incidents, key)
	openedAt := inc.OpenedAt
	origMsgID := inc.MessageID
	n.mu.Unlock()

	st := n.settings.Get()
	if !isKindAllowed(st, TGKindRecovery) {
		return
	}

	durStr := formatHumanDuration(now.Sub(openedAt))
	recBody := fmt.Sprintf("⏱ Простой: <b>%s</b>", html.EscapeString(durStr))
	if strings.TrimSpace(body) != "" {
		recBody += "\n" + body
	}
	n.enqueueEvent(tgEvent{
		kind:         TGKindRecovery,
		title:        title,
		body:         recBody,
		replyToMsgID: origMsgID,
	})
}

func (n *TGNotifier) IsIncidentOpen(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.incidents[key]
	return ok
}

func (n *TGNotifier) applyOverrideSettings(override *AppSettings) AppSettings {
	st := n.settings.Get()
	if override == nil {
		return st
	}
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
	if merged.TGDeliveryMode == "" {
		merged.TGDeliveryMode = st.TGDeliveryMode
	}
	return merged
}

func (n *TGNotifier) SendTest(override *AppSettings) (int64, error) {
	st := n.applyOverrideSettings(override)
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
	locNow := n.currentNow().UTC().Add(time.Duration(st.TGDigestTZOffset) * time.Minute)
	tzHours := float64(st.TGDigestTZOffset) / 60.0
	body := fmt.Sprintf(
		"Маршрут бота: <code>%s</code>\nНазначение: %s\nАктивный туннель: <code>%s</code>\nВремя узла: <code>%s</code> (UTC%+.1f)\nДоставка клиентам: <code>%s</code>",
		html.EscapeString(st.TGVia),
		html.EscapeString(threadInfo),
		html.EscapeString(primary),
		locNow.Format("15:04:05"),
		tzHours,
		html.EscapeString(normalizeTGDeliveryMode(st.TGDeliveryMode)),
	)
	return n.sendSyncWithSettings(st, TGKindTest, "Тест уведомлений AmneziaWG", body)
}

func (n *TGNotifier) SendTestSuite(override *AppSettings, testAlertTopic bool) TGTestSuiteResult {
	st := n.applyOverrideSettings(override)
	msgID, err := n.SendTest(&st)
	if err != nil {
		return TGTestSuiteResult{
			OK:    false,
			Error: redactTelegramSecrets(err.Error(), st.TGBotToken),
			TG:    n.Status(),
		}
	}
	res := TGTestSuiteResult{
		OK:        true,
		MessageID: msgID,
		TG:        n.Status(),
	}
	if testAlertTopic && st.TGAlertThreadID > 0 && st.TGAlertThreadID != st.TGThreadID {
		alertBody := fmt.Sprintf("Проверка топика критических алертов <code>#%d</code>\nСюда поступают падения туннелей и авто-Failover.", st.TGAlertThreadID)
		aID, _, _, aErr := n.sendEventWithFallback(st, tgEvent{
			kind:             TGKindFailover,
			title:            "Тест канала алертов",
			body:             alertBody,
			noThreadFallback: true,
		}, true)
		if aErr != nil {
			res.AlertError = redactTelegramSecrets(aErr.Error(), st.TGBotToken)
		} else {
			res.AlertMessageID = aID
		}
		res.TG = n.Status()
	}
	return res
}

func (n *TGNotifier) MaybeSendDigest(now time.Time) {
	if n.settings == nil || n.mgr == nil {
		return
	}
	st := n.settings.Get()
	if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" || st.TGDailyDigestHour < 0 {
		return
	}
	locNow := now.UTC().Add(time.Duration(st.TGDigestTZOffset) * time.Minute)
	if locNow.Hour() != st.TGDailyDigestHour {
		return
	}
	day := locNow.Format("2006-01-02")
	n.mu.Lock()
	if n.lastDigestDay == day {
		n.mu.Unlock()
		return
	}
	n.lastDigestDay = day
	extraFn := n.digestExtraFn
	openCnt := len(n.incidents)
	n.mu.Unlock()

	n.saveDigestDayToDisk(day)

	ifaces, _ := n.mgr.ShowInterfaces()
	primary := n.mgr.PrimaryInterface()
	var lines []string
	if len(ifaces) == 0 {
		lines = append(lines, "Активные туннели: <b>нет</b>")
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
			role := ""
			if primary != "" && ifc.Name == primary {
				role = " ★"
			}
			lines = append(lines, fmt.Sprintf("• <code>%s</code>%s: HS %s · ↓%.1f / ↑%.1f MiB",
				html.EscapeString(ifc.Name), role, hsStr, float64(rx)/1048576, float64(tx)/1048576))
		}
	}
	if openCnt > 0 {
		lines = append(lines, fmt.Sprintf("⚠️ Открытых инцидентов сейчас: <b>%d</b>", openCnt))
	}
	if extraFn != nil {
		for _, ex := range extraFn() {
			if strings.TrimSpace(ex) != "" {
				lines = append(lines, ex)
			}
		}
	}
	n.Notify(TGKindDigest, "digest:"+day, "Ежедневная сводка AmneziaWG", strings.Join(lines, "\n"))
}

func (n *TGNotifier) worker() {
	var deferred []tgEvent
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	processOne := func(ev tgEvent) {
		st := n.settings.Get()
		if !st.TGEnabled || st.TGBotToken == "" || st.TGChatID == "" {
			return
		}
		if err := n.waitChatPace(st.TGChatID); err != nil {
			return
		}
		msgID, retryAfter, retryable, err := n.sendEventWithFallback(st, ev)
		if err == nil {
			if ev.onSent != nil {
				ev.onSent(msgID)
			}
			return
		}
		if retryable && ev.attempt < 4 {
			delay := retryAfter
			if delay <= 0 {
				backoffs := []time.Duration{4 * time.Second, 12 * time.Second, 35 * time.Second, 90 * time.Second}
				delay = backoffs[ev.attempt]
			}
			ev.attempt++
			ev.notBefore = n.currentNow().Add(delay)
			if len(deferred) < 64 {
				deferred = append(deferred, ev)
			}
			return
		}
		if n.logger != nil {
			n.logger.Logf("WARN Telegram send failed (%s): %v", ev.title, err)
		}
	}

	for {
		select {
		case <-n.stopCh:
			return
		case ev := <-n.queue:
			processOne(ev)
		case <-ticker.C:
			if len(deferred) == 0 {
				continue
			}
			now := n.currentNow()
			var remaining []tgEvent
			for _, ev := range deferred {
				if !ev.notBefore.After(now) {
					processOne(ev)
				} else {
					remaining = append(remaining, ev)
				}
			}
			deferred = remaining
		}
	}
}

func (n *TGNotifier) waitChatPace(chatID string) error {
	// Skip artificial pacing sleep in unit tests using mock senders
	if n.isMockTransport() {
		return nil
	}
	return n.waitChatPaceCtx(context.Background(), chatID)
}

func (n *TGNotifier) waitChatPaceCtx(ctx context.Context, chatID string) error {
	if n.isMockTransport() {
		return nil
	}
	chatID = strings.TrimSpace(chatID)
	if chatID == "" {
		return nil
	}
	isGroup := strings.HasPrefix(chatID, "-")
	capacity := 3.0
	refillPerSec := 1.0 / 1.1 // Private chat: ~1 msg/sec
	if isGroup {
		capacity = 4.0
		refillPerSec = 1.0 / 3.2 // Group / supergroup: <= 18.75 msg/min (Telegram cap: 20/min)
	}

	for {
		n.mu.Lock()
		now := n.nowFn()
		b, ok := n.chatBuckets[chatID]
		if !ok {
			b = &tgChatBucket{tokens: capacity, lastRefill: now}
			n.chatBuckets[chatID] = b
		}
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * refillPerSec
			if b.tokens > capacity {
				b.tokens = capacity
			}
			b.lastRefill = now
		}
		if b.tokens >= 1.0 {
			b.tokens -= 1.0
			n.mu.Unlock()
			return nil
		}
		needSec := (1.0 - b.tokens) / refillPerSec
		n.mu.Unlock()

		waitDur := time.Duration(needSec*1000+25) * time.Millisecond
		select {
		case <-n.stopCh:
			return errors.New("notifier stopped")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDur):
		}
	}
}

func (n *TGNotifier) isMockTransport() bool {
	if n.forcePace {
		return false
	}
	if n.sendHTTPFn != nil && reflect.ValueOf(n.sendHTTPFn).Pointer() != n.origSendHTTPPtr {
		return true
	}
	if n.sendMethodFn != nil && reflect.ValueOf(n.sendMethodFn).Pointer() != n.origSendMethodPtr {
		return true
	}
	return false
}

func (n *TGNotifier) sendSyncWithSettings(st AppSettings, kind TGEventKind, title, body string) (int64, error) {
	return n.sendSyncWithOpts(st, kind, title, body, 0, false)
}

func (n *TGNotifier) sendSyncWithOpts(st AppSettings, kind TGEventKind, title, body string, replyToMsgID int64, forceSilent bool) (int64, error) {
	msgID, _, _, err := n.sendEventWithFallback(st, tgEvent{
		kind:         kind,
		title:        title,
		body:         body,
		replyToMsgID: replyToMsgID,
	}, forceSilent)
	return msgID, err
}

func eventIcon(kind TGEventKind) string {
	switch kind {
	case TGKindStart:
		return "✅"
	case TGKindFailover:
		return "🔁"
	case TGKindDown:
		return "🔴"
	case TGKindRecovery:
		return "🟢"
	case TGKindWarn:
		return "🟡"
	case TGKindConfig:
		return "⚙️"
	case TGKindSecurity:
		return "🛡"
	case TGKindDigest:
		return "📊"
	case TGKindTest:
		return "🔔"
	default:
		return "ℹ️"
	}
}

func (n *TGNotifier) sendEventWithFallback(st AppSettings, ev tgEvent, extraSilent ...bool) (int64, time.Duration, bool, error) {
	if st.TGBotToken == "" || st.TGChatID == "" {
		return 0, 0, false, fmt.Errorf("tg_bot_token and tg_chat_id are required")
	}

	node := strings.TrimSpace(st.TGNodeName)
	if node == "" {
		node = "routeros-awg"
	}
	text := fmt.Sprintf("%s <b>[%s] %s</b>", eventIcon(ev.kind), html.EscapeString(node), html.EscapeString(ev.title))
	if strings.TrimSpace(ev.body) != "" {
		text += "\n" + ev.body
	}
	text = truncateUTF8(text, 4000)

	threadID := st.TGThreadID
	if (ev.kind == TGKindFailover || ev.kind == TGKindDown) && st.TGAlertThreadID > 0 {
		threadID = st.TGAlertThreadID
	}

	silent := shouldSilenceNotification(st, ev.kind, n.currentNow())
	if len(extraSilent) > 0 && extraSilent[0] {
		silent = true
	}

	sendOnce := func(useHTML bool, useThread int) (int64, *tgAPIError, error) {
		msgText := text
		reqObj := map[string]any{
			"chat_id":                  st.TGChatID,
			"disable_web_page_preview": true,
		}
		if useHTML {
			reqObj["parse_mode"] = "HTML"
		} else {
			msgText = truncateUTF8(stripHTMLTags(text), 4000)
		}
		reqObj["text"] = msgText
		if useThread > 0 {
			reqObj["message_thread_id"] = useThread
		}
		if silent {
			reqObj["disable_notification"] = true
		}
		if ev.replyToMsgID > 0 {
			reqObj["reply_parameters"] = map[string]any{
				"message_id":                    ev.replyToMsgID,
				"allow_sending_without_reply":   true,
			}
		}

		payload, err := json.Marshal(reqObj)
		if err != nil {
			return 0, nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		status, respBody, reqErr := n.sendHTTPFn(ctx, st.TGVia, st.TGAPIURL, st.TGBotToken, payload)
		if reqErr != nil {
			cleanErr := errors.New(redactTelegramSecrets(reqErr.Error(), st.TGBotToken))
			return 0, nil, cleanErr
		}
		msgID, apiErr := parseTGAPIResponse(status, respBody, useThread)
		if apiErr != nil {
			return 0, apiErr, apiErr
		}
		return msgID, nil, nil
	}

	msgID, apiErr, err := sendOnce(true, threadID)
	if apiErr != nil && apiErr.Status == http.StatusBadRequest {
		low := strings.ToLower(apiErr.Desc)
		// Fallback 1: broken HTML tags/entities -> retry as clean plain text
		if strings.Contains(low, "can't parse entities") || strings.Contains(low, "parse entities") {
			msgID, apiErr, err = sendOnce(false, threadID)
		}
		// Fallback 2: wrong/missing forum thread -> record warning and retry without thread for critical alerts (unless testing strict topic)
		if apiErr != nil && threadID > 0 && strings.Contains(low, "thread") && strings.Contains(low, "not found") {
			n.mu.Lock()
			n.topicError = fmt.Sprintf("Топик #%d не найден в чате %s", threadID, st.TGChatID)
			n.mu.Unlock()
			if !ev.noThreadFallback && isCriticalEventKind(ev.kind) {
				msgID, apiErr, err = sendOnce(!strings.Contains(low, "parse entities"), 0)
			}
		}
	}

	if err != nil {
		n.recordResult(err)
		if apiErr != nil {
			retryable := apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500
			return 0, apiErr.RetryAfter, retryable, err
		}
		return 0, 0, true, err
	}

	if threadID > 0 {
		n.mu.Lock()
		n.topicError = ""
		n.mu.Unlock()
	}
	n.recordResult(nil)
	return msgID, 0, false, nil
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
	n.lastSentAt = n.nowFn().Unix()
	n.lastError = ""
}

func (n *TGNotifier) defaultSendHTTP(ctx context.Context, via, apiURL, token string, payload []byte) (int, []byte, error) {
	return n.callMethodHTTP(ctx, via, apiURL, token, "sendMessage", "application/json", payload)
}

func (n *TGNotifier) callMethodHTTP(ctx context.Context, via, apiURL, token, method, contentType string, payload []byte) (int, []byte, error) {
	if apiURL == "" {
		apiURL = DefaultTelegramAPI
	}
	if err := validateHTTPURL(apiURL); err != nil {
		return 0, nil, fmt.Errorf("некорректный tg_api_url: %w", err)
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/bot" + token + "/" + strings.TrimLeft(method, "/")
	isMedia := method == "sendPhoto" || method == "sendDocument"

	doPost := func(cli *http.Client, attemptTimeout time.Duration) (int, []byte, error) {
		subCtx := ctx
		var cancel context.CancelFunc
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > attemptTimeout {
			subCtx, cancel = context.WithTimeout(ctx, attemptTimeout)
		}
		if cancel != nil {
			defer cancel()
		}
		req, err := http.NewRequestWithContext(subCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, errors.New(redactTelegramSecrets(err.Error(), token))
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := cli.Do(req)
		if err != nil {
			return 0, nil, errors.New(redactTelegramSecrets(err.Error(), token))
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, b, nil
	}

	dirTimeout := 7 * time.Second
	tunTimeout := 10 * time.Second
	if isMedia {
		dirTimeout = 15 * time.Second
		tunTimeout = 18 * time.Second
	}

	switch via {
	case "direct":
		return doPost(n.directClient, dirTimeout)
	case "tunnel":
		return doPost(n.tunClient, tunTimeout)
	default: // "auto": sticky-route aware + isolated attempt timeout so blocked direct doesn't starve tunnel
		tunnelUp := n.mgr != nil && n.mgr.PrimaryInterface() != ""
		n.mu.Lock()
		preferTun := tunnelUp && n.stickyVia == "tunnel" && n.nowFn().Sub(n.stickyAt) < 5*time.Minute
		n.mu.Unlock()

		firstVia, secondVia := "direct", "tunnel"
		firstCli, secondCli := n.directClient, n.tunClient
		firstTO, secondTO := dirTimeout, tunTimeout
		if preferTun {
			firstVia, secondVia = "tunnel", "direct"
			firstCli, secondCli = n.tunClient, n.directClient
			firstTO, secondTO = tunTimeout, dirTimeout
		}

		st, b, err := doPost(firstCli, firstTO)
		if err == nil {
			n.mu.Lock()
			n.stickyVia = firstVia
			n.stickyAt = n.nowFn()
			n.mu.Unlock()
			return st, b, nil
		}
		if (secondVia == "tunnel" && !tunnelUp) || ctx.Err() != nil {
			return st, b, err
		}
		st2, b2, err2 := doPost(secondCli, secondTO)
		if err2 == nil {
			n.mu.Lock()
			n.stickyVia = secondVia
			n.stickyAt = n.nowFn()
			n.mu.Unlock()
			return st2, b2, nil
		}
		return st, b, err
	}
}

func parseTGAPIResponse(status int, respBody []byte, threadID int) (int64, *tgAPIError) {
	var apiResp struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	_ = json.Unmarshal(respBody, &apiResp)
	if status < 400 && apiResp.OK {
		return apiResp.Result.MessageID, nil
	}
	msg := apiResp.Description
	if msg == "" {
		msg = strings.TrimSpace(string(respBody))
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", status)
	}
	code := apiResp.ErrorCode
	if code == 0 {
		code = status
	}
	var retryAfter time.Duration
	if code == http.StatusTooManyRequests && apiResp.Parameters.RetryAfter > 0 {
		retryAfter = time.Duration(apiResp.Parameters.RetryAfter+1) * time.Second
	}
	lower := strings.ToLower(msg)
	friendly := fmt.Sprintf("telegram (%d): %s", code, msg)
	switch {
	case strings.Contains(lower, "chat not found") || strings.Contains(lower, "bot was blocked") || strings.Contains(lower, "can't initiate") || strings.Contains(lower, "user is deactivated"):
		friendly = fmt.Sprintf("telegram (%d): %s — пользователь должен сначала нажать /start у бота", code, msg)
	case strings.Contains(lower, "thread") && strings.Contains(lower, "not found"):
		friendly = fmt.Sprintf("telegram (%d): топик #%d не найден — проверьте message_thread_id или права бота в форуме", code, threadID)
	}
	return 0, &tgAPIError{
		Status:     status,
		Code:       code,
		Desc:       msg,
		RetryAfter: retryAfter,
		Friendly:   friendly,
	}
}

func buildTGMultipart(fields map[string]string, fileField, fileName string, fileData []byte) (string, []byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return "", nil, err
		}
	}
	part, err := w.CreateFormFile(fileField, fileName)
	if err != nil {
		return "", nil, err
	}
	if _, err := part.Write(fileData); err != nil {
		return "", nil, err
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	return w.FormDataContentType(), buf.Bytes(), nil
}

func (n *TGNotifier) callMethodWithRetry(ctx context.Context, st AppSettings, chatID, method, contentType string, payload []byte, threadID int) error {
	callFn := n.sendMethodFn
	if callFn == nil {
		callFn = n.callMethodHTTP
	}
	token := strings.TrimSpace(st.TGBotToken)
	for attempt := 0; attempt < 2; attempt++ {
		if err := n.waitChatPaceCtx(ctx, chatID); err != nil {
			return err
		}
		status, respBody, reqErr := callFn(ctx, st.TGVia, st.TGAPIURL, token, method, contentType, payload)
		if reqErr != nil {
			cleanErr := errors.New(redactTelegramSecrets(reqErr.Error(), token))
			n.recordResult(cleanErr)
			return cleanErr
		}
		_, apiErr := parseTGAPIResponse(status, respBody, threadID)
		if apiErr == nil {
			return nil
		}
		if apiErr.Status == http.StatusTooManyRequests && apiErr.RetryAfter > 0 && apiErr.RetryAfter <= 15*time.Second && attempt == 0 {
			select {
			case <-n.stopCh:
				return apiErr
			case <-ctx.Done():
				return apiErr
			case <-time.After(apiErr.RetryAfter):
				continue
			}
		}
		n.recordResult(apiErr)
		return apiErr
	}
	return nil
}

func (n *TGNotifier) SendClientConfig(ctx context.Context, chatID string, threadID int, vpsName, clientName, reason, confText, vpnURL, subURL string) error {
	return n.SendClientConfigWithOptions(ctx, chatID, threadID, vpsName, clientName, reason, confText, vpnURL, subURL, true)
}

// SendClientConfigWithOptions delivers updated VPN config according to st.TGDeliveryMode:
// - "off": disabled
// - "notify_only": single text notice (+ CopyText button for subscription URL <= 256 bytes)
// - "compact": QR + .conf on creation/manual send, .conf only on rotation/update
// - "full": QR + .conf (2 messages + CopyText button if subURL <= 256)
// - "full_vpn": QR + .conf + expandable vpn:// message
func (n *TGNotifier) SendClientConfigWithOptions(ctx context.Context, chatID string, threadID int, vpsName, clientName, reason, confText, vpnURL, subURL string, isCreation bool) error {
	if n.settings == nil {
		return fmt.Errorf("settings unavailable")
	}
	st := n.settings.Get()
	token := strings.TrimSpace(st.TGBotToken)
	if token == "" {
		return fmt.Errorf("не задан Bot Token в Настройки → Telegram")
	}
	mode := normalizeTGDeliveryMode(st.TGDeliveryMode)
	if mode == "off" {
		return fmt.Errorf("доставка конфигов клиентам отключена (Настройки → Telegram → Доставка клиентам)")
	}
	chatID = strings.TrimSpace(chatID)
	if chatID == "" {
		return fmt.Errorf("не указан Telegram chat_id получателя")
	}
	if strings.TrimSpace(confText) == "" {
		return fmt.Errorf("пустой текст конфигурации")
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
	}

	epLine := ""
	for _, ln := range strings.Split(confText, "\n") {
		tr := strings.TrimSpace(ln)
		if strings.HasPrefix(tr, "Endpoint") && strings.Contains(tr, "=") {
			epLine = strings.TrimSpace(strings.SplitN(tr, "=", 2)[1])
			break
		}
	}
	reasonTxt := strings.TrimSpace(reason)
	if reasonTxt == "" {
		reasonTxt = "Обновление конфигурации"
	}
	reasonTxt = truncateUTF8(reasonTxt, 240)

	silent := st.TGSilent || (st.TGQuietHours != "" && isInQuietHours(st.TGQuietHours, st.TGDigestTZOffset, n.currentNow()))

	// CopyTextButton limit in Telegram Bot API is 256 chars; ideal for /sub/<token> links.
	var copyMarkupJSON string
	if subURL != "" && len(subURL) <= 256 {
		markup := map[string]any{
			"inline_keyboard": [][]map[string]any{
				{{"text": "📋 Скопировать ссылку подписки", "copy_text": map[string]string{"text": subURL}}},
			},
		}
		if b, err := json.Marshal(markup); err == nil {
			copyMarkupJSON = string(b)
		}
	}

	if mode == "notify_only" {
		txt := fmt.Sprintf("🔄 <b>AmneziaWG — %s</b>\n📡 Сервер: <code>%s</code>",
			html.EscapeString(clientName), html.EscapeString(vpsName))
		if epLine != "" {
			txt += fmt.Sprintf("\n🌐 Endpoint: <code>%s</code>", html.EscapeString(epLine))
		}
		txt += fmt.Sprintf("\nℹ️ %s", html.EscapeString(reasonTxt))
		if subURL != "" {
			txt += "\nЕсли используется автоподписка, настройки обновятся автоматически."
		}
		msgObj := map[string]any{
			"chat_id":                  chatID,
			"text":                     truncateUTF8(txt, 4000),
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
		}
		if threadID > 0 {
			msgObj["message_thread_id"] = threadID
		}
		if silent {
			msgObj["disable_notification"] = true
		}
		if copyMarkupJSON != "" {
			msgObj["reply_markup"] = json.RawMessage(copyMarkupJSON)
		}
		body, _ := json.Marshal(msgObj)
		err := n.callMethodWithRetry(ctx, st, chatID, "sendMessage", "application/json", body, threadID)
		if err != nil && copyMarkupJSON != "" {
			if ae, ok := err.(*tgAPIError); ok && ae.Status == http.StatusBadRequest {
				delete(msgObj, "reply_markup")
				body2, _ := json.Marshal(msgObj)
				err = n.callMethodWithRetry(ctx, st, chatID, "sendMessage", "application/json", body2, threadID)
			}
		}
		if err != nil {
			return err
		}
		n.recordResult(nil)
		return nil
	}

	sendQR := mode != "compact" || isCreation
	if sendQR {
		qrPNG, err := qrcode.Encode(confText, qrcode.Medium, 320)
		if err != nil {
			qrPNG, err = qrcode.Encode(confText, qrcode.Low, 320)
		}
		if err == nil && len(qrPNG) > 0 {
			capLines := []string{
				fmt.Sprintf("🔐 <b>AmneziaWG 3.1 — %s</b>", html.EscapeString(clientName)),
				fmt.Sprintf("📡 Сервер: <code>%s</code>", html.EscapeString(vpsName)),
			}
			if epLine != "" {
				capLines = append(capLines, fmt.Sprintf("🌐 Endpoint: <code>%s</code>", html.EscapeString(truncateUTF8(epLine, 120))))
			}
			capLines = append(capLines, fmt.Sprintf("ℹ️ %s", html.EscapeString(reasonTxt)))
			capLines = append(capLines, "\nСканируйте QR в <b>AmneziaWG / AmneziaVPN</b> или импортируйте файл ниже.")
			photoCap := strings.Join(capLines, "\n")
			if len(photoCap) > 1000 {
				photoCap = truncateUTF8(stripHTMLTags(photoCap), 1000)
			}

			fields := map[string]string{
				"chat_id":    chatID,
				"caption":    photoCap,
				"parse_mode": "HTML",
			}
			if threadID > 0 {
				fields["message_thread_id"] = strconv.Itoa(threadID)
			}
			if silent {
				fields["disable_notification"] = "true"
			}
			ct, body, mErr := buildTGMultipart(fields, "photo", clientName+".png", qrPNG)
			if mErr != nil {
				return mErr
			}
			if err := n.callMethodWithRetry(ctx, st, chatID, "sendPhoto", ct, body, threadID); err != nil {
				return err
			}
		}
	}

	// Send .conf file via sendDocument
	docCap := fmt.Sprintf("📄 <b>%s.conf</b> (%s)", html.EscapeString(clientName), html.EscapeString(vpsName))
	if !sendQR {
		if epLine != "" {
			docCap += fmt.Sprintf("\n🌐 Endpoint: <code>%s</code>", html.EscapeString(truncateUTF8(epLine, 120)))
		}
		docCap += fmt.Sprintf("\nℹ️ %s", html.EscapeString(reasonTxt))
	}
	if subURL != "" {
		subLine := fmt.Sprintf("\n🔗 Подписка: <code>%s</code>", html.EscapeString(subURL))
		if len(docCap)+len(subLine) <= 1000 {
			docCap += subLine
		}
	}
	if len(docCap) > 1000 {
		docCap = truncateUTF8(stripHTMLTags(docCap), 1000)
	}
	docFields := map[string]string{
		"chat_id":    chatID,
		"caption":    docCap,
		"parse_mode": "HTML",
	}
	if threadID > 0 {
		docFields["message_thread_id"] = strconv.Itoa(threadID)
	}
	if silent {
		docFields["disable_notification"] = "true"
	}
	if copyMarkupJSON != "" {
		docFields["reply_markup"] = copyMarkupJSON
	}
	ctDoc, bodyDoc, err := buildTGMultipart(docFields, "document", clientName+".conf", []byte(confText))
	if err != nil {
		return err
	}
	err = n.callMethodWithRetry(ctx, st, chatID, "sendDocument", ctDoc, bodyDoc, threadID)
	if err != nil && copyMarkupJSON != "" {
		if ae, ok := err.(*tgAPIError); ok && ae.Status == http.StatusBadRequest {
			delete(docFields, "reply_markup")
			if ctDoc2, bodyDoc2, mErr := buildTGMultipart(docFields, "document", clientName+".conf", []byte(confText)); mErr == nil {
				err = n.callMethodWithRetry(ctx, st, chatID, "sendDocument", ctDoc2, bodyDoc2, threadID)
			}
		}
	}
	if err != nil {
		return err
	}

	// Optionally send vpn:// link in expandable blockquote for full_vpn mode
	if mode == "full_vpn" && vpnURL != "" && len(vpnURL) < 3800 {
		msgObj := map[string]any{
			"chat_id":                  chatID,
			"text":                     fmt.Sprintf("⚡ <b>Ссылка AmneziaVPN (<code>%s</code>):</b>\n<blockquote expandable><code>%s</code></blockquote>", html.EscapeString(clientName), html.EscapeString(vpnURL)),
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
		}
		if threadID > 0 {
			msgObj["message_thread_id"] = threadID
		}
		if silent {
			msgObj["disable_notification"] = true
		}
		if msgBody, mErr := json.Marshal(msgObj); mErr == nil {
			_ = n.callMethodWithRetry(ctx, st, chatID, "sendMessage", "application/json", msgBody, threadID)
		}
	}

	n.recordResult(nil)
	return nil
}

type netDialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)
