package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SubscriptionManager handles automatic and on-demand syncing of WireGuard/AmneziaWG configs
// from remote HTTP(S) endpoints, subscription URLs, or client tokens.
type SubscriptionManager struct {
	mu            sync.Mutex
	settings      *SettingsStore
	mgr           *TunnelManager
	tg            *TGNotifier
	logger        *RingLogger
	client        *http.Client
	stopCh        chan struct{}
	stopped       bool
	lastFailCheck map[string]time.Time
}

func NewSubscriptionManager(settings *SettingsStore, mgr *TunnelManager, tg *TGNotifier, logger *RingLogger) *SubscriptionManager {
	return &SubscriptionManager{
		settings: settings,
		mgr:      mgr,
		tg:       tg,
		logger:   logger,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		stopCh:        make(chan struct{}),
		lastFailCheck: make(map[string]time.Time),
	}
}

// cleanHost strips schema, path, brackets, and all trailing port segments from a host/endpoint string.
func cleanHost(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	// Check bracketed IPv6 first: e.g. [2001:db8::1]:1234
	if strings.HasPrefix(raw, "[") {
		if idx := strings.Index(raw, "]"); idx != -1 {
			return raw[1:idx]
		}
	}
	// If it contains dots, it is an IPv4 or domain name.
	// Strip ANY and ALL trailing :port segments (even if accidentally repeated, e.g. 1.2.3.4:111:222)
	if strings.Contains(raw, ".") {
		if idx := strings.Index(raw, ":"); idx != -1 {
			return strings.Trim(raw[:idx], "[]")
		}
		return strings.Trim(raw, "[]")
	}
	// Standard SplitHostPort
	if h, _, err := net.SplitHostPort(raw); err == nil && h != "" {
		return strings.Trim(h, "[]")
	}
	raw = strings.Trim(raw, "[]")
	if idx := strings.LastIndex(raw, ":"); idx != -1 && !strings.Contains(raw[:idx], ":") {
		return raw[:idx]
	}
	return raw
}

// EffectiveURL resolves the actual subscription endpoint for a config:
// 1. If explicit URL is given (http://, https://, vpn://), use it (auto-cleaning any chained ports).
// 2. If Token is given, construct http://<host>:<port>/sub/<token> using APIHost or config Endpoint.
func (sm *SubscriptionManager) EffectiveURL(sub SubscriptionConfig, cfgName string) string {
	rawURL := strings.TrimSpace(sub.URL)
	if strings.HasPrefix(strings.ToLower(rawURL), "vpn://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		scheme := "http://"
		rest := rawURL[len("http://"):]
		if strings.HasPrefix(rawURL, "https://") {
			scheme = "https://"
			rest = rawURL[len("https://"):]
		}
		pathIdx := strings.Index(rest, "/")
		var hostPortStr, pathStr string
		if pathIdx != -1 {
			hostPortStr = rest[:pathIdx]
			pathStr = rest[pathIdx:]
		} else {
			hostPortStr = rest
			pathStr = ""
		}
		lastPort := ""
		if idx := strings.LastIndex(hostPortStr, ":"); idx != -1 {
			p := hostPortStr[idx+1:]
			if _, err := strconv.Atoi(p); err == nil {
				lastPort = p
			}
		}
		cleanH := cleanHost(hostPortStr)
		if cleanH != "" {
			if lastPort != "" {
				if strings.Contains(cleanH, ":") && !strings.HasPrefix(cleanH, "[") {
					cleanH = fmt.Sprintf("[%s]:%s", cleanH, lastPort)
				} else {
					cleanH = fmt.Sprintf("%s:%s", cleanH, lastPort)
				}
			}
			return scheme + cleanH + pathStr
		}
		return rawURL
	}

	token := strings.TrimSpace(sub.Token)
	if token == "" && strings.HasPrefix(rawURL, "awg_tok_") {
		token = rawURL
	}
	if token == "" {
		return ""
	}

	host := cleanHost(sub.APIHost)
	if host == "" {
		// Try to extract host from existing config Endpoint
		if sm.mgr != nil {
			cfgs, _ := sm.mgr.ListConfigs()
			baseName := strings.TrimSuffix(cfgName, ".conf")
			for _, c := range cfgs {
				cBase := strings.TrimSuffix(c.Name, ".conf")
				if (c.Name == cfgName || cBase == baseName) && c.Endpoint != "" {
					host = cleanHost(c.Endpoint)
					if host != "" {
						break
					}
				}
			}
		}
	}

	if host == "" {
		return ""
	}

	port := sub.APIPort
	if port <= 0 {
		port = 8443
	}

	var hostPort string
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		hostPort = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		hostPort = fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("http://%s/sub/%s", hostPort, token)
}

// FetchSubscription retrieves configuration content from a resolved subscription URL.
// If currentETag is provided and server returns 304 Not Modified, notModified will be true.
func (sm *SubscriptionManager) FetchSubscription(ctx context.Context, rawURL, currentETag string) (string, string, bool, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", false, fmt.Errorf("URL подписки пуст")
	}

	// 1. Support for Amnezia vpn:// format
	if strings.HasPrefix(strings.ToLower(rawURL), "vpn://") {
		content, err := decodeVPNURI(rawURL)
		if err != nil {
			return "", "", false, fmt.Errorf("ошибка декодирования vpn://: %w", err)
		}
		return content, "", false, nil
	}

	// 2. HTTP / HTTPS endpoints
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", "", false, fmt.Errorf("неверный формат URL: поддерживаются http://, https:// или vpn://")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("ошибка создания запроса: %w", err)
	}
	req.Header.Set("User-Agent", "AmneziaWG-Mikrotik-Client/"+AppVersion)
	req.Header.Set("Accept", "text/plain, application/json, */*")

	cleanETag := strings.Trim(strings.TrimSpace(currentETag), "\"")
	if cleanETag != "" {
		req.Header.Set("If-None-Match", `"`+cleanETag+`"`)
	}

	resp, err := sm.client.Do(req)
	if err != nil {
		return "", "", false, fmt.Errorf("ошибка сети при обращении к серверу подписки: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return "", cleanETag, true, nil
	}

	if resp.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", false, fmt.Errorf("сервер подписки вернул HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodySnippet)))
	}

	newETag := strings.Trim(strings.TrimSpace(resp.Header.Get("ETag")), "\"")
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB cap
	if err != nil {
		return "", "", false, fmt.Errorf("ошибка чтения ответа: %w", err)
	}

	rawBody := strings.TrimSpace(string(bodyBytes))
	if rawBody == "" {
		return "", "", false, fmt.Errorf("сервер подписки вернул пустой ответ")
	}

	// Parse JSON if body starts with '{'
	if strings.HasPrefix(rawBody, "{") {
		parsed, err := parseJSONSubscription(bodyBytes)
		if err == nil && parsed != "" {
			return parsed, newETag, false, nil
		}
	}

	// Check if body is vpn://
	if strings.HasPrefix(strings.ToLower(rawBody), "vpn://") {
		parsed, err := decodeVPNURI(rawBody)
		if err == nil && parsed != "" {
			return parsed, newETag, false, nil
		}
	}

	// Plain .conf format
	return rawBody, newETag, false, nil
}

// Sync updates a single config from its configured token / subscription URL.
func (sm *SubscriptionManager) Sync(ctx context.Context, cfgName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	st := sm.settings.Get()
	sub, exists := st.Subscriptions[cfgName]
	if !exists {
		return fmt.Errorf("подписка для %s не настроена", cfgName)
	}

	targetURL := sm.EffectiveURL(sub, cfgName)
	if targetURL == "" {
		err := fmt.Errorf("не удалось составить URL подписки: укажите токен и проверьте endpoint")
		sub.LastSync = time.Now()
		sub.LastStatus = "error: " + err.Error()
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		return err
	}

	content, newETag, notModified, err := sm.FetchSubscription(ctx, targetURL, sub.LastETag)
	if err != nil {
		sub.LastSync = time.Now()
		sub.LastStatus = "error: " + err.Error()
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		return err
	}

	if notModified {
		sub.LastSync = time.Now()
		sub.LastStatus = "not_modified"
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		sm.logger.Logf("[subscription] %s: 304 Not Modified (ETag: %s)", cfgName, sub.LastETag)
		return nil
	}

	if err := ValidateConfig(content); err != nil {
		sub.LastSync = time.Now()
		sub.LastStatus = "invalid config: " + err.Error()
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		return fmt.Errorf("полученный конфиг не прошёл валидацию: %w", err)
	}

	if err := sm.mgr.SaveConfig(cfgName, content); err != nil {
		sub.LastSync = time.Now()
		sub.LastStatus = "save error: " + err.Error()
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		return fmt.Errorf("ошибка сохранения конфига %s: %w", cfgName, err)
	}

	// Apply updated config seamlessly
	if err := sm.mgr.ApplySavedConfig(cfgName); err != nil {
		sub.LastSync = time.Now()
		sub.LastStatus = "apply error: " + err.Error()
		_, _ = sm.settings.SetSubscription(cfgName, sub)
		return fmt.Errorf("ошибка применения конфига %s: %w", cfgName, err)
	}

	sub.LastSync = time.Now()
	sub.LastETag = newETag
	sub.LastStatus = "ok"
	_, _ = sm.settings.SetSubscription(cfgName, sub)

	sm.logger.Logf("[subscription] SUCCESS: %s обновлён из подписки (ETag: %s)", cfgName, newETag)
	if sm.tg != nil {
		sm.tg.Notify(TGKindConfig, "sub:"+cfgName, "Профиль обновлён из подписки",
			fmt.Sprintf("Профиль <b>%s</b> успешно обновлён через Subscription API (ETag: <code>%s</code>).", cfgName, newETag))
	}

	return nil
}

// OnTunnelFailure is triggered when failover detects handshake loss or UNHEALTHY state.
func (sm *SubscriptionManager) OnTunnelFailure(cfgName string) {
	st := sm.settings.Get()
	sub, exists := st.Subscriptions[cfgName]
	if !exists || !sub.SyncOnFailure {
		return
	}

	sm.mu.Lock()
	last := sm.lastFailCheck[cfgName]
	if time.Since(last) < 20*time.Second {
		sm.mu.Unlock()
		return
	}
	sm.lastFailCheck[cfgName] = time.Now()
	sm.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		sm.logger.Logf("[subscription] UNHEALTHY trigger: опрос подписки для восстановления %s...", cfgName)
		_ = sm.Sync(ctx, cfgName)
	}()
}

// SyncAll syncs all configured subscriptions. If onlyAuto is true, only subscriptions with AutoUpdate=true are synced.
func (sm *SubscriptionManager) SyncAll(ctx context.Context, onlyAuto bool) map[string]error {
	st := sm.settings.Get()
	results := make(map[string]error)

	for name, sub := range st.Subscriptions {
		if onlyAuto && !sub.AutoUpdate {
			continue
		}
		if err := sm.Sync(ctx, name); err != nil {
			results[name] = err
		}
	}
	return results
}

// ImportSubscription imports a new profile from a subscription URL or token.
func (sm *SubscriptionManager) ImportSubscription(ctx context.Context, rawInput, preferredName string, activate bool) (string, error) {
	tempSub := SubscriptionConfig{
		URL:     rawInput,
		APIPort: 8443,
	}
	if strings.HasPrefix(strings.TrimSpace(rawInput), "awg_tok_") {
		tempSub.Token = strings.TrimSpace(rawInput)
		tempSub.URL = ""
	}

	targetURL := sm.EffectiveURL(tempSub, preferredName)
	if targetURL == "" {
		targetURL = strings.TrimSpace(rawInput)
	}

	content, newETag, _, err := sm.FetchSubscription(ctx, targetURL, "")
	if err != nil {
		return "", err
	}

	if err := ValidateConfig(content); err != nil {
		return "", fmt.Errorf("полученный конфиг не прошёл валидацию: %w", err)
	}

	targetName := strings.TrimSpace(preferredName)
	if targetName == "" {
		existing, _ := sm.mgr.ListConfigs()
		used := make(map[string]bool)
		for _, c := range existing {
			used[c.Name] = true
		}
		for i := 0; i < 100; i++ {
			cand := fmt.Sprintf("awg%d.conf", i)
			if !used[cand] {
				targetName = cand
				break
			}
		}
		if targetName == "" {
			targetName = "sub0.conf"
		}
	} else {
		if !strings.HasSuffix(targetName, ".conf") {
			targetName += ".conf"
		}
	}

	if err := sm.mgr.SaveConfig(targetName, content); err != nil {
		return "", fmt.Errorf("ошибка сохранения нового профиля %s: %w", targetName, err)
	}

	sub := SubscriptionConfig{
		Token:         tempSub.Token,
		APIPort:       8443,
		URL:           tempSub.URL,
		AutoUpdate:    true,
		IntervalMin:   30,
		SyncOnFailure: true,
		LastSync:      time.Now(),
		LastStatus:    "ok",
		LastETag:      newETag,
	}
	_, _ = sm.settings.SetSubscription(targetName, sub)

	if activate {
		if err := sm.mgr.ActivateConfig(targetName); err != nil {
			sm.logger.Logf("WARN: ошибка активации импортированного профиля %s: %v", targetName, err)
		}
	}

	sm.logger.Logf("[subscription] Импортирован новый профиль %s из %s (ETag: %s)", targetName, targetURL, newETag)
	return targetName, nil
}

// Start begins background periodic checking of subscriptions.
func (sm *SubscriptionManager) Start() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-sm.stopCh:
				return
			case <-ticker.C:
				sm.checkPendingAutoUpdates()
			}
		}
	}()
}

// Stop terminates the background ticker.
func (sm *SubscriptionManager) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if !sm.stopped {
		sm.stopped = true
		close(sm.stopCh)
	}
}

func (sm *SubscriptionManager) checkPendingAutoUpdates() {
	st := sm.settings.Get()
	now := time.Now()

	for name, sub := range st.Subscriptions {
		if !sub.AutoUpdate {
			continue
		}
		interval := sub.IntervalMin
		if interval <= 0 {
			interval = 30
		}
		if now.Sub(sub.LastSync) >= time.Duration(interval)*time.Minute {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			_ = sm.Sync(ctx, name)
			cancel()
		}
	}
}

// Helper: decode Amnezia vpn:// URI
func decodeVPNURI(uri string) (string, error) {
	trimmed := strings.TrimPrefix(uri, "vpn://")
	trimmed = strings.TrimPrefix(trimmed, "VPN://")

	rawBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		rawBytes, err = base64.URLEncoding.DecodeString(trimmed)
		if err != nil {
			return "", fmt.Errorf("неверный base64: %w", err)
		}
	}

	if strings.HasPrefix(strings.TrimSpace(string(rawBytes)), "{") {
		conf, err := parseJSONSubscription(rawBytes)
		if err == nil && conf != "" {
			return conf, nil
		}
	}

	return string(rawBytes), nil
}

// Helper: parse JSON subscription
func parseJSONSubscription(b []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}

	// 1. Direct "conf_base64"
	if b64, ok := m["conf_base64"].(string); ok && b64 != "" {
		if dec, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return string(dec), nil
		}
	}

	// 2. Direct "config" or "conf" string
	if conf, ok := m["config"].(string); ok && conf != "" {
		return conf, nil
	}
	if conf, ok := m["conf"].(string); ok && conf != "" {
		return conf, nil
	}

	// 3. Amnezia containers format
	if containers, ok := m["containers"].([]any); ok {
		for _, c := range containers {
			if cm, ok := c.(map[string]any); ok {
				if awg, ok := cm["awg"].(map[string]any); ok {
					if lastConf, ok := awg["last_config"].(string); ok && lastConf != "" {
						return lastConf, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("в JSON не найдена валидная конфигурация WireGuard/AmneziaWG")
}
