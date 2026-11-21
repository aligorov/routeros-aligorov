package main

import (
	"context"
	"fmt"
	"html"
	"sort"
	"strings"
	"sync"
	"time"
)

type TunnelHealth struct {
	Name            string `json:"name"`
	Interface       string `json:"interface"`
	Enabled         bool   `json:"enabled"`
	Primary         bool   `json:"primary"`
	Running         bool   `json:"running"`
	State           string `json:"state"` // "healthy" | "degraded" | "unhealthy" | "cooldown" | "standby" | "disabled"
	Reason          string `json:"reason,omitempty"`
	FailStreak      int    `json:"fail_streak"`
	HandshakeAgeSec int64  `json:"handshake_age_sec"` // -1 if never
	ProbeOK         *bool  `json:"probe_ok,omitempty"`
	ProbeRTTMs      int64  `json:"probe_rtt_ms,omitempty"`
	ProbeMethod     string `json:"probe_method,omitempty"`
	PingOK          *bool  `json:"ping_ok,omitempty"`
	PingRTTMs       int64  `json:"ping_rtt_ms,omitempty"`
	TCPOK           *bool  `json:"tcp_ok,omitempty"`
	TCPRTTMs        int64  `json:"tcp_rtt_ms,omitempty"`
	CooldownLeftSec int64  `json:"cooldown_left_sec,omitempty"`
	LastCheckAt     int64  `json:"last_check_at,omitempty"`
}

type FailoverStatus struct {
	Mode             string         `json:"mode"`
	Trigger          string         `json:"trigger"`
	IntervalSec      int            `json:"interval_sec"`
	Threshold        int            `json:"threshold"`
	CooldownSec      int            `json:"cooldown_sec"`
	ProbeTarget      string         `json:"probe_target"`
	ProbeMethod      string         `json:"probe_method"`
	Failback         bool           `json:"failback"`
	LastSwitchAt     int64          `json:"last_switch_at,omitempty"`
	LastSwitchReason string         `json:"last_switch_reason,omitempty"`
	SwitchesTotal    int            `json:"switches_total"`
	Tunnels          []TunnelHealth `json:"tunnels"`
}

type FailoverMonitor struct {
	mgr      *TunnelManager
	settings *SettingsStore
	tg       *TGNotifier
	logger   *RingLogger

	stopCh chan struct{}
	wakeCh chan struct{}

	mu                  sync.Mutex
	failStreak          map[string]int
	healthyStreak       map[string]int
	failbackStreak      map[string]int
	cooldownUntil       map[string]time.Time
	lastTX              map[string]uint64
	lastRX              map[string]uint64
	health              map[string]TunnelHealth
	lastOrder           []string
	lastSwitchAt        int64
	lastSwitchReason    string
	switchesTotal       int
	switchTimes         []time.Time
	flapSuppressedUntil time.Time

	// Injectable hooks for deterministic unit tests
	nowFn       func() time.Time
	probeFn     func(ctx context.Context, iface string, mark int, target string) (int64, error)
	pingFn      func(ctx context.Context, iface string, mark int, target string) (int64, error)
	directIface string
	ifacesFn    func() ([]InterfaceStatus, error)
	configsFn   func() ([]ConfigMeta, error)
	startedAtFn func(iface string) time.Time
	markFn      func(iface string) int
	switchFn    func(target string, standbyFast bool) error
	subMgr      *SubscriptionManager
}

func (f *FailoverMonitor) SetSubscriptionManager(sm *SubscriptionManager) {
	f.subMgr = sm
}

func NewFailoverMonitor(mgr *TunnelManager, settings *SettingsStore, tg *TGNotifier, logger *RingLogger) *FailoverMonitor {
	f := &FailoverMonitor{
		mgr:            mgr,
		settings:       settings,
		tg:             tg,
		logger:         logger,
		stopCh:         make(chan struct{}),
		wakeCh:         make(chan struct{}, 1),
		failStreak:     map[string]int{},
		healthyStreak:  map[string]int{},
		failbackStreak: map[string]int{},
		cooldownUntil:  map[string]time.Time{},
		lastTX:         map[string]uint64{},
		lastRX:         map[string]uint64{},
		health:         map[string]TunnelHealth{},
		nowFn:          time.Now,
	}
	f.probeFn = defaultTunnelProbe
	f.pingFn = defaultICMPPingProbe
	if mgr != nil {
		f.directIface = mgr.LanIface()
		f.ifacesFn = mgr.ShowInterfaces
		f.configsFn = mgr.ListConfigs
		f.startedAtFn = mgr.InterfaceStartedAt
		f.markFn = mgr.ProbeMarkForInterface
		f.switchFn = func(target string, standbyFast bool) error {
			if standbyFast {
				if err := mgr.SwitchPrimaryFast(target); err == nil {
					return nil
				}
			}
			return mgr.ActivateConfig(target)
		}
	}
	go f.loop()
	return f
}

func (f *FailoverMonitor) Stop() {
	select {
	case <-f.stopCh:
	default:
		close(f.stopCh)
	}
}

func (f *FailoverMonitor) Wake() {
	select {
	case f.wakeCh <- struct{}{}:
	default:
	}
}

func defaultICMPPingProbe(ctx context.Context, iface string, mark int, target string) (int64, error) {
	host := extractProbeHost(target)
	if host == "" {
		host = "1.1.1.1"
	}
	rtt, _, err := icmpPingHost(ctx, iface, mark, host, 3*time.Second)
	return rtt, err
}

func defaultTunnelProbe(ctx context.Context, iface string, mark int, target string) (int64, error) {
	dialer := sockBindDialer(iface, mark, 3*time.Second)
	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", normalizeTCPProbeTarget(target))
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	rtt := time.Since(t0).Milliseconds()
	if rtt < 1 {
		rtt = 1
	}
	return rtt, nil
}

func (f *FailoverMonitor) loop() {
	// Initial delay so container finishes starting before first failover probe
	select {
	case <-f.stopCh:
		return
	case <-time.After(10 * time.Second):
	}
	for {
		st := f.settings.Get()
		interval := time.Duration(st.FailoverIntervalSec) * time.Second
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
		f.CheckNow(false)
		select {
		case <-f.stopCh:
			return
		case <-f.wakeCh:
		case <-time.After(interval):
		}
	}
}

func (f *FailoverMonitor) Status() FailoverStatus {
	st := AppSettings{}
	if f.settings != nil {
		st = f.settings.Get()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.nowFn()
	list := make([]TunnelHealth, 0, len(f.lastOrder))
	for _, n := range f.lastOrder {
		if h, ok := f.health[n]; ok {
			if until, cd := f.cooldownUntil[n]; cd && until.After(now) {
				h.CooldownLeftSec = int64(until.Sub(now).Seconds()) + 1
			}
			list = append(list, h)
		}
	}
	return FailoverStatus{
		Mode:             st.FailoverMode,
		Trigger:          st.FailoverTrigger,
		IntervalSec:      st.FailoverIntervalSec,
		Threshold:        st.FailoverThreshold,
		CooldownSec:      st.FailoverCooldownSec,
		ProbeTarget:      st.FailoverProbeTarget,
		ProbeMethod:      normalizeProbeMethod(st.FailoverProbeMethod, st.FailoverProbeTarget),
		Failback:         st.FailoverFailback,
		LastSwitchAt:     f.lastSwitchAt,
		LastSwitchReason: f.lastSwitchReason,
		SwitchesTotal:    f.switchesTotal,
		Tunnels:          list,
	}
}

func (f *FailoverMonitor) SwitchTo(target string, reason string) error {
	if f.configsFn == nil || f.switchFn == nil {
		return fmt.Errorf("failover manager not initialized")
	}
	st := f.settings.Get()
	cfgs, err := f.configsFn()
	if err != nil {
		return err
	}
	ifaces, _ := f.ifacesFn()
	upMap := map[string]bool{}
	for _, i := range ifaces {
		upMap[i.Name] = true
	}

	var currentPrimary string
	var enabled []ConfigMeta
	for _, c := range cfgs {
		if c.Primary || c.Selected {
			currentPrimary = c.Name
		}
		if c.Enabled {
			enabled = append(enabled, c)
		}
	}

	if target == "" {
		if len(enabled) < 2 {
			return fmt.Errorf("нужно минимум 2 включённых профиля для переключения")
		}
		now := f.nowFn()
		f.mu.Lock()
		target = f.pickCandidateLocked(enabled, upMap, currentPrimary, now)
		f.mu.Unlock()
		if target == "" {
			return fmt.Errorf("нет доступного резервного профиля")
		}
	}

	standbyFast := (st.FailoverMode == "standby" || st.MultiTunnel) && upMap[trimConfExt(target)]
	if err := f.switchFn(target, standbyFast); err != nil {
		return err
	}

	if reason == "" {
		reason = "ручное переключение"
	}
	now := f.nowFn()
	nowUnix := now.Unix()
	isAuto := reason != "" && reason != "ручное переключение"
	var suppressTG, sendFlapWarn bool
	var recentCount int

	f.mu.Lock()
	f.failStreak[target] = 0
	f.lastSwitchAt = nowUnix
	f.lastSwitchReason = fmt.Sprintf("%s → %s (%s)", currentPrimary, target, reason)
	f.switchesTotal++
	if isAuto {
		kept := f.switchTimes[:0]
		for _, ts := range f.switchTimes {
			if now.Sub(ts) < 5*time.Minute {
				kept = append(kept, ts)
			}
		}
		kept = append(kept, now)
		f.switchTimes = kept
		recentCount = len(kept)
		if !now.After(f.flapSuppressedUntil) {
			suppressTG = true
		} else if recentCount >= 3 {
			f.flapSuppressedUntil = now.Add(15 * time.Minute)
			sendFlapWarn = true
			suppressTG = true
		}
	}
	f.mu.Unlock()

	if f.logger != nil {
		f.logger.Logf("Failover: switched %s -> %s (%s)", currentPrimary, target, reason)
	}
	if f.tg != nil {
		f.tg.ResolveIncident("blackout", "VPN-связь восстановлена", fmt.Sprintf("Переключено на <b>%s</b>", html.EscapeString(target)))
		if sendFlapWarn {
			f.tg.Notify(
				TGKindWarn,
				"flap",
				"Обнаружен флаппинг маршрута",
				fmt.Sprintf("%d переключений за 5 мин (последнее: <b>%s</b> → <b>%s</b>).\nУведомления о переключениях приглушены на 15 мин.",
					recentCount, html.EscapeString(currentPrimary), html.EscapeString(target)),
			)
		} else if !suppressTG {
			f.tg.Notify(
				TGKindFailover,
				"switch:"+currentPrimary+"->"+target,
				"Переключение туннеля",
				fmt.Sprintf("<b>%s</b> → <b>%s</b>\nПричина: %s",
					html.EscapeString(currentPrimary), html.EscapeString(target), html.EscapeString(reason)),
			)
		}
	}
	return nil
}

func trimConfExt(name string) string {
	if len(name) > 5 && name[len(name)-5:] == ".conf" {
		return name[:len(name)-5]
	}
	return name
}

func (f *FailoverMonitor) CheckNow(forceProbe bool) FailoverStatus {
	if f.configsFn == nil || f.ifacesFn == nil || f.settings == nil {
		return FailoverStatus{}
	}
	st := f.settings.Get()
	cfgs, err := f.configsFn()
	if err != nil {
		return f.Status()
	}
	ifaces, _ := f.ifacesFn()
	ifcMap := make(map[string]InterfaceStatus, len(ifaces))
	upMap := make(map[string]bool, len(ifaces))
	for _, ifc := range ifaces {
		ifcMap[ifc.Name] = ifc
		upMap[ifc.Name] = true
	}

	now := f.nowFn()
	allowProbe := forceProbe || (st.FailoverMode != "off" && st.FailoverTrigger != "handshake")

	var primaryCfg *ConfigMeta
	var topEnabledCfg *ConfigMeta
	var enabled []ConfigMeta
	for idx := range cfgs {
		c := cfgs[idx]
		if c.Enabled {
			enabled = append(enabled, c)
			if topEnabledCfg == nil {
				cc := c
				topEnabledCfg = &cc
			}
		}
		if c.Primary {
			cc := c
			primaryCfg = &cc
		}
	}
	if primaryCfg == nil {
		for idx := range cfgs {
			if cfgs[idx].Selected {
				cc := cfgs[idx]
				primaryCfg = &cc
				break
			}
		}
	}

	newHealth := make(map[string]TunnelHealth, len(cfgs))
	order := make([]string, 0, len(cfgs))
	var failedPrimaryReason string
	var unhealthyPrimary bool

	for _, c := range cfgs {
		order = append(order, c.Name)
		ifc, isUp := ifcMap[c.Interface]

		h := TunnelHealth{
			Name:            c.Name,
			Interface:       c.Interface,
			Enabled:         c.Enabled,
			Primary:         primaryCfg != nil && c.Name == primaryCfg.Name,
			Running:         isUp,
			HandshakeAgeSec: -1,
			LastCheckAt:     now.Unix(),
		}

		if c.Disabled {
			h.State = "disabled"
			h.Reason = "отключён"
			newHealth[c.Name] = h
			continue
		}

		f.mu.Lock()
		cdUntil := f.cooldownUntil[c.Name]
		inCD := cdUntil.After(now)
		prevStreak := f.failStreak[c.Name]
		f.mu.Unlock()
		if inCD {
			h.CooldownLeftSec = int64(cdUntil.Sub(now).Seconds()) + 1
		}

		if !isUp {
			isExpectedUp := h.Primary || st.MultiTunnel || st.FailoverMode == "standby"
			if !isExpectedUp {
				if inCD {
					h.State = "cooldown"
					h.Reason = fmt.Sprintf("пауза (%ds)", h.CooldownLeftSec)
				} else {
					h.State = "standby"
					h.Reason = "ожидание (резерв)"
				}
			} else {
				h.State = "unhealthy"
				if c.StartError != "" {
					h.Reason = c.StartError
				} else {
					h.Reason = "туннель не активен"
				}
				if h.Primary {
					unhealthyPrimary = true
					failedPrimaryReason = h.Reason
				}
			}
			newHealth[c.Name] = h
			continue
		}

		// Compute handshake age & RX/TX counters
		var bestHS int64 = -1
		var rxSum, txSum uint64
		for _, p := range ifc.Peers {
			rxSum += p.RxBytes
			txSum += p.TxBytes
			if p.HandshakeAgeSec >= 0 && (bestHS < 0 || p.HandshakeAgeSec < bestHS) {
				bestHS = p.HandshakeAgeSec
			}
		}
		h.HandshakeAgeSec = bestHS

		f.mu.Lock()
		prevTX := f.lastTX[c.Name]
		prevRX := f.lastRX[c.Name]
		var txDelta, rxDelta uint64
		if txSum >= prevTX {
			txDelta = txSum - prevTX
		}
		if rxSum >= prevRX {
			rxDelta = rxSum - prevRX
		}
		f.lastTX[c.Name] = txSum
		f.lastRX[c.Name] = rxSum
		f.mu.Unlock()

		var upAge time.Duration
		if f.startedAtFn != nil {
			if sa := f.startedAtFn(c.Interface); !sa.IsZero() {
				upAge = now.Sub(sa)
			} else {
				upAge = time.Hour
			}
		} else {
			upAge = time.Hour
		}

		if len(ifc.Peers) == 0 {
			h.State = "unhealthy"
			h.Reason = "нет peer в конфиге"
		} else {
			method := normalizeProbeMethod(st.FailoverProbeMethod, st.FailoverProbeTarget)
			h.ProbeMethod = method
			var probeOK *bool
			var probeErr error
			if allowProbe && (f.probeFn != nil || f.pingFn != nil) {
				mark := 0
				if f.markFn != nil {
					mark = f.markFn(c.Interface)
				}
				pctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
				ok, rtt, pOK, pRTT, tOK, tRTT, err := f.runHealthProbe(pctx, c.Interface, mark, method, st.FailoverProbeTarget)
				cancel()
				probeOK = &ok
				probeErr = err
				h.PingOK = pOK
				h.PingRTTMs = pRTT
				h.TCPOK = tOK
				h.TCPRTTMs = tRTT
				if ok {
					h.ProbeRTTMs = rtt
				}
			}
			h.ProbeOK = probeOK

			hsGrace := time.Duration(st.FailoverHandshakeSec) * time.Second
			hsMaxAge := int64(st.FailoverHandshakeMaxAge)

			switch st.FailoverTrigger {
			case "handshake":
				if bestHS < 0 {
					if upAge < hsGrace {
						h.State = "degraded"
						h.Reason = fmt.Sprintf("ожидание handshake (%ds/%ds)", int(upAge.Seconds()), st.FailoverHandshakeSec)
					} else {
						h.State = "unhealthy"
						h.Reason = fmt.Sprintf("нет handshake (>%ds)", st.FailoverHandshakeSec)
					}
				} else if bestHS > hsMaxAge {
					h.State = "unhealthy"
					h.Reason = fmt.Sprintf("handshake устарел (%ds > %ds)", bestHS, hsMaxAge)
				} else if txDelta > 4096 && rxDelta == 0 && bestHS > 25 {
					h.State = "unhealthy"
					h.Reason = "TX растёт, RX=0 (похоже на блокировку)"
				} else {
					h.State = "healthy"
				}
			case "probe":
				if probeOK != nil && !*probeOK {
					h.State = "unhealthy"
					h.Reason = fmt.Sprintf("probe fail (%v)", probeErr)
				} else {
					h.State = "healthy"
				}
			default: // "hybrid"
				if probeOK != nil && *probeOK {
					h.State = "healthy"
				} else if probeOK != nil && !*probeOK {
					if bestHS < 0 && upAge < hsGrace {
						h.State = "degraded"
						h.Reason = fmt.Sprintf("ожидание первого handshake (%ds/%ds)", int(upAge.Seconds()), st.FailoverHandshakeSec)
					} else if bestHS < 0 {
						h.State = "unhealthy"
						h.Reason = "нет handshake и probe не прошёл"
					} else if bestHS > hsMaxAge {
						h.State = "unhealthy"
						h.Reason = fmt.Sprintf("handshake устарел (%ds) и probe fail", bestHS)
					} else {
						h.State = "unhealthy"
						h.Reason = fmt.Sprintf("нет сети через туннель (%v)", probeErr)
					}
				} else {
					// Failover off & !forceProbe: passive status only
					if bestHS < 0 && upAge < hsGrace {
						h.State = "degraded"
						h.Reason = "ожидание handshake"
					} else if bestHS < 0 || bestHS > hsMaxAge {
						h.State = "degraded"
						h.Reason = "нет свежего handshake"
					} else {
						h.State = "healthy"
					}
				}
			}
		}

		var resolvedHealthy bool
		f.mu.Lock()
		if h.State == "unhealthy" {
			f.failStreak[c.Name] = prevStreak + 1
			f.healthyStreak[c.Name] = 0
			h.FailStreak = f.failStreak[c.Name]
			if f.subMgr != nil {
				f.subMgr.OnTunnelFailure(c.Name)
			}
			if st.FailoverMode != "off" && h.FailStreak < st.FailoverThreshold {
				h.State = "degraded"
			}
		} else {
			if h.State == "healthy" {
				f.failStreak[c.Name] = 0
				f.healthyStreak[c.Name]++
				if f.healthyStreak[c.Name] >= 2 {
					resolvedHealthy = true
				}
				if inCD {
					// Keep cooldown active so flaky tunnels don't flap before cooldown expires
					h.State = "cooldown"
					h.Reason = fmt.Sprintf("восстановлен, пауза (%ds)", h.CooldownLeftSec)
				} else {
					delete(f.cooldownUntil, c.Name)
					h.CooldownLeftSec = 0
				}
			} else {
				f.healthyStreak[c.Name] = 0
			}
			h.FailStreak = f.failStreak[c.Name]
		}
		f.mu.Unlock()

		if f.tg != nil && st.FailoverMode != "off" {
			if resolvedHealthy {
				f.tg.ResolveIncident("down:"+c.Name, "Туннель восстановлен", "Профиль: <b>"+html.EscapeString(c.Name)+"</b>")
				f.tg.ResolveIncident("reserve:"+c.Name, "Резервный туннель восстановлен", "Профиль: <b>"+html.EscapeString(c.Name)+"</b>")
				if h.Primary {
					f.tg.ResolveIncident("blackout", "VPN-связь восстановлена", "Основной профиль: <b>"+html.EscapeString(c.Name)+"</b>")
				}
			} else if !h.Primary && len(enabled) >= 2 && h.FailStreak >= st.FailoverThreshold && h.State == "unhealthy" && !inCD {
				f.tg.OpenIncident("reserve:"+c.Name, TGKindWarn, "Резервный туннель не отвечает",
					fmt.Sprintf("Профиль: <b>%s</b>\nПричина: %s", html.EscapeString(c.Name), html.EscapeString(h.Reason)))
			}
		}

		if h.Primary && h.FailStreak >= st.FailoverThreshold && h.State == "unhealthy" {
			unhealthyPrimary = true
			failedPrimaryReason = h.Reason
		}
		newHealth[c.Name] = h
	}

	f.mu.Lock()
	f.health = newHealth
	f.lastOrder = order
	f.mu.Unlock()

	if st.FailoverMode == "off" || f.switchFn == nil {
		return f.Status()
	}

	// Execute switch / alert if active primary failed >= Threshold checks
	if unhealthyPrimary && primaryCfg != nil {
		if len(enabled) < 2 {
			if f.tg != nil {
				f.tg.OpenIncident(
					"down:"+primaryCfg.Name,
					TGKindDown,
					"Туннель не отвечает",
					fmt.Sprintf("Профиль: <b>%s</b>\nПричина: %s\nРезервных конфигов нет.",
						html.EscapeString(primaryCfg.Name), html.EscapeString(failedPrimaryReason)),
				)
			}
			return f.Status()
		}

		f.mu.Lock()
		f.cooldownUntil[primaryCfg.Name] = now.Add(time.Duration(st.FailoverCooldownSec) * time.Second)
		candidate := f.pickCandidateLocked(enabled, upMap, primaryCfg.Name, now)
		f.mu.Unlock()

		if candidate != "" && candidate != primaryCfg.Name {
			_ = f.SwitchTo(candidate, failedPrimaryReason)
		} else if f.tg != nil {
			f.tg.OpenIncident(
				"blackout",
				TGKindDown,
				"Все VPN-туннели недоступны",
				fmt.Sprintf("Основной: <b>%s</b>\nПричина: %s\nНет доступных резервных профилей.",
					html.EscapeString(primaryCfg.Name), html.EscapeString(failedPrimaryReason)),
			)
		}
		return f.Status()
	}

	// Optional failback to Priority #1 when recovered
	if st.FailoverFailback && topEnabledCfg != nil && primaryCfg != nil && topEnabledCfg.Name != primaryCfg.Name {
		topH, hasTop := newHealth[topEnabledCfg.Name]
		f.mu.Lock()
		cdUntil := f.cooldownUntil[topEnabledCfg.Name]
		cdExpired := !cdUntil.After(now)
		var doFailback bool
		if cdExpired {
			if st.FailoverMode == "standby" {
				if hasTop && topH.State == "healthy" {
					f.failbackStreak[topEnabledCfg.Name]++
					doFailback = f.failbackStreak[topEnabledCfg.Name] >= 2
				} else {
					f.failbackStreak[topEnabledCfg.Name] = 0
				}
			} else {
				// Cold switch mode: wait 2 cycles after cooldown expiry before failback
				f.failbackStreak[topEnabledCfg.Name]++
				doFailback = f.failbackStreak[topEnabledCfg.Name] >= 2
			}
		}
		if doFailback {
			f.failbackStreak[topEnabledCfg.Name] = 0
		}
		f.mu.Unlock()
		if doFailback {
			_ = f.SwitchTo(topEnabledCfg.Name, "авто-возврат на приоритет #1 (failback)")
		}
	}

	return f.Status()
}

func (f *FailoverMonitor) pickCandidateLocked(enabled []ConfigMeta, upMap map[string]bool, exclude string, now time.Time) string {
	// Pass 1: healthy running tunnel not in cooldown
	for _, c := range enabled {
		if c.Name == exclude {
			continue
		}
		if cd, ok := f.cooldownUntil[c.Name]; ok && cd.After(now) {
			continue
		}
		if h, ok := f.health[c.Name]; ok && h.State == "healthy" {
			return c.Name
		}
	}
	// Pass 2: any enabled not in cooldown (cold standby or untested)
	for _, c := range enabled {
		if c.Name == exclude {
			continue
		}
		if cd, ok := f.cooldownUntil[c.Name]; ok && cd.After(now) {
			continue
		}
		if h, ok := f.health[c.Name]; ok && h.State == "unhealthy" && upMap[c.Interface] {
			continue
		}
		return c.Name
	}
	// Pass 3: everyone is in cooldown -> pick earliest expiring cooldown
	var best string
	var earliest time.Time
	for _, c := range enabled {
		if c.Name == exclude {
			continue
		}
		cd := f.cooldownUntil[c.Name]
		if best == "" || cd.Before(earliest) {
			best = c.Name
			earliest = cd
		}
	}
	if best == "" {
		// Sort deterministically fallback
		names := make([]string, 0, len(enabled))
		for _, c := range enabled {
			if c.Name != exclude {
				names = append(names, c.Name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			return names[0]
		}
	}
	return best
}

type FailoverPingTargetResult struct {
	Name      string `json:"name"`
	Config    string `json:"config,omitempty"`
	Interface string `json:"interface"`
	Primary   bool   `json:"primary,omitempty"`
	Direct    bool   `json:"direct,omitempty"`
	Method    string `json:"method"`
	Target    string `json:"target"`
	OK        bool   `json:"ok"`
	RTTMs     int64  `json:"rtt_ms,omitempty"`
	PingOK    *bool  `json:"ping_ok,omitempty"`
	PingRTTMs int64  `json:"ping_rtt_ms,omitempty"`
	TCPOK     *bool  `json:"tcp_ok,omitempty"`
	TCPRTTMs  int64  `json:"tcp_rtt_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type FailoverPingReport struct {
	Host    string                     `json:"host"`
	Method  string                     `json:"method"`
	Results []FailoverPingTargetResult `json:"results"`
}

func (f *FailoverMonitor) runHealthProbe(ctx context.Context, iface string, mark int, method, target string) (ok bool, rttMs int64, pingOK *bool, pingRTT int64, tcpOK *bool, tcpRTT int64, err error) {
	m := normalizeProbeMethod(method, target)
	tcpFn := f.probeFn
	if tcpFn == nil {
		tcpFn = defaultTunnelProbe
	}
	pingFn := f.pingFn
	if pingFn == nil {
		pingFn = defaultICMPPingProbe
	}
	tcpTarget := normalizeTCPProbeTarget(target)
	pingTarget := extractProbeHost(target)
	if pingTarget == "" {
		pingTarget = "1.1.1.1"
	}

	switch m {
	case ProbeMethodPing:
		rtt, pErr := pingFn(ctx, iface, mark, pingTarget)
		b := (pErr == nil)
		pingOK = &b
		if b {
			pingRTT = rtt
			return true, rtt, pingOK, pingRTT, nil, 0, nil
		}
		return false, 0, pingOK, 0, nil, 0, pErr

	case ProbeMethodAny, ProbeMethodBoth:
		var wg sync.WaitGroup
		var tErr, pErr error
		var tR, pR int64
		wg.Add(2)
		go func() {
			defer wg.Done()
			tR, tErr = tcpFn(ctx, iface, mark, tcpTarget)
		}()
		go func() {
			defer wg.Done()
			pR, pErr = pingFn(ctx, iface, mark, pingTarget)
		}()
		wg.Wait()

		tb := (tErr == nil)
		pb := (pErr == nil)
		tcpOK = &tb
		pingOK = &pb
		if tb {
			tcpRTT = tR
		}
		if pb {
			pingRTT = pR
		}

		if m == ProbeMethodAny {
			if pb && tb {
				best := pingRTT
				if tcpRTT >= 0 && (best <= 0 || tcpRTT < best) {
					best = tcpRTT
				}
				return true, best, pingOK, pingRTT, tcpOK, tcpRTT, nil
			}
			if pb {
				return true, pingRTT, pingOK, pingRTT, tcpOK, tcpRTT, nil
			}
			if tb {
				return true, tcpRTT, pingOK, pingRTT, tcpOK, tcpRTT, nil
			}
			return false, 0, pingOK, 0, tcpOK, 0, fmt.Errorf("ICMP: %v; TCP: %v", pErr, tErr)
		}

		// ProbeMethodBoth requires both ICMP and TCP probes to succeed.
		if pb && tb {
			best := pingRTT
			if best <= 0 {
				best = tcpRTT
			}
			return true, best, pingOK, pingRTT, tcpOK, tcpRTT, nil
		}
		switch {
		case !pb && !tb:
			return false, 0, pingOK, pingRTT, tcpOK, tcpRTT, fmt.Errorf("ICMP: %v; TCP: %v", pErr, tErr)
		case !pb:
			return false, 0, pingOK, pingRTT, tcpOK, tcpRTT, fmt.Errorf("ICMP fail: %v", pErr)
		default:
			return false, 0, pingOK, pingRTT, tcpOK, tcpRTT, fmt.Errorf("TCP fail: %v", tErr)
		}

	default: // ProbeMethodTCP
		rtt, tErr := tcpFn(ctx, iface, mark, tcpTarget)
		b := (tErr == nil)
		tcpOK = &b
		if b {
			tcpRTT = rtt
			return true, rtt, nil, 0, tcpOK, tcpRTT, nil
		}
		return false, 0, nil, 0, tcpOK, 0, tErr
	}
}

// PingHostAcrossTunnels probes target host/IP concurrently across all configured active tunnels and Direct LAN.
func (f *FailoverMonitor) PingHostAcrossTunnels(host, method string) FailoverPingReport {
	var st AppSettings
	if f.settings != nil {
		st = f.settings.Get()
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = strings.TrimSpace(st.FailoverProbeTarget)
	}
	if host == "" {
		host = "1.1.1.1"
	}
	if strings.TrimSpace(method) == "" && !strings.HasPrefix(strings.ToLower(host), "tcp://") {
		method = ProbeMethodPing
	}
	normMethod := normalizeProbeMethod(method, host)

	type probeSpec struct {
		name      string
		config    string
		iface     string
		mark      int
		primary   bool
		direct    bool
		canProbe  bool
		downError string
	}

	var cfgs []ConfigMeta
	if f.configsFn != nil {
		cfgs, _ = f.configsFn()
	}
	upMap := map[string]bool{}
	if f.ifacesFn != nil {
		if ifaces, err := f.ifacesFn(); err == nil {
			for _, i := range ifaces {
				upMap[i.Name] = true
			}
		}
	}
	primaryName := ""
	f.mu.Lock()
	for name, h := range f.health {
		if h.Primary {
			primaryName = name
			break
		}
	}
	f.mu.Unlock()

	var specs []probeSpec
	for _, c := range cfgs {
		if c.Disabled {
			continue
		}
		mark := 0
		if f.markFn != nil {
			mark = f.markFn(c.Interface)
		}
		name := strings.TrimSuffix(c.Name, ".conf")
		if name == "" {
			name = c.Interface
		}
		specs = append(specs, probeSpec{
			name:      name,
			config:    c.Name,
			iface:     c.Interface,
			mark:      mark,
			primary:   c.Primary || c.Name == primaryName,
			canProbe:  upMap[c.Interface],
			downError: "туннель не поднят",
		})
	}
	if f.directIface != "" {
		specs = append(specs, probeSpec{
			name:     "Direct (" + f.directIface + ")",
			iface:    f.directIface,
			direct:   true,
			canProbe: true,
		})
	}

	results := make([]FailoverPingTargetResult, len(specs))
	var wg sync.WaitGroup
	for idx, sp := range specs {
		results[idx] = FailoverPingTargetResult{
			Name:      sp.name,
			Config:    sp.config,
			Interface: sp.iface,
			Primary:   sp.primary,
			Direct:    sp.direct,
			Method:    normMethod,
			Target:    host,
		}
		if !sp.canProbe {
			results[idx].Error = sp.downError
			continue
		}
		wg.Add(1)
		go func(i int, s probeSpec) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
			defer cancel()
			ok, rtt, pOK, pRTT, tOK, tRTT, err := f.runHealthProbe(pctx, s.iface, s.mark, normMethod, host)
			results[i].OK = ok
			results[i].RTTMs = rtt
			results[i].PingOK = pOK
			results[i].PingRTTMs = pRTT
			results[i].TCPOK = tOK
			results[i].TCPRTTMs = tRTT
			if err != nil {
				results[i].Error = err.Error()
			}
		}(idx, sp)
	}
	wg.Wait()

	return FailoverPingReport{
		Host:    host,
		Method:  normMethod,
		Results: results,
	}
}
