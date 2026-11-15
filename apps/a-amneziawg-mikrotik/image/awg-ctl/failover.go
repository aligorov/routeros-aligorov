package main

import (
	"context"
	"fmt"
	"html"
	"sort"
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

	mu               sync.Mutex
	failStreak       map[string]int
	failbackStreak   map[string]int
	cooldownUntil    map[string]time.Time
	lastTX           map[string]uint64
	lastRX           map[string]uint64
	health           map[string]TunnelHealth
	lastOrder        []string
	lastSwitchAt     int64
	lastSwitchReason string
	switchesTotal    int

	// Injectable hooks for deterministic unit tests
	nowFn       func() time.Time
	probeFn     func(ctx context.Context, iface string, mark int, target string) (int64, error)
	ifacesFn    func() ([]InterfaceStatus, error)
	configsFn   func() ([]ConfigMeta, error)
	startedAtFn func(iface string) time.Time
	markFn      func(iface string) int
	switchFn    func(target string, standbyFast bool) error
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
		failbackStreak: map[string]int{},
		cooldownUntil:  map[string]time.Time{},
		lastTX:         map[string]uint64{},
		lastRX:         map[string]uint64{},
		health:         map[string]TunnelHealth{},
		nowFn:          time.Now,
	}
	f.probeFn = defaultTunnelProbe
	if mgr != nil {
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

func defaultTunnelProbe(ctx context.Context, iface string, mark int, target string) (int64, error) {
	dialer := sockBindDialer(iface, mark, 3*time.Second)
	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
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
	nowUnix := f.nowFn().Unix()
	f.mu.Lock()
	f.failStreak[target] = 0
	f.lastSwitchAt = nowUnix
	f.lastSwitchReason = fmt.Sprintf("%s → %s (%s)", currentPrimary, target, reason)
	f.switchesTotal++
	f.mu.Unlock()

	if f.logger != nil {
		f.logger.Logf("Failover: switched %s -> %s (%s)", currentPrimary, target, reason)
	}
	if f.tg != nil {
		f.tg.Notify(
			TGKindFailover,
			"switch:"+currentPrimary+"->"+target,
			"Переключение туннеля",
			fmt.Sprintf("<b>%s</b> → <b>%s</b>\nПричина: %s",
				html.EscapeString(currentPrimary), html.EscapeString(target), html.EscapeString(reason)),
		)
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
			var probeOK *bool
			var probeErr error
			if allowProbe && f.probeFn != nil {
				mark := 0
				if f.markFn != nil {
					mark = f.markFn(c.Interface)
				}
				pctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
				rtt, err := f.probeFn(pctx, c.Interface, mark, st.FailoverProbeTarget)
				cancel()
				ok := (err == nil)
				probeOK = &ok
				probeErr = err
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

		f.mu.Lock()
		if h.State == "unhealthy" {
			f.failStreak[c.Name] = prevStreak + 1
			h.FailStreak = f.failStreak[c.Name]
			if st.FailoverMode != "off" && h.FailStreak < st.FailoverThreshold {
				h.State = "degraded"
			}
		} else {
			if h.State == "healthy" {
				f.failStreak[c.Name] = 0
				if inCD {
					// Keep cooldown active so flaky tunnels don't flap before cooldown expires
					h.State = "cooldown"
					h.Reason = fmt.Sprintf("восстановлен, пауза (%ds)", h.CooldownLeftSec)
				} else {
					delete(f.cooldownUntil, c.Name)
					h.CooldownLeftSec = 0
				}
			}
			h.FailStreak = f.failStreak[c.Name]
		}
		f.mu.Unlock()

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
				f.tg.Notify(
					TGKindDown,
					"down:"+primaryCfg.Name,
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
