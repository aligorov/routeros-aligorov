package main

import (
	"fmt"
	"html"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func main() {
	logger := NewRingLogger(300)
	srcDir := envOr("AWG_CONF_DIR", "/etc/amnezia/amneziawg")
	runDir := envOr("AWG_RUN_DIR", "/run/awg")
	lanIface := strings.TrimSpace(os.Getenv("AWG_LAN_IFACE"))

	settingsStore, err := NewSettingsStore(srcDir)
	if err != nil {
		logger.Logf("WARN loading settings.json: %v", err)
	}
	st := settingsStore.Get()

	mgr := NewTunnelManager(srcDir, runDir, lanIface, st.AutoRoute, st.KillSwitch, logger)
	mgr.SetRuntimeOptions(st.AutoRoute, st.KillSwitch, st.MultiTunnel)
	mgr.SetAllowHooks(st.AllowConfigHooks)
	mgr.SetTunnelPlan(st.TunnelOrder, st.DisabledConfigs)
	if err := mgr.SeedFromEnv(); err != nil {
		logger.Logf("ERROR seeding env config: %v", err)
		os.Exit(1)
	}

	geoStore := NewGeoStore(srcDir, logger)
	policy := NewPolicyEngine(srcDir, settingsStore, geoStore, mgr, logger)
	if err := policy.LoadAndInit(); err != nil {
		logger.Logf("WARN loading rules: %v", err)
	}

	var dnsFwd *DNSForwarder
	if envOr("DNS_ENABLE", "on") == "on" {
		dnsFwd = NewDNSForwarder(envOr("DNS_LISTEN", ":53"), st.ProxyDNS, logger)
		dnsFwd.SetPolicy(policy, settingsStore)
		dnsFwd.ConfigureFromSettings(st)
		if err := dnsFwd.Start(); err != nil {
			logger.Logf("WARN: DNS forwarder failed to start: %v", err)
			dnsFwd = nil
		}
	}

	rosClient := NewROSClient(srcDir, logger)
	rosClient.SetManager(mgr)
	rosClient.SetPolicy(policy)
	rosClient.SetAutoGatewayFn(func() string { return detectInterfaceIPv4(mgr.LanIface()) })
	rosClient.Configure(st)
	if dnsFwd != nil {
		dnsFwd.SetROS(rosClient)
		rosClient.SetDNS(dnsFwd)
	}

	tg := NewTGNotifier(settingsStore, mgr, logger)
	rosClient.SetTGNotifier(tg)
	failover := NewFailoverMonitor(mgr, settingsStore, tg, logger)
	subMgr := NewSubscriptionManager(settingsStore, mgr, tg, logger)
	failover.SetSubscriptionManager(subMgr)
	vpsFleet := NewVPSFleetManager(srcDir, settingsStore, mgr, subMgr, tg, logger)
	subMgr.SetOnUpdated(vpsFleet.OnLocalSubscriptionUpdated)
	tg.SetDigestExtrasProvider(func() []string {
		var out []string
		foSt := failover.Status()
		if foSt.Mode != "off" {
			out = append(out, fmt.Sprintf("🔁 Failover (%s): переключений %d", html.EscapeString(foSt.Mode), foSt.SwitchesTotal))
		}
		rosSt := rosClient.Status()
		if rosSt.Mode != ROSModeGateway && rosSt.Enabled {
			if rosSt.Mode == ROSModeBGP {
				out = append(out, fmt.Sprintf("🌐 RouterOS BGP: %s (%d маршрутов)", html.EscapeString(rosSt.BGPState), rosSt.BGPRoutes))
			} else if rosSt.LastError != "" {
				out = append(out, fmt.Sprintf("🌐 RouterOS: ОШИБКА (%s)", html.EscapeString(truncateUTF8(rosSt.LastError, 90))))
			} else {
				out = append(out, fmt.Sprintf("🌐 RouterOS (%s): OK (статика %d, DNS %d)", html.EscapeString(rosSt.Mode), rosSt.StaticSynced, rosSt.DynSynced))
			}
		}
		fv := vpsFleet.View()
		if len(fv.Servers) > 0 {
			okSrv, tgErrCli := 0, 0
			for _, s := range fv.Servers {
				if s.LastError == "" {
					okSrv++
				}
			}
			for _, c := range fv.Clients {
				if c.LastSendError != "" {
					tgErrCli++
				}
			}
			line := fmt.Sprintf("📡 VPS Fleet: %d/%d онлайн · %d кл.", okSrv, len(fv.Servers), len(fv.Clients))
			if tgErrCli > 0 {
				line += fmt.Sprintf(" (ошибки ТГ: %d)", tgErrCli)
			}
			out = append(out, line)
		}
		return out
	})
	subMgr.Start()
	vpsFleet.Start()

	mgr.onChange = func() {
		if dnsFwd != nil {
			dnsFwd.SetUpstreams(mgr.ActiveDNSServers())
		}
		_ = policy.ApplyRouting()
		rosClient.configureBGPFromState()
		if rosClient.Status().Enabled {
			go func() {
				_ = rosClient.SyncAll(mgr)
			}()
		}
	}

	web := NewWebServer(envOr("UI_LISTEN", ":8080"), mgr, dnsFwd, rosClient, settingsStore, geoStore, policy, logger)
	web.SetIntegrations(failover, tg)
	web.SetSubscriptionManager(subMgr)
	web.SetVPSFleet(vpsFleet)
	go func() {
		if err := web.Start(); err != nil {
			logger.Logf("ERROR WebUI server: %v", err)
			os.Exit(1)
		}
	}()

	if err := mgr.StartAll(); err != nil {
		logger.Logf("ERROR starting tunnels: %v", err)
		_ = policy.ApplyRouting()
		tg.Notify(TGKindDown, "boot:err", "Ошибка запуска туннеля", "<code>"+html.EscapeString(truncateUTF8(err.Error(), 600))+"</code>")
		if envOr("AWG_EXIT_ON_ERROR", "off") == "on" {
			os.Exit(1)
		}
	} else {
		if dnsFwd != nil {
			dnsFwd.SetUpstreams(mgr.ActiveDNSServers())
		}
		_ = policy.ApplyRouting()
		if primary := mgr.PrimaryInterface(); primary != "" {
			cur := settingsStore.Get()
			tg.Notify(TGKindStart, "boot:ok", "Контейнер запущен", fmt.Sprintf("Основной туннель: <code>%s</code>\nMulti-Tunnel: %v · Failover: %s",
				html.EscapeString(primary), cur.MultiTunnel, html.EscapeString(cur.FailoverMode)))
		}
	}

	// Periodic RouterOS sync, Telegram digest & optional Geo auto-update
	go func() {
		if rosClient.Status().Enabled {
			_ = rosClient.SyncAll(mgr)
		}
		lastGeoCheck := time.Now()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			if rosClient.Status().Enabled {
				_ = rosClient.SyncPeriodic(mgr)
			}
			tg.MaybeSendDigest(now)
			cur := settingsStore.Get()
			if cur.GeoAutoUpdateHours > 0 && now.Sub(lastGeoCheck) >= time.Duration(cur.GeoAutoUpdateHours)*time.Hour {
				lastGeoCheck = now
				sites, ips := policy.NeededGeoCategories()
				if err := geoStore.DownloadAndReload(cur.GeoSiteURL, cur.GeoIPURL, sites, ips); err == nil {
					_ = policy.ApplyRouting()
					rosClient.OnPolicyChanged()
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	sig := <-sigCh
	logger.Logf("Received signal %s, shutting down...", sig)
	vpsFleet.Stop()
	subMgr.Stop()
	failover.Stop()
	tg.Stop()
	rosClient.Close()
	mgr.StopAll()
}
