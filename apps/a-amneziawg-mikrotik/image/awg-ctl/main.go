package main

import (
	"fmt"
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
	rosClient.Configure(st)

	tg := NewTGNotifier(settingsStore, mgr, logger)
	failover := NewFailoverMonitor(mgr, settingsStore, tg, logger)

	mgr.onChange = func() {
		if dnsFwd != nil {
			dnsFwd.SetUpstreams(mgr.ActiveDNSServers())
		}
		_ = policy.ApplyRouting()
		if rosClient.Status().Enabled {
			_ = rosClient.SyncAll(mgr)
		}
	}

	web := NewWebServer(envOr("UI_LISTEN", ":8080"), mgr, dnsFwd, rosClient, settingsStore, geoStore, policy, logger)
	web.SetIntegrations(failover, tg)
	go func() {
		if err := web.Start(); err != nil {
			logger.Logf("ERROR WebUI server: %v", err)
			os.Exit(1)
		}
	}()

	if err := mgr.StartAll(); err != nil {
		logger.Logf("ERROR starting tunnels: %v", err)
		_ = policy.ApplyRouting()
		tg.Notify(TGKindDown, "boot:err", "Ошибка запуска туннеля", err.Error())
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
				primary, cur.MultiTunnel, cur.FailoverMode))
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
				_ = rosClient.SyncAll(mgr)
			}
			tg.MaybeSendDigest(now)
			cur := settingsStore.Get()
			if cur.GeoAutoUpdateHours > 0 && now.Sub(lastGeoCheck) >= time.Duration(cur.GeoAutoUpdateHours)*time.Hour {
				lastGeoCheck = now
				sites, ips := policy.NeededGeoCategories()
				if err := geoStore.DownloadAndReload(cur.GeoSiteURL, cur.GeoIPURL, sites, ips); err == nil {
					_ = policy.ApplyRouting()
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	sig := <-sigCh
	logger.Logf("Received signal %s, shutting down...", sig)
	failover.Stop()
	tg.Stop()
	mgr.StopAll()
}
