package main

import (
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
	autoRoute := envOr("AWG_AUTO_ROUTE", "on") == "on"
	killSwitch := envOr("AWG_KILLSWITCH", "on") == "on"

	mgr := NewTunnelManager(srcDir, runDir, lanIface, autoRoute, killSwitch, logger)
	if err := mgr.SeedFromEnv(); err != nil {
		logger.Logf("ERROR seeding env config: %v", err)
		os.Exit(1)
	}

	var dnsFwd *DNSForwarder
	if envOr("DNS_ENABLE", "on") == "on" {
		dnsFwd = NewDNSForwarder(envOr("DNS_LISTEN", ":53"), envOr("DNS_UPSTREAM", "1.1.1.1:53,8.8.8.8:53"), logger)
		if err := dnsFwd.Start(); err != nil {
			logger.Logf("WARN: DNS forwarder failed to start: %v", err)
			dnsFwd = nil
		}
	}

	rosClient := NewROSClient(srcDir, logger)

	mgr.onChange = func() {
		if dnsFwd != nil {
			dnsFwd.SetUpstreams(mgr.ActiveDNSServers())
		}
		if rosClient.Status().Enabled {
			_ = rosClient.SyncAll(mgr)
		}
	}

	web := NewWebServer(envOr("UI_LISTEN", ":8080"), mgr, dnsFwd, rosClient, logger)
	go func() {
		if err := web.Start(); err != nil {
			logger.Logf("ERROR WebUI server: %v", err)
			os.Exit(1)
		}
	}()

	if err := mgr.StartAll(); err != nil {
		logger.Logf("ERROR starting tunnels: %v", err)
		if envOr("AWG_EXIT_ON_ERROR", "off") == "on" {
			os.Exit(1)
		}
	} else if dnsFwd != nil {
		dnsFwd.SetUpstreams(mgr.ActiveDNSServers())
	}

	if rosClient.Status().Enabled {
		go func() {
			_ = rosClient.SyncAll(mgr)
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				_ = rosClient.SyncAll(mgr)
			}
		}()
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	sig := <-sigCh
	logger.Logf("Received signal %s, shutting down...", sig)
	mgr.StopAll()
}
