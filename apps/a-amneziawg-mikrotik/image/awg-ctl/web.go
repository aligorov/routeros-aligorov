package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed ui.html
var uiHTML []byte

type WebServer struct {
	listenAddr   string
	healthAddr   string
	uiUser       string
	uiPass       string
	maxHSAge     int64
	mgr          *TunnelManager
	dns          *DNSForwarder
	ros          *ROSClient
	logger       *RingLogger
}

func NewWebServer(listenAddr string, mgr *TunnelManager, dns *DNSForwarder, ros *ROSClient, logger *RingLogger) *WebServer {
	maxHS, _ := strconv.ParseInt(envOr("AWG_HEALTH_MAX_HANDSHAKE_SEC", "0"), 10, 64)
	return &WebServer{
		listenAddr: listenAddr,
		healthAddr: strings.TrimSpace(os.Getenv("HEALTH_LISTEN")),
		uiUser:     envOr("UI_USER", "admin"),
		uiPass:     strings.TrimSpace(os.Getenv("UI_PASSWORD")),
		maxHSAge:   maxHS,
		mgr:        mgr,
		dns:        dns,
		ros:        ros,
		logger:     logger,
	}
}

func (w *WebServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", w.handleHealth)
	mux.HandleFunc("GET /", w.withAuth(w.handleIndex))
	mux.HandleFunc("GET /api/status", w.withAuth(w.handleStatus))
	mux.HandleFunc("GET /api/configs/{name}", w.withAuth(w.handleGetConfig))
	mux.HandleFunc("POST /api/configs/{name}", w.withAuth(w.handleSaveConfig))
	mux.HandleFunc("DELETE /api/configs/{name}", w.withAuth(w.handleDeleteConfig))
	mux.HandleFunc("POST /api/tunnel/up", w.withAuth(w.handleTunnelUp))
	mux.HandleFunc("POST /api/tunnel/down", w.withAuth(w.handleTunnelDown))
	mux.HandleFunc("POST /api/tunnel/restart", w.withAuth(w.handleTunnelRestart))
	mux.HandleFunc("POST /api/keygen", w.withAuth(w.handleKeygen))
	mux.HandleFunc("POST /api/qr", w.withAuth(w.handleQR))
	mux.HandleFunc("GET /api/domains", w.withAuth(w.handleGetDomains))
	mux.HandleFunc("POST /api/domains", w.withAuth(w.handleSaveDomains))
	mux.HandleFunc("POST /api/ros/sync", w.withAuth(w.handleROSSync))

	if w.healthAddr != "" {
		hmux := http.NewServeMux()
		hmux.HandleFunc("GET /", w.handleHealth)
		hmux.HandleFunc("GET /health", w.handleHealth)
		hsrv := &http.Server{Addr: w.healthAddr, Handler: hmux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			w.logger.Logf("Health probe listening on %s (for RouterOS netwatch)", w.healthAddr)
			if err := hsrv.ListenAndServe(); err != nil {
				w.logger.Logf("WARN: health probe stopped: %v", err)
			}
		}()
	}

	w.logger.Logf("WebUI listening on %s (auth=%v)", w.listenAddr, w.uiPass != "")
	srv := &http.Server{
		Addr:              w.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (w *WebServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if w.uiPass != "" {
			u, p, ok := r.BasicAuth()
			uMatch := subtle.ConstantTimeCompare([]byte(u), []byte(w.uiUser)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(p), []byte(w.uiPass)) == 1
			if !ok || !uMatch || !pMatch {
				rw.Header().Set("WWW-Authenticate", `Basic realm="AmneziaWG"`)
				http.Error(rw, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(rw, r)
	}
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}

func (w *WebServer) handleIndex(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(uiHTML)
}

func (w *WebServer) handleHealth(rw http.ResponseWriter, _ *http.Request) {
	ifaces, err := w.mgr.ShowInterfaces()
	if err != nil || len(ifaces) == 0 {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]any{
			"ok":     false,
			"reason": "no active awg interfaces",
		})
		return
	}
	if w.maxHSAge > 0 {
		for _, iface := range ifaces {
			for _, p := range iface.Peers {
				if p.Endpoint == "" || p.Endpoint == "(none)" {
					continue
				}
				if p.HandshakeAgeSec < 0 || p.HandshakeAgeSec > w.maxHSAge {
					writeJSON(rw, http.StatusServiceUnavailable, map[string]any{
						"ok":        false,
						"interface": iface.Name,
						"reason":    "handshake stale or missing",
						"age_sec":   p.HandshakeAgeSec,
					})
					return
				}
			}
		}
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":         true,
		"interfaces": names,
	})
}

func (w *WebServer) handleStatus(rw http.ResponseWriter, _ *http.Request) {
	ifaces, _ := w.mgr.ShowInterfaces()
	cfgs, _ := w.mgr.ListConfigs()
	var upstreams []string
	if w.dns != nil {
		upstreams = w.dns.Upstreams()
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"interfaces":    ifaces,
		"configs":       cfgs,
		"lan_iface":     w.mgr.lanIface,
		"auto_route":    w.mgr.autoRoute,
		"kill_switch":   w.mgr.killSwitch,
		"dns_upstreams": upstreams,
		"ros":           w.ros.Status(),
		"logs":          w.logger.Lines(),
	})
}

func (w *WebServer) handleGetConfig(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	text, err := w.mgr.ReadConfig(name)
	if err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]string{"name": name, "content": text})
}

func (w *WebServer) handleSaveConfig(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Content string `json:"content"`
		Apply   bool   `json:"apply"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := w.mgr.SaveConfig(name, body.Content); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Apply {
		if err := w.mgr.RestartAll(); err != nil {
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleDeleteConfig(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := w.mgr.DeleteConfig(name); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelUp(rw http.ResponseWriter, _ *http.Request) {
	if err := w.mgr.StartAll(); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelDown(rw http.ResponseWriter, _ *http.Request) {
	w.mgr.StopAll()
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelRestart(rw http.ResponseWriter, _ *http.Request) {
	if err := w.mgr.RestartAll(); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleKeygen(rw http.ResponseWriter, _ *http.Request) {
	cPriv, cPub, psk, err := GenerateKeypair()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sPriv, sPub, _, err := GenerateKeypair()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"client_private": cPriv,
		"client_public":  cPub,
		"server_private": sPriv,
		"server_public":  sPub,
		"preshared_key":  psk,
		"awg":            RandomAwgParams(),
	})
}

func (w *WebServer) handleQR(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(body.Text, qrcode.Medium, 256)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	rw.Header().Set("Content-Type", "image/png")
	_, _ = rw.Write(png)
}

func (w *WebServer) handleGetDomains(rw http.ResponseWriter, _ *http.Request) {
	domains, err := w.ros.ReadDomains()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"domains": domains})
}

func (w *WebServer) handleSaveDomains(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Domains string `json:"domains"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := w.ros.SaveDomains(body.Domains); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var syncErr string
	if w.ros.Status().Enabled {
		if err := w.ros.SyncAll(w.mgr); err != nil {
			syncErr = err.Error()
		}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": syncErr == "", "sync_error": syncErr})
}

func (w *WebServer) handleROSSync(rw http.ResponseWriter, _ *http.Request) {
	if !w.ros.Status().Enabled {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "ROS_URL and ROS_USER are not configured"})
		return
	}
	if err := w.ros.SyncAll(w.mgr); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "ros": w.ros.Status()})
}
