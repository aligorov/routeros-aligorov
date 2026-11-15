package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed ui.html
var uiHTML []byte

var (
	uiETag     string
	uiHTMLGzip []byte
)

func init() {
	sum := sha256.Sum256(uiHTML)
	uiETag = `"` + hex.EncodeToString(sum[:8]) + `"`
	var buf bytes.Buffer
	if gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression); err == nil {
		_, _ = gz.Write(uiHTML)
		_ = gz.Close()
		uiHTMLGzip = buf.Bytes()
	}
}

type WebServer struct {
	listenAddr string
	healthAddr string
	uiUser     string
	uiPass     string
	maxHSAge   int64
	mgr        *TunnelManager
	dns        *DNSForwarder
	ros        *ROSClient
	settings   *SettingsStore
	geo        *GeoStore
	policy     *PolicyEngine
	term       *TermRunner
	failover   *FailoverMonitor
	tg         *TGNotifier
	logger     *RingLogger
}

func (w *WebServer) SetIntegrations(fo *FailoverMonitor, tg *TGNotifier) {
	w.failover = fo
	w.tg = tg
}

func NewWebServer(listenAddr string, mgr *TunnelManager, dns *DNSForwarder, ros *ROSClient, settings *SettingsStore, geo *GeoStore, policy *PolicyEngine, logger *RingLogger) *WebServer {
	maxHS, _ := strconv.ParseInt(envOr("AWG_HEALTH_MAX_HANDSHAKE_SEC", "0"), 10, 64)
	srcDir := ""
	if mgr != nil {
		srcDir = mgr.srcDir
	}
	return &WebServer{
		listenAddr: listenAddr,
		healthAddr: strings.TrimSpace(os.Getenv("HEALTH_LISTEN")),
		uiUser:     envOr("UI_USER", "admin"),
		uiPass:     strings.TrimSpace(os.Getenv("UI_PASSWORD")),
		maxHSAge:   maxHS,
		mgr:        mgr,
		dns:        dns,
		ros:        ros,
		settings:   settings,
		geo:        geo,
		policy:     policy,
		term:       NewTermRunner(srcDir),
		logger:     logger,
	}
}

func (w *WebServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", w.handleReady)
	mux.HandleFunc("GET /", w.withAuth(w.handleIndex))
	mux.HandleFunc("GET /api/status", w.withAuth(w.handleStatus))
	mux.HandleFunc("GET /api/configs/{name}", w.withAuth(w.handleGetConfig))
	mux.HandleFunc("POST /api/configs/plan", w.withAuth(w.handleSaveTunnelPlan))
	mux.HandleFunc("POST /api/configs/{name}", w.withAuth(w.handleSaveConfig))
	mux.HandleFunc("DELETE /api/configs/{name}", w.withAuth(w.handleDeleteConfig))
	mux.HandleFunc("POST /api/configs/{name}/activate", w.withAuth(w.handleActivateConfig))
	mux.HandleFunc("POST /api/tunnel/up", w.withAuth(w.handleTunnelUp))
	mux.HandleFunc("POST /api/tunnel/down", w.withAuth(w.handleTunnelDown))
	mux.HandleFunc("POST /api/tunnel/restart", w.withAuth(w.handleTunnelRestart))
	mux.HandleFunc("GET /api/failover", w.withAuth(w.handleFailoverStatus))
	mux.HandleFunc("POST /api/failover/check", w.withAuth(w.handleFailoverCheck))
	mux.HandleFunc("POST /api/failover/switch", w.withAuth(w.handleFailoverSwitch))
	mux.HandleFunc("POST /api/telegram/test", w.withAuth(w.handleTelegramTest))
	mux.HandleFunc("POST /api/keygen", w.withAuth(w.handleKeygen))
	mux.HandleFunc("POST /api/qr", w.withAuth(w.handleQR))
	mux.HandleFunc("GET /api/settings", w.withAuth(w.handleGetSettings))
	mux.HandleFunc("POST /api/settings", w.withAuth(w.handleSaveSettings))
	mux.HandleFunc("GET /api/rules", w.withAuth(w.handleGetRules))
	mux.HandleFunc("POST /api/rules", w.withAuth(w.handleSaveRules))
	mux.HandleFunc("GET /api/rules/test", w.withAuth(w.handleTestRule))
	mux.HandleFunc("GET /api/geo/status", w.withAuth(w.handleGeoStatus))
	mux.HandleFunc("POST /api/geo/update", w.withAuth(w.handleGeoUpdate))
	mux.HandleFunc("GET /api/domains", w.withAuth(w.handleGetDomains))
	mux.HandleFunc("POST /api/domains", w.withAuth(w.handleSaveDomains))
	mux.HandleFunc("POST /api/ros/sync", w.withAuth(w.handleROSSync))
	mux.HandleFunc("POST /api/ros/test", w.withAuth(w.handleROSTest))
	mux.HandleFunc("POST /api/ros/cleanup", w.withAuth(w.handleROSCleanup))
	mux.HandleFunc("GET /api/ros/schema", w.withAuth(w.handleROSSchema))
	mux.HandleFunc("POST /api/ros/provision", w.withAuth(w.handleROSProvision))
	mux.HandleFunc("POST /api/ros/mode", w.withAuth(w.handleROSMode))
	mux.HandleFunc("POST /api/term/exec", w.withAuth(w.handleTermExec))
	mux.HandleFunc("POST /api/term/kill", w.withAuth(w.handleTermKill))

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
		Handler:           w.gzipMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gw *gzip.Writer
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	return g.gw.Write(p)
}

func (g *gzipResponseWriter) Flush() {
	_ = g.gw.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *WebServer) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Pre-compressed uiHTML handles "/", QR PNG shouldn't be re-compressed,
		// and /api/term/exec uses chunked streaming without buffering.
		if r.URL.Path == "/" || r.URL.Path == "/api/qr" || strings.HasPrefix(r.URL.Path, "/api/term/") || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(rw, r)
			return
		}
		rw.Header().Add("Vary", "Accept-Encoding")
		rw.Header().Set("Content-Encoding", "gzip")
		rw.Header().Del("Content-Length")
		gz, err := gzip.NewWriterLevel(rw, gzip.BestSpeed)
		if err != nil {
			next.ServeHTTP(rw, r)
			return
		}
		defer gz.Close()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: rw, gw: gz}, r)
	})
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

func (w *WebServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("ETag", uiETag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, uiETag) {
		rw.WriteHeader(http.StatusNotModified)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Add("Vary", "Accept-Encoding")
	if len(uiHTMLGzip) > 0 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		rw.Header().Set("Content-Encoding", "gzip")
		_, _ = rw.Write(uiHTMLGzip)
		return
	}
	_, _ = rw.Write(uiHTML)
}

// handleReady is used by Docker/RouterOS /app HEALTHCHECK on :8080/health:
// returns 200 OK whenever WebUI is up (even before a .conf is added),
// unless ?tunnel=1 is passed. RouterOS Netwatch continues to use :8081 (handleHealth).
func (w *WebServer) handleReady(rw http.ResponseWriter, r *http.Request) {
	if r.URL != nil && r.URL.Query().Get("tunnel") == "1" {
		w.handleHealth(rw, r)
		return
	}
	ifaces, _ := w.mgr.ShowInterfaces()
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":         true,
		"version":    AppVersion,
		"tunnel_up":  len(ifaces) > 0,
		"interfaces": names,
	})
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
		"version":    AppVersion,
		"interfaces": names,
	})
}

func (w *WebServer) handleStatus(rw http.ResponseWriter, _ *http.Request) {
	ifaces, _ := w.mgr.ShowInterfaces()
	cfgs, _ := w.mgr.ListConfigs()
	var upstreams []string
	var directUpstreams []string
	if w.dns != nil {
		upstreams = w.dns.getProxyUpstreams()
		directUpstreams = w.dns.getDirectUpstreams()
	}
	var policyStats PolicyStats
	if w.policy != nil {
		policyStats = w.policy.Stats()
	}
	var defPol string
	var multiTun bool
	if w.settings != nil {
		st := w.settings.Get()
		defPol = st.DefaultPolicy
		multiTun = st.MultiTunnel
	}
	containerIP, gw := w.containerNetInfo()
	var foStatus any
	if w.failover != nil {
		foStatus = w.failover.Status()
	}
	var tgStatus any
	if w.tg != nil {
		tgStatus = w.tg.Status()
	}
	conflicts := w.mgr.DetectConflicts(cfgs)
	writeJSON(rw, http.StatusOK, map[string]any{
		"version":        AppVersion,
		"interfaces":     ifaces,
		"configs":        cfgs,
		"conflicts":      conflicts,
		"lan_iface":      w.mgr.lanIface,
		"container_ip":   containerIP,
		"gateway":        gw,
		"auto_route":     w.mgr.autoRoute,
		"kill_switch":    w.mgr.killSwitch,
		"multi_tunnel":   multiTun,
		"default_policy": defPol,
		"dns_upstreams":  upstreams,
		"direct_dns":     directUpstreams,
		"policy":         policyStats,
		"failover":       foStatus,
		"tg":             tgStatus,
		"ros":            w.ros.Status(),
		"logs":           w.logger.Lines(),
	})
}

func (w *WebServer) containerNetInfo() (containerIP, gateway string) {
	if w.mgr == nil || w.mgr.lanIface == "" {
		return "", ""
	}
	if ifc, err := net.InterfaceByName(w.mgr.lanIface); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					containerIP = ipn.String()
					break
				}
			}
		}
	}
	if w.policy != nil && w.policy.detectRouteFn != nil {
		gateway, _ = w.policy.detectRouteFn(w.mgr.lanIface)
	} else {
		gateway, _ = defaultDetectRoute(w.mgr.lanIface)
	}
	return containerIP, gateway
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
		if err := w.mgr.ActivateConfig(name); err != nil {
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if w.tg != nil {
		w.tg.Notify(TGKindConfig, "cfg:"+name, "Профиль обновлён", "Профиль: <b>"+name+"</b>")
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleActivateConfig(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := w.mgr.ActivateConfig(name); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if w.tg != nil {
		w.tg.Notify(TGKindFailover, "act:"+name, "Активный профиль изменён", "Выбран: <b>"+name+"</b>")
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleSaveTunnelPlan(rw http.ResponseWriter, r *http.Request) {
	if w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "settings store unavailable"})
		return
	}
	var body struct {
		Order    []string `json:"order"`
		Disabled []string `json:"disabled"`
		Apply    bool     `json:"apply"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	next, err := w.settings.UpdateTunnelPlan(body.Order, body.Disabled)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.mgr.SetTunnelPlan(next.TunnelOrder, next.DisabledConfigs)
	var applyErr string
	if body.Apply && next.MultiTunnel {
		if err := w.mgr.RestartAll(); err != nil {
			applyErr = err.Error()
		}
	}
	if w.failover != nil {
		w.failover.Wake()
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":          applyErr == "",
		"apply_error": applyErr,
	})
}

func (w *WebServer) handleDeleteConfig(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := w.mgr.DeleteConfig(name); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if w.tg != nil {
		w.tg.Notify(TGKindConfig, "del:"+name, "Профиль удалён", "Удалён: <b>"+name+"</b>")
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelUp(rw http.ResponseWriter, _ *http.Request) {
	if err := w.mgr.StartAll(); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if w.tg != nil {
		w.tg.Notify(TGKindStart, "up", "Туннели подняты", "Основной: <code>"+w.mgr.PrimaryInterface()+"</code>")
	}
	if w.failover != nil {
		w.failover.Wake()
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelDown(rw http.ResponseWriter, _ *http.Request) {
	w.mgr.StopAll()
	if w.tg != nil {
		w.tg.Notify(TGKindDown, "down:manual", "Туннели остановлены", "Остановлено вручную через WebUI")
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleTunnelRestart(rw http.ResponseWriter, _ *http.Request) {
	if err := w.mgr.RestartAll(); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if w.tg != nil {
		w.tg.Notify(TGKindStart, "restart", "Туннели перезапущены", "Основной: <code>"+w.mgr.PrimaryInterface()+"</code>")
	}
	if w.failover != nil {
		w.failover.Wake()
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *WebServer) handleFailoverStatus(rw http.ResponseWriter, _ *http.Request) {
	if w.failover == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "failover monitor unavailable"})
		return
	}
	writeJSON(rw, http.StatusOK, w.failover.Status())
}

func (w *WebServer) handleFailoverCheck(rw http.ResponseWriter, _ *http.Request) {
	if w.failover == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "failover monitor unavailable"})
		return
	}
	writeJSON(rw, http.StatusOK, w.failover.CheckNow(true))
}

func (w *WebServer) handleFailoverSwitch(rw http.ResponseWriter, r *http.Request) {
	if w.failover == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "failover monitor unavailable"})
		return
	}
	var body struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body)
	}
	if err := w.failover.SwitchTo(strings.TrimSpace(body.Target), strings.TrimSpace(body.Reason)); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "failover": w.failover.Status()})
}

func (w *WebServer) handleTelegramTest(rw http.ResponseWriter, r *http.Request) {
	if w.tg == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "telegram notifier unavailable"})
		return
	}
	var body struct {
		TGBotToken      string `json:"tg_bot_token"`
		TGChatID        string `json:"tg_chat_id"`
		TGThreadID      int    `json:"tg_thread_id"`
		TGAlertThreadID int    `json:"tg_alert_thread_id"`
		TGNodeName      string `json:"tg_node_name"`
		TGAPIURL        string `json:"tg_api_url"`
		TGVia           string `json:"tg_via"`
		TGSilent        bool   `json:"tg_silent"`
	}
	var override *AppSettings
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err == nil && (body.TGChatID != "" || body.TGBotToken != "") {
			cur := w.settings.Get()
			if strings.TrimSpace(body.TGBotToken) != "" {
				cur.TGBotToken = strings.TrimSpace(body.TGBotToken)
			}
			if strings.TrimSpace(body.TGChatID) != "" {
				cur.TGChatID = strings.TrimSpace(body.TGChatID)
			}
			cur.TGThreadID = body.TGThreadID
			cur.TGAlertThreadID = body.TGAlertThreadID
			if strings.TrimSpace(body.TGNodeName) != "" {
				cur.TGNodeName = strings.TrimSpace(body.TGNodeName)
			}
			if strings.TrimSpace(body.TGAPIURL) != "" {
				cur.TGAPIURL = strings.TrimRight(strings.TrimSpace(body.TGAPIURL), "/")
			}
			if strings.TrimSpace(body.TGVia) != "" {
				cur.TGVia = strings.TrimSpace(body.TGVia)
			}
			cur.TGSilent = body.TGSilent
			override = &cur
		}
	}
	msgID, err := w.tg.SendTest(override)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "tg": w.tg.Status()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "message_id": msgID, "tg": w.tg.Status()})
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

func (w *WebServer) handleROSTest(rw http.ResponseWriter, r *http.Request) {
	if w.ros == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "ros client unavailable"})
		return
	}
	var body struct {
		ROSURL           string  `json:"ros_url"`
		ROSUser          string  `json:"ros_user"`
		ROSPass          string  `json:"ros_pass"`
		ClearROSPass     bool    `json:"clear_ros_pass"`
		ROSTLSSkipVerify *bool   `json:"ros_tls_insecure"`
		ROSContainerIP   *string `json:"ros_container_ip"`
		ROSRouteTable    *string `json:"ros_route_table"`
		ROSUseBinaryAPI  *bool   `json:"ros_use_binary_api"`
		ROSAPIPort       *int    `json:"ros_api_port"`
		ROSAPITLS        *bool   `json:"ros_api_tls"`
	}
	var override *AppSettings
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err == nil && (strings.TrimSpace(body.ROSURL) != "" || strings.TrimSpace(body.ROSUser) != "") {
			cur := w.settings.Get()
			cur.ROSURL = strings.TrimSpace(body.ROSURL)
			cur.ROSUser = strings.TrimSpace(body.ROSUser)
			if body.ClearROSPass {
				cur.ROSPass = ""
			} else if body.ROSPass != "" {
				cur.ROSPass = body.ROSPass
			}
			if body.ROSTLSSkipVerify != nil {
				cur.ROSTLSSkipVerify = *body.ROSTLSSkipVerify
			}
			if body.ROSContainerIP != nil {
				cur.ROSContainerIP = *body.ROSContainerIP
			}
			if body.ROSRouteTable != nil {
				cur.ROSRouteTable = *body.ROSRouteTable
			}
			if body.ROSUseBinaryAPI != nil {
				cur.ROSUseBinaryAPI = *body.ROSUseBinaryAPI
			}
			if body.ROSAPIPort != nil {
				cur.ROSAPIPort = *body.ROSAPIPort
			}
			if body.ROSAPITLS != nil {
				cur.ROSAPITLS = *body.ROSAPITLS
			}
			override = &cur
		}
	}
	res := w.ros.TestConnection(override)
	writeJSON(rw, http.StatusOK, res)
}

func (w *WebServer) handleROSSchema(rw http.ResponseWriter, r *http.Request) {
	if w.ros == nil || w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "ros client unavailable"})
		return
	}
	s := w.settings.Get()
	if qMode := strings.TrimSpace(r.URL.Query().Get("mode")); qMode != "" {
		s.ROSMode = normalizeROSMode(qMode)
	}
	writeJSON(rw, http.StatusOK, w.ros.InspectSchema(s))
}

func (w *WebServer) handleROSProvision(rw http.ResponseWriter, r *http.Request) {
	if w.ros == nil || w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "ros client unavailable"})
		return
	}
	var opts ROSProvisionOptions
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&opts)
	}
	s := w.settings.Get()
	res := w.ros.ProvisionSchema(s, opts)
	if res.OK {
		go func() {
			_ = w.ros.SyncAll(w.mgr)
		}()
	}
	writeJSON(rw, http.StatusOK, res)
}

func (w *WebServer) handleROSMode(rw http.ResponseWriter, r *http.Request) {
	if w.ros == nil || w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "ros client unavailable"})
		return
	}
	var body struct {
		ROSMode              string  `json:"ros_mode"`
		ROSUseBinaryAPI      *bool   `json:"ros_use_binary_api,omitempty"`
		ROSDynamicTimeout    *string `json:"ros_dynamic_timeout,omitempty"`
		ROSSyncPolicyCIDRs   *bool   `json:"ros_sync_policy_cidrs,omitempty"`
		ROSStaticPrefixLimit *int    `json:"ros_static_prefix_limit,omitempty"`
		ROSBGPLocalAS        *uint32 `json:"ros_bgp_local_as,omitempty"`
		ROSBGPRemoteAS       *uint32 `json:"ros_bgp_remote_as,omitempty"`
		ROSBGPPeerIP         *string `json:"ros_bgp_peer_ip,omitempty"`
		ROSBGPRouteTable     *string `json:"ros_bgp_route_table,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cur := w.settings.Get()
	cur.ROSMode = normalizeROSMode(body.ROSMode)
	if body.ROSUseBinaryAPI != nil {
		cur.ROSUseBinaryAPI = *body.ROSUseBinaryAPI
	}
	if body.ROSDynamicTimeout != nil {
		cur.ROSDynamicTimeout = *body.ROSDynamicTimeout
	}
	if body.ROSSyncPolicyCIDRs != nil {
		cur.ROSSyncPolicyCIDRs = *body.ROSSyncPolicyCIDRs
	}
	if body.ROSStaticPrefixLimit != nil {
		cur.ROSStaticPrefixLimit = *body.ROSStaticPrefixLimit
	}
	if body.ROSBGPLocalAS != nil {
		cur.ROSBGPLocalAS = *body.ROSBGPLocalAS
	}
	if body.ROSBGPRemoteAS != nil {
		cur.ROSBGPRemoteAS = *body.ROSBGPRemoteAS
	}
	if body.ROSBGPPeerIP != nil {
		cur.ROSBGPPeerIP = *body.ROSBGPPeerIP
	}
	if body.ROSBGPRouteTable != nil {
		cur.ROSBGPRouteTable = *body.ROSBGPRouteTable
	}
	next, err := w.settings.Update(SettingsUpdate{AppSettings: cur})
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.ros.Configure(next)
	if w.ros.Status().Enabled {
		go func() {
			_ = w.ros.SyncAll(w.mgr)
		}()
	}
	st := w.ros.Status()
	w.logger.Logf("ROS mode switched -> %s", next.ROSMode)
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":         true,
		"settings":   w.settings.View(),
		"ros":        st,
		"cli_script": BuildROSSchemaCLIScript(next, st.GatewayIP, next.ROSBGPPeerIP),
	})
}

func (w *WebServer) handleROSCleanup(rw http.ResponseWriter, _ *http.Request) {
	if w.ros == nil || !w.ros.Status().Enabled {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "ROS_URL and ROS_USER are not configured"})
		return
	}
	routesDel, dnsDel, err := w.ros.CleanupManaged()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":             true,
		"routes_deleted": routesDel,
		"dns_deleted":    dnsDel,
		"ros":            w.ros.Status(),
	})
}

func (w *WebServer) handleGetSettings(rw http.ResponseWriter, _ *http.Request) {
	if w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "settings store unavailable"})
		return
	}
	writeJSON(rw, http.StatusOK, w.settings.View())
}

func (w *WebServer) handleSaveSettings(rw http.ResponseWriter, r *http.Request) {
	if w.settings == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "settings store unavailable"})
		return
	}
	var upd SettingsUpdate
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&upd); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	prev := w.settings.Get()
	next, err := w.settings.Update(upd)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.mgr.SetRuntimeOptions(next.AutoRoute, next.KillSwitch, next.MultiTunnel)
	w.mgr.SetTunnelPlan(next.TunnelOrder, next.DisabledConfigs)
	if w.dns != nil {
		w.dns.ConfigureFromSettings(next)
	}
	if w.ros != nil {
		w.ros.Configure(next)
		if w.ros.Status().Enabled {
			go func() {
				_ = w.ros.SyncAll(w.mgr)
			}()
		}
	}
	var applyErr string
	if prev.AutoRoute != next.AutoRoute || prev.MultiTunnel != next.MultiTunnel {
		if err := w.mgr.RestartAll(); err != nil {
			applyErr = err.Error()
		}
	} else if w.policy != nil {
		if err := w.policy.ApplyRouting(); err != nil {
			applyErr = err.Error()
		}
	}
	if w.failover != nil {
		w.failover.Wake()
	}
	if w.tg != nil {
		w.tg.Notify(TGKindConfig, "settings", "Настройки сохранены", "failover="+next.FailoverMode+", multi="+strconv.FormatBool(next.MultiTunnel))
	}
	w.logger.Logf("Settings updated (default_policy=%s, ros_mode=%s, auto_route=%v, kill_switch=%v, multi=%v, failover=%s/%s)",
		next.DefaultPolicy, next.ROSMode, next.AutoRoute, next.KillSwitch, next.MultiTunnel, next.FailoverMode, next.FailoverTrigger)
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":          applyErr == "",
		"apply_error": applyErr,
		"settings":    w.settings.View(),
	})
}

func (w *WebServer) handleGetRules(rw http.ResponseWriter, _ *http.Request) {
	if w.policy == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "policy engine unavailable"})
		return
	}
	raw, rules := w.policy.RawAndRules()
	writeJSON(rw, http.StatusOK, map[string]any{
		"raw":    raw,
		"rules":  rules,
		"stats":  w.policy.Stats(),
		"geo":    w.geo.Status(),
	})
}

func (w *WebServer) handleSaveRules(rw http.ResponseWriter, r *http.Request) {
	if w.policy == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "policy engine unavailable"})
		return
	}
	var body struct {
		Raw           string `json:"raw"`
		DefaultPolicy string `json:"default_policy,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.DefaultPolicy != "" && w.settings != nil {
		cur := w.settings.Get()
		cur.DefaultPolicy = body.DefaultPolicy
		_, _ = w.settings.Update(SettingsUpdate{AppSettings: cur})
	}
	rules, err := w.policy.SaveRules(body.Raw)
	if err != nil {
		writeJSON(rw, http.StatusOK, map[string]any{
			"ok":          false,
			"apply_error": err.Error(),
			"rules":       rules,
			"stats":       w.policy.Stats(),
		})
		return
	}
	if w.ros != nil {
		w.ros.OnPolicyChanged()
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":    true,
		"rules": rules,
		"stats": w.policy.Stats(),
		"geo":   w.geo.Status(),
	})
}

func (w *WebServer) handleTestRule(rw http.ResponseWriter, r *http.Request) {
	if w.policy == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "policy engine unavailable"})
		return
	}
	q := r.URL.Query().Get("q")
	writeJSON(rw, http.StatusOK, w.policy.TestQuery(q))
}

func (w *WebServer) handleGeoStatus(rw http.ResponseWriter, _ *http.Request) {
	if w.geo == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "geo store unavailable"})
		return
	}
	writeJSON(rw, http.StatusOK, w.geo.Status())
}

func (w *WebServer) handleGeoUpdate(rw http.ResponseWriter, r *http.Request) {
	if w.geo == nil || w.settings == nil || w.policy == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "geo subsystem unavailable"})
		return
	}
	var body struct {
		GeoSiteURL string `json:"geosite_url,omitempty"`
		GeoIPURL   string `json:"geoip_url,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body)
	}
	cur := w.settings.Get()
	changed := false
	if strings.TrimSpace(body.GeoSiteURL) != "" && body.GeoSiteURL != cur.GeoSiteURL {
		cur.GeoSiteURL = strings.TrimSpace(body.GeoSiteURL)
		changed = true
	}
	if strings.TrimSpace(body.GeoIPURL) != "" && body.GeoIPURL != cur.GeoIPURL {
		cur.GeoIPURL = strings.TrimSpace(body.GeoIPURL)
		changed = true
	}
	if changed {
		cur, _ = w.settings.Update(SettingsUpdate{AppSettings: cur})
	}
	sites, ips := w.policy.NeededGeoCategories()
	dlErr := w.geo.DownloadAndReload(cur.GeoSiteURL, cur.GeoIPURL, sites, ips)
	applyErr := w.policy.ApplyRouting()
	if w.ros != nil {
		w.ros.OnPolicyChanged()
	}
	var errMsg string
	if dlErr != nil {
		errMsg = dlErr.Error()
	} else if applyErr != nil {
		errMsg = applyErr.Error()
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":    errMsg == "",
		"error": errMsg,
		"geo":   w.geo.Status(),
		"stats": w.policy.Stats(),
	})
}

func (w *WebServer) handleTermExec(rw http.ResponseWriter, r *http.Request) {
	if w.term == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "terminal runner unavailable"})
		return
	}
	var body struct {
		Command string `json:"command"`
		Cwd     string `json:"cwd"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rw.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache, no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(rw)
	enc := json.NewEncoder(rw)
	w.term.ExecStream(r.Context(), body.Command, body.Cwd, func(ev TermEvent) {
		_ = enc.Encode(ev)
		_ = rc.Flush()
	})
}

func (w *WebServer) handleTermKill(rw http.ResponseWriter, r *http.Request) {
	if w.term == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "terminal runner unavailable"})
		return
	}
	var body struct {
		ExecID string `json:"exec_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	killed := w.term.Kill(strings.TrimSpace(body.ExecID))
	writeJSON(rw, http.StatusOK, map[string]any{"ok": killed})
}
