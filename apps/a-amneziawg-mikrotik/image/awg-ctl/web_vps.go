package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func (w *WebServer) requireVPSFleet(rw http.ResponseWriter) bool {
	if w.vpsFleet == nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "модуль управления VPS не инициализирован"})
		return false
	}
	return true
}

func (w *WebServer) handleVPSFleetView(rw http.ResponseWriter, _ *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	writeJSON(rw, http.StatusOK, w.vpsFleet.View())
}

func (w *WebServer) handleVPSUpsert(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	var req UpsertVPSRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON: " + err.Error()})
		return
	}
	srv, err := w.vpsFleet.UpsertServer(req)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Immediately try to refresh clients list if token is set
	var refreshErr string
	if srv.AdminTokenSet {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		_, rErr := w.vpsFleet.RefreshServer(ctx, srv.ID, false, false, "")
		cancel()
		if rErr != nil {
			refreshErr = rErr.Error()
		}
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":            true,
		"server":        srv,
		"refresh_error": refreshErr,
		"fleet":         w.vpsFleet.View(),
	})
}

func (w *WebServer) handleVPSDelete(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if err := w.vpsFleet.DeleteServer(id); err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSRefresh(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		NotifyChanges bool `json:"notify_changes"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req)

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	sent, err := w.vpsFleet.RefreshServer(ctx, id, false, req.NotifyChanges, "Синхронизация изменений с VPS")
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]any{
			"error": err.Error(),
			"fleet": w.vpsFleet.View(),
		})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":          true,
		"notified_tg": sent,
		"fleet":       w.vpsFleet.View(),
	})
}

func (w *WebServer) handleVPSEndpoint(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Target         string `json:"target"`
		ResetOverrides bool   `json:"reset_overrides"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON"})
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "укажите target: ipv4, ipv6 или домен/IP"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	res, err := w.vpsFleet.SwitchServerEndpoint(ctx, id, req.Target, req.ResetOverrides)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "result": res, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSPreset(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Preset string `json:"preset"`
		Port   string `json:"port"`
		I1     string `json:"i1"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON"})
		return
	}
	if strings.TrimSpace(req.Preset) == "" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "укажите профиль маскировки"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	res, err := w.vpsFleet.ApplyServerPreset(ctx, id, req.Preset, req.Port, req.I1)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "result": res, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSRotate(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Preset string `json:"preset"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req)

	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	res, err := w.vpsFleet.RotateServer(ctx, id, req.Preset)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "result": res, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSCreateClient(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req CreateVPSClientRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := w.vpsFleet.CreateClient(ctx, id, req)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusCreated, map[string]any{"ok": true, "data": res, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSGetClient(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	name := strings.TrimSpace(r.PathValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	res, err := w.vpsFleet.GetClientConfig(ctx, id, name)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, res)
}

func (w *WebServer) handleVPSUpdateClient(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	name := strings.TrimSpace(r.PathValue("name"))
	var req UpdateVPSClientRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := w.vpsFleet.UpdateClient(ctx, id, name, req)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": res, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSDeleteClient(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	name := strings.TrimSpace(r.PathValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := w.vpsFleet.DeleteClient(ctx, id, name); err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSSendClientTG(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	name := strings.TrimSpace(r.PathValue("name"))
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req)
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "Отправка актуальной конфигурации вручную"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	if err := w.vpsFleet.SendClientToTelegram(ctx, id, name, reason); err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]any{"error": err.Error(), "fleet": w.vpsFleet.View()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleVPSImportClientLocal(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	name := strings.TrimSpace(r.PathValue("name"))
	var req struct {
		LocalName string `json:"local_name"`
		Activate  bool   `json:"activate"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	savedName, err := w.vpsFleet.ImportClientToRouter(ctx, id, name, req.LocalName, req.Activate)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "name": savedName})
}

func (w *WebServer) handleTGContactUpsert(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	var c TGContact
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&c); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "некорректный JSON"})
		return
	}
	saved, err := w.vpsFleet.UpsertContact(c)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "contact": saved, "fleet": w.vpsFleet.View()})
}

func (w *WebServer) handleTGContactDelete(rw http.ResponseWriter, r *http.Request) {
	if !w.requireVPSFleet(rw) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if err := w.vpsFleet.DeleteContact(id); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "fleet": w.vpsFleet.View()})
}
