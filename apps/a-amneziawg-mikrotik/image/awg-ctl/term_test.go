package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTermRunnerCDStreamAndKill(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewTermRunner(dir)

	// 1. Standalone cd updates cwd
	var events []TermEvent
	r.ExecStream(context.Background(), "cd sub", dir, func(ev TermEvent) {
		events = append(events, ev)
	})
	last := events[len(events)-1]
	if last.Type != "exit" || last.ExitCode != 0 || last.Cwd != sub {
		t.Fatalf("expected cd into %s, got %+v", sub, last)
	}

	// 2. Shell command preserves pwd and streams output
	events = nil
	r.ExecStream(context.Background(), "printf 'ok-line'", sub, func(ev TermEvent) {
		events = append(events, ev)
	})
	var out strings.Builder
	for _, ev := range events {
		if ev.Type == "data" {
			out.WriteString(ev.Data)
		}
	}
	last = events[len(events)-1]
	if out.String() != "ok-line" || last.ExitCode != 0 || last.Cwd != sub {
		t.Fatalf("unexpected exec result out=%q last=%+v", out.String(), last)
	}

	// 3. Kill interrupts long-running command quickly
	execIDCh := make(chan string, 1)
	doneCh := make(chan TermEvent, 1)
	go r.ExecStream(context.Background(), "sleep 10", dir, func(ev TermEvent) {
		if ev.Type == "start" {
			select {
			case execIDCh <- ev.ExecID:
			default:
			}
		} else if ev.Type == "exit" {
			doneCh <- ev
		}
	})
	id := <-execIDCh
	time.Sleep(80 * time.Millisecond)
	if !r.Kill(id) {
		t.Fatalf("expected Kill(%s) to return true", id)
	}
	select {
	case ev := <-doneCh:
		if ev.ExitCode == 0 {
			t.Fatalf("expected non-zero exit after kill, got %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("command did not terminate after Kill")
	}
}

func TestWebETagGzipAndTermEndpoint(t *testing.T) {
	t.Setenv("TERM_ENABLE", "on")
	dir := t.TempDir()
	logger := NewRingLogger(20)
	mgr := NewTunnelManager(dir, filepath.Join(dir, "run"), "eth0", true, true, logger)
	st, _ := NewSettingsStore(dir)
	geo := NewGeoStore(dir, logger)
	pol := NewPolicyEngine(dir, st, geo, mgr, logger)
	ros := NewROSClient(dir, logger)
	w := NewWebServer(":0", mgr, nil, ros, st, geo, pol, logger)
	w.uiUser = "admin"
	w.uiPass = "secret"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", w.withAuth(w.handleIndex))
	mux.HandleFunc("GET /api/status", w.withAuth(w.handleStatus))
	mux.HandleFunc("POST /api/term/exec", w.withAuth(w.handleTermExec))
	handler := w.gzipMiddleware(mux)

	// Unauthenticated must be 401
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	rw0 := httptest.NewRecorder()
	handler.ServeHTTP(rw0, req0)
	if rw0.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rw0.Code)
	}

	// Pre-gzipped / + ETag 304
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.SetBasicAuth("admin", "secret")
	req1.Header.Set("Accept-Encoding", "gzip")
	rw1 := httptest.NewRecorder()
	handler.ServeHTTP(rw1, req1)
	if rw1.Code != http.StatusOK || rw1.Header().Get("Content-Encoding") != "gzip" || rw1.Header().Get("ETag") == "" {
		t.Fatalf("unexpected / response: code=%d enc=%q etag=%q", rw1.Code, rw1.Header().Get("Content-Encoding"), rw1.Header().Get("ETag"))
	}
	gr, err := gzip.NewReader(rw1.Body)
	if err != nil {
		t.Fatal(err)
	}
	htmlBytes, _ := io.ReadAll(gr)
	_ = gr.Close()
	if !strings.Contains(string(htmlBytes), "Терминал контейнера") {
		t.Fatalf("decompressed ui.html missing Terminal tab")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.SetBasicAuth("admin", "secret")
	req2.Header.Set("If-None-Match", rw1.Header().Get("ETag"))
	rw2 := httptest.NewRecorder()
	handler.ServeHTTP(rw2, req2)
	if rw2.Code != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified on ETag match, got %d", rw2.Code)
	}

	// /api/term/exec unbuffered NDJSON
	req3 := httptest.NewRequest(http.MethodPost, "/api/term/exec", strings.NewReader(`{"command":"echo term-ok"}`))
	req3.SetBasicAuth("admin", "secret")
	req3.Header.Set("Accept-Encoding", "gzip")
	rw3 := httptest.NewRecorder()
	handler.ServeHTTP(rw3, req3)
	if rw3.Code != http.StatusOK || rw3.Header().Get("Content-Encoding") != "" {
		t.Fatalf("expected uncompressed streaming NDJSON 200, got code=%d enc=%q", rw3.Code, rw3.Header().Get("Content-Encoding"))
	}
	var gotTerm bool
	for _, line := range strings.Split(strings.TrimSpace(rw3.Body.String()), "\n") {
		var ev TermEvent
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == "data" && strings.Contains(ev.Data, "term-ok") {
			gotTerm = true
		}
	}
	if !gotTerm {
		t.Fatalf("expected streamed term-ok output, got:\n%s", rw3.Body.String())
	}
}
