package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	termDefaultTimeout = 45 * time.Second
	termMaxOutputBytes = 512 * 1024
)

type TermEvent struct {
	Type     string `json:"type"` // "start" | "data" | "exit"
	ExecID   string `json:"exec_id,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	Data     string `json:"data,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

type runningTermCmd struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
}

type TermRunner struct {
	mu      sync.Mutex
	baseDir string
	running map[string]*runningTermCmd
}

func NewTermRunner(baseDir string) *TermRunner {
	if baseDir == "" {
		baseDir = "/etc/amnezia/amneziawg"
	}
	return &TermRunner{
		baseDir: baseDir,
		running: make(map[string]*runningTermCmd),
	}
}

func (r *TermRunner) ResolveCwd(cwd string) string {
	c := strings.TrimSpace(cwd)
	if c == "" {
		if info, err := os.Stat(r.baseDir); err == nil && info.IsDir() {
			return r.baseDir
		}
		if wd, err := os.Getwd(); err == nil {
			return wd
		}
		return "/"
	}
	if !filepath.IsAbs(c) {
		c = filepath.Join(r.baseDir, c)
	}
	c = filepath.Clean(c)
	if info, err := os.Stat(c); err == nil && info.IsDir() {
		return c
	}
	return "/"
}

func newExecID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// isPureCD handles standalone `cd` / `cd <dir>` so interactive directory state persists cleanly.
func parsePureCD(cmdline string) (target string, ok bool) {
	t := strings.TrimSpace(cmdline)
	if t == "cd" {
		return "~", true
	}
	if !strings.HasPrefix(t, "cd ") && !strings.HasPrefix(t, "cd\t") {
		return "", false
	}
	// If chained with shell operators, let /bin/sh execute the full pipeline.
	if strings.ContainsAny(t, ";&|\n`$") {
		return "", false
	}
	rest := strings.TrimSpace(t[2:])
	rest = strings.Trim(rest, `"'`)
	if rest == "" {
		rest = "~"
	}
	return rest, true
}

func (r *TermRunner) ExecStream(ctx context.Context, command, cwd string, emit func(TermEvent)) {
	curDir := r.ResolveCwd(cwd)
	cmdStr := strings.TrimSpace(command)
	execID := newExecID()
	emit(TermEvent{Type: "start", ExecID: execID, Cwd: curDir})

	if cmdStr == "" {
		emit(TermEvent{Type: "exit", ExecID: execID, Cwd: curDir, ExitCode: 0})
		return
	}

	if target, ok := parsePureCD(cmdStr); ok {
		if target == "~" {
			target = "/root"
			if h, err := os.UserHomeDir(); err == nil && h != "" {
				target = h
			}
		} else if !filepath.IsAbs(target) {
			target = filepath.Join(curDir, target)
		}
		target = filepath.Clean(target)
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			msg := fmt.Sprintf("cd: %s: No such directory\n", target)
			emit(TermEvent{Type: "data", ExecID: execID, Data: msg})
			emit(TermEvent{Type: "exit", ExecID: execID, Cwd: curDir, ExitCode: 1})
			return
		}
		emit(TermEvent{Type: "exit", ExecID: execID, Cwd: target, ExitCode: 0})
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, termDefaultTimeout)
	defer cancel()

	// Append pwd marker on exit so chained commands like `cd foo && pwd` persist cwd cleanly.
	marker := "__AWGPWD_" + execID + "__"
	wrapped := cmdStr + "\n__rc=$?\nprintf '%s%s\\n' '" + marker + "' \"$PWD\"\nexit $__rc"

	shellBin := "/bin/sh"
	cmd := exec.Command(shellBin, "-c", wrapped)
	cmd.Dir = curDir
	setProcGroup(cmd)

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		emit(TermEvent{Type: "data", ExecID: execID, Data: err.Error() + "\n"})
		emit(TermEvent{Type: "exit", ExecID: execID, Cwd: curDir, ExitCode: 127, Error: err.Error()})
		return
	}

	r.mu.Lock()
	r.running[execID] = &runningTermCmd{cancel: cancel, cmd: cmd}
	r.mu.Unlock()

	doneKill := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			killProcGroup(cmd)
		case <-doneKill:
		}
	}()

	waitCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		waitCh <- err
	}()

	newCwd := curDir
	totalBytes := 0
	truncated := false
	reader := bufio.NewReaderSize(pr, 4096)
	for {
		chunk, readErr := reader.ReadString('\n')
		if chunk != "" {
			if idx := strings.Index(chunk, marker); idx >= 0 {
				before := chunk[:idx]
				after := strings.TrimSpace(chunk[idx+len(marker):])
				if info, err := os.Stat(after); err == nil && info.IsDir() {
					newCwd = after
				}
				chunk = before
			}
			if chunk != "" && !truncated {
				if totalBytes+len(chunk) > termMaxOutputBytes {
					remain := termMaxOutputBytes - totalBytes
					if remain > 0 {
						emit(TermEvent{Type: "data", ExecID: execID, Data: chunk[:remain]})
					}
					emit(TermEvent{Type: "data", ExecID: execID, Data: "\n...[вывод обрезан > 512 KiB]\n"})
					truncated = true
				} else {
					totalBytes += len(chunk)
					emit(TermEvent{Type: "data", ExecID: execID, Data: chunk})
				}
			}
		}
		if readErr != nil {
			break
		}
	}

	waitErr := <-waitCh
	close(doneKill)

	r.mu.Lock()
	delete(r.running, execID)
	r.mu.Unlock()

	code := 0
	errMsg := ""
	if waitErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			code = 124
			errMsg = "timeout (45s)"
			emit(TermEvent{Type: "data", ExecID: execID, Data: "\n[Прервано по таймауту 45s]\n"})
		} else if errors.Is(runCtx.Err(), context.Canceled) {
			code = 130
			errMsg = "interrupted"
			emit(TermEvent{Type: "data", ExecID: execID, Data: "\n^C\n"})
		} else {
			var ee *exec.ExitError
			if errors.As(waitErr, &ee) {
				code = ee.ExitCode()
			} else {
				code = 1
				errMsg = waitErr.Error()
			}
		}
	}

	emit(TermEvent{Type: "exit", ExecID: execID, Cwd: newCwd, ExitCode: code, Error: errMsg})
}

func (r *TermRunner) Kill(execID string) bool {
	r.mu.Lock()
	entry := r.running[execID]
	r.mu.Unlock()
	if entry == nil {
		return false
	}
	entry.cancel()
	killProcGroup(entry.cmd)
	return true
}
