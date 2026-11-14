package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// RingLogger writes timestamped lines to stdout and keeps the last N lines in memory for the WebUI.
type RingLogger struct {
	mu    sync.Mutex
	lines []string
	cap   int
}

func NewRingLogger(capacity int) *RingLogger {
	return &RingLogger{cap: capacity}
}

func (l *RingLogger) Logf(format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", time.Now().UTC().Format("2006-01-02T15:04:05Z"), fmt.Sprintf(format, args...))
	fmt.Fprintln(os.Stdout, line)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.cap {
		l.lines = l.lines[len(l.lines)-l.cap:]
	}
}

func (l *RingLogger) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.lines))
	copy(out, l.lines)
	return out
}
