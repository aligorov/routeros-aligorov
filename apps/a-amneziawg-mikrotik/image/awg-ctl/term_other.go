//go:build !unix

package main

import "os/exec"

func setProcGroup(_ *exec.Cmd) {}

func killProcGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
