//go:build dev || production || bindings

package main

import (
	"os/exec"
	"syscall"
)

func hideChildProcessWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
