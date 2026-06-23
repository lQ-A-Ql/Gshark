//go:build (dev && !windows) || (production && !windows) || (bindings && !windows)

package main

import "os/exec"

func hideChildProcessWindow(_ *exec.Cmd) {}
