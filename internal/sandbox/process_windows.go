//go:build windows

package sandbox

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}

func killProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
