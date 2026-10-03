//go:build windows

package runner

import (
	"os/exec"
)

// CommandContext terminates the child on Windows. Descendants are not sandboxed.
func configureProcess(cmd *exec.Cmd) {}
