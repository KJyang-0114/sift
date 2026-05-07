package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Result is the outcome of a single code execution in the sandbox.
type Result struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
	Error    string        `json:"error,omitempty"`
}

// Orbital is a lightweight code isolation executor with zero external dependencies.
type Orbital struct {
	timeout      time.Duration
	maxOutputLen int
	workDir      string
}

// NewOrbital creates an Orbital sandbox.
func NewOrbital(timeout time.Duration) *Orbital {
	return &Orbital{
		timeout:      timeout,
		maxOutputLen: 100 * 1024, // 100KB max output
	}
}

// Run executes code in an isolated environment.
// lang can be "python", "javascript", "go", or "bash".
func (o *Orbital) Run(code, lang string) (*Result, error) {
	// Create isolated working directory
	workDir, err := os.MkdirTemp("", "sift-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	// Write code file
	filePath, err := o.writeCodeFile(workDir, code, lang)
	if err != nil {
		return nil, err
	}

	// Build execution command
	cmd := o.buildCommand(filePath, lang)
	if cmd == nil {
		return nil, fmt.Errorf("unsupported language: %s", lang)
	}

	// Set process group (so subprocesses can be killed)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Dir = workDir

	// Set isolated environment variables
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"LANG=en_US.UTF-8",
	}

	start := time.Now()

	// Limit execution time with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = workDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"LANG=en_US.UTF-8",
	}

	// Capture output
	stdout := &limitedBuffer{max: o.maxOutputLen}
	stderr := &limitedBuffer{max: o.maxOutputLen}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Run()

	result := &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.TimedOut = true
			result.Error = fmt.Sprintf("execution timed out (limit: %v)", o.timeout)
			killProcess(cmd)
			return result, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Error = fmt.Sprintf("execution failed (exit code: %d)", result.ExitCode)
			return result, nil
		}
		result.Error = fmt.Sprintf("execution failed: %v", err)
		return result, nil
	}

	result.ExitCode = 0
	return result, nil
}

// writeCodeFile writes code to a file with the appropriate extension for the language.
func (o *Orbital) writeCodeFile(dir, code, lang string) (string, error) {
	var filename string
	switch lang {
	case "python":
		filename = "code.py"
	case "javascript":
		filename = "code.js"
	case "go":
		filename = "main.go"
	case "bash":
		filename = "script.sh"
	default:
		filename = "code.txt"
	}

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		return "", fmt.Errorf("failed to write code file: %w", err)
	}

	return path, nil
}

// buildCommand builds the appropriate execution command for the given language.
func (o *Orbital) buildCommand(filePath, lang string) *exec.Cmd {
	switch lang {
	case "python":
		return exec.Command("python3", filePath)
	case "javascript":
		// Prefer node
		return exec.Command("node", filePath)
	case "go":
		return exec.Command("go", "run", filePath)
	case "bash":
		return exec.Command("bash", filePath)
	default:
		return nil
	}
}

// Available checks whether the execution environment for a given language is available.
func Available(lang string) bool {
	switch lang {
	case "python":
		return commandExists("python3") || commandExists("python")
	case "javascript":
		return commandExists("node")
	case "go":
		return commandExists("go")
	case "bash":
		return true
	}
	return false
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func killProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		// Use negative PID to kill the entire process group
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			cmd.Process.Kill()
		}
	}
}

// limitedBuffer is a buffer that limits the maximum output length.
type limitedBuffer struct {
	buf strings.Builder
	max int
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.buf.Len()+len(p) > lb.max {
		n := lb.max - lb.buf.Len()
		if n > 0 {
			lb.buf.Write(p[:n])
		}
		return len(p), nil
	}
	return lb.buf.Write(p)
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}
