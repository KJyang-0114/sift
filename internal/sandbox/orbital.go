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

// Result 是沙盒執行一次程式碼的結果。
type Result struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
	Error    string        `json:"error,omitempty"`
}

// Orbital 是零外部依賴的輕量級程式碼隔離執行器。
type Orbital struct {
	timeout      time.Duration
	maxOutputLen int
	workDir      string
}

// NewOrbital 建立 Orbital 沙盒。
func NewOrbital(timeout time.Duration) *Orbital {
	return &Orbital{
		timeout:      timeout,
		maxOutputLen: 100 * 1024, // 100KB max output
	}
}

// Run 在隔離環境中執行程式碼。
// lang 可以是 "python", "javascript", "go", "bash"。
func (o *Orbital) Run(code, lang string) (*Result, error) {
	// 建立獨立工作目錄
	workDir, err := os.MkdirTemp("", "sift-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("建立沙盒目錄失敗: %w", err)
	}
	defer os.RemoveAll(workDir)

	// 寫入程式碼檔案
	filePath, err := o.writeCodeFile(workDir, code, lang)
	if err != nil {
		return nil, err
	}

	// 建立執行指令
	cmd := o.buildCommand(filePath, lang)
	if cmd == nil {
		return nil, fmt.Errorf("不支援的語言: %s", lang)
	}

	// 設定 process group（讓 subprocess 可以被 kill）
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Dir = workDir

	// 設定環境變數隔離
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"LANG=en_US.UTF-8",
	}

	start := time.Now()

	// 以 context timeout 限制執行時間
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

	// 擷取輸出
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
			result.Error = fmt.Sprintf("執行超時 (限制: %v)", o.timeout)
			killProcess(cmd)
			return result, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Error = fmt.Sprintf("執行失敗 (exit code: %d)", result.ExitCode)
			return result, nil
		}
		result.Error = fmt.Sprintf("執行失敗: %v", err)
		return result, nil
	}

	result.ExitCode = 0
	return result, nil
}

// writeCodeFile 將程式碼寫入對應語言的檔案。
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
		return "", fmt.Errorf("寫入程式碼檔案失敗: %w", err)
	}

	return path, nil
}

// buildCommand 根據語言建立對應的執行指令。
func (o *Orbital) buildCommand(filePath, lang string) *exec.Cmd {
	switch lang {
	case "python":
		return exec.Command("python3", filePath)
	case "javascript":
		// 優先使用 node
		return exec.Command("node", filePath)
	case "go":
		return exec.Command("go", "run", filePath)
	case "bash":
		return exec.Command("bash", filePath)
	default:
		return nil
	}
}

// Available 檢查特定語言的執行環境是否可用。
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
		// 用負 PID kill 整個 process group
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			cmd.Process.Kill()
		}
	}
}

// limitedBuffer 限制最大輸出長度的 buffer。
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
