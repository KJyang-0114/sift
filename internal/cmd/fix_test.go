package cmd

import (
	"bytes"
	"context"
	"fmt"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixRejectsInvalidConfigBeforeScanning(t *testing.T) {
	t.Setenv("SIFT_LLM_PROVIDER", "")
	t.Setenv("SIFT_LLM_API_KEY", "")
	t.Setenv("SIFT_LLM_MODEL", "")
	for _, tc := range []struct{ name, config, message string }{
		{"timeout", "[scan]\ntimeout = 0\n", "must be greater than zero"},
		{"concurrency", "[scan]\nconcurrency = -1\n", "must be greater than zero"},
		{"sandbox", "[scan]\nsandbox = 'unknown'\n", "unsupported sandbox"},
		{"provider", "[llm]\nprovider = 'unknown'\n", "unsupported LLM provider"},
		{"format", "[output]\nformat = 'unknown'\n", "unsupported output format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			root := NewRootCmd("test", "test", "test")
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			// An absent target distinguishes config rejection from scan errors.
			root.SetArgs([]string{"fix", filepath.Join(t.TempDir(), "absent"), "--config", path})
			err := root.Execute()
			if ExitCode(err) != 2 || err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("exit=%d err=%v, want configuration error %q", ExitCode(err), err, tc.message)
			}
		})
	}
}

func TestFixRollbackNeedsNoModel(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.py")
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".sift.bak", []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd("test", "test", "test")
	root.SetArgs([]string{"fix", file, "--rollback", "--config", filepath.Join(dir, "missing.toml")})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != "original" {
		t.Fatalf("got %q: %v", got, err)
	}
	if _, err := os.Stat(file + ".sift.bak"); !os.IsNotExist(err) {
		t.Fatalf("backup remains: %v", err)
	}
}

type partialFixScan struct{}

func (partialFixScan) RunTo(context.Context, string, string, io.Writer) error {
	return &core.OperationError{Kind: core.DiagnosticAnalyzer, Err: fmt.Errorf("incomplete fixture scan")}
}
func (partialFixScan) LastFindings() []core.Finding { return nil }
func TestFixPreservesPartialScanWithoutFindings(t *testing.T) {
	t.Setenv("SIFT_LLM_PROVIDER", "offline")
	file := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(file, []byte("[llm]\nprovider='offline'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd("test", "test", "test")
	for _, cmd := range root.Commands() {
		if cmd.Name() == "fix" {
			root.RemoveCommand(cmd)
		}
	}
	root.AddCommand(newFixCmdWithFactory(func(*config.Config) fixScanService { return partialFixScan{} }))
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"fix", ".", "--config", file})
	if err := root.Execute(); ExitCode(err) != 3 {
		t.Fatalf("exit=%d err=%v", ExitCode(err), err)
	}
	if strings.Contains(output.String(), "No issues to fix") {
		t.Fatal("partial scan presented as clean")
	}
}
