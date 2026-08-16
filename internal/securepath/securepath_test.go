package securepath

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePathAcceptsAbsolutePathInsideBase(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "file.txt")

	got, err := ValidatePath(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(path) {
		t.Fatalf("resolved path = %q, want %q", got, filepath.Clean(path))
	}
}

func TestValidatePathRejectsOutsideAbsolutePath(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")

	_, err := ValidatePath(base, outside)
	if err == nil {
		t.Fatal("ValidatePath accepted a path outside the base directory")
	}
	if !strings.Contains(err.Error(), "path traversal detected") {
		t.Fatalf("error = %q, want path traversal diagnostic", err)
	}
}

func TestReadWriteFileInsideBase(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "file.txt")

	if err := WriteFile(base, path, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "safe" {
		t.Fatalf("content = %q, want %q", got, "safe")
	}
}

func TestReadWriteFileRejectOutsideBase(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")

	if err := WriteFile(base, outside, []byte("unsafe"), 0o600); err == nil {
		t.Fatal("WriteFile accepted a path outside the base directory")
	}
	if _, err := ReadFile(base, outside); err == nil {
		t.Fatal("ReadFile accepted a path outside the base directory")
	}
}
