package securepath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelativePathsUseBaseNotWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	t.Chdir(t.TempDir())
	for _, name := range []string{"file.txt", "..valid.txt"} {
		if err := WriteFile(base, name, []byte("safe"), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := ReadFile(base, name)
		if err != nil || string(data) != "safe" {
			t.Fatalf("read %s: %q, %v", name, data, err)
		}
		if _, err := ValidatePath(base, name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSymlinkEscapesAreRejected(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, name := range []string{"escape/secret", "escape/new", "escape/newdir/new"} {
		if _, err := ValidatePath(base, name); err == nil {
			t.Fatalf("validated escape %s", name)
		}
		if _, err := ReadFile(base, name); err == nil {
			t.Fatalf("read escape %s", name)
		}
		if err := WriteFile(base, name, []byte("changed"), 0o600); err == nil {
			t.Fatalf("wrote escape %s", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(outside, "secret"))
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside file modified: %q, %v", data, err)
	}
}

func TestRelativeInternalSymlinkWorks(t *testing.T) {
	base := t.TempDir()
	if err := WriteFile(base, "real", []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	data, err := ReadFile(base, "link")
	if err != nil || string(data) != "safe" {
		t.Fatalf("internal link: %q, %v", data, err)
	}
}

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
