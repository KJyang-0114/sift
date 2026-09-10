package securepath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// relativePath interprets relative names against baseDir, never the process cwd.
func relativePath(baseDir, name string) (string, string, error) {
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return "", "", err
	}
	if name == "" {
		return "", "", fmt.Errorf("securepath: empty path")
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(base, name)
	}
	rel, err := filepath.Rel(base, name)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("securepath: path traversal detected: %q is outside base directory %q", name, base)
	}
	return base, rel, nil
}

// ValidatePath checks lexical and symlink containment, including existing parents
// of a new file. The returned name is not an authority for later filesystem I/O:
// callers must use rooted operations to avoid symlink replacement races.
func ValidatePath(baseDir, name string) (string, error) {
	base, rel, err := relativePath(baseDir, name)
	if err != nil {
		return "", err
	}
	canonicalBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(base, rel)
	ancestor := candidate
	for {
		_, err := os.Lstat(ancestor)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", err
			}
			if _, _, err := relativePath(canonicalBase, resolved); err != nil {
				return "", err
			}
			return candidate, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", err
		}
		ancestor = parent
	}
}

// ReadFile uses an OS-rooted operation so links cannot escape between validation
// and access. Absolute symlinks are rejected, including links back into the root.
func ReadFile(baseDir, name string) ([]byte, error) {
	base, rel, err := relativePath(baseDir, name)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(rel)
}

// WriteFile creates or replaces a file without following links outside baseDir.
func WriteFile(baseDir, name string, data []byte, perm os.FileMode) error {
	base, rel, err := relativePath(baseDir, name)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFile(rel, data, perm)
}
