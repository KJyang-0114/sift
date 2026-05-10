package securepath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatePath resolves baseDir and path to absolute paths, then verifies that
// the resolved path lies within baseDir (path traversal protection).
// Returns the resolved absolute path on success, or an error if traversal is detected.
func ValidatePath(baseDir, path string) (string, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("securepath: cannot resolve base directory %q: %w", baseDir, err)
	}

	// Resolve the target path. If it is already absolute, resolve it directly.
	// If relative, resolve it relative to the base directory.
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("securepath: cannot resolve path %q: %w", path, err)
	}

	// Clean the base directory path to ensure consistent comparison.
	absBase = filepath.Clean(absBase)
	resolved = filepath.Clean(resolved)

	// Use filepath.Rel to check if resolved is inside absBase.
	rel, err := filepath.Rel(absBase, resolved)
	if err != nil {
		return "", fmt.Errorf("securepath: path traversal detected: %q is outside base directory %q", path, absBase)
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("securepath: path traversal detected: %q resolves outside base directory %q", path, absBase)
	}

	return resolved, nil
}

// ReadFile validates that path is within baseDir, then reads and returns the file contents.
// Returns an error if path traversal is detected or if the file cannot be read.
func ReadFile(baseDir, path string) ([]byte, error) {
	resolved, err := ValidatePath(baseDir, path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

// WriteFile validates that path is within baseDir, then writes data to the file.
// Returns an error if path traversal is detected or if the file cannot be written.
func WriteFile(baseDir, path string, data []byte, perm os.FileMode) error {
	resolved, err := ValidatePath(baseDir, path)
	if err != nil {
		return err
	}
	return os.WriteFile(resolved, data, perm)
}
