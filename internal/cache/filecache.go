package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileCache provides SHA256-based file change detection for incremental scanning.
// Enterprise feature: only scans files changed since last run, dramatically reducing repeat scan time.
type FileCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry `json:"entries"`
	path     string
}

// CacheEntry records the cached state of a single file.
type CacheEntry struct {
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	LastScan  time.Time `json:"last_scan"`
	Findings  int       `json:"findings"`
}

// NewFileCache creates or loads the cache.
func NewFileCache(projectRoot string) (*FileCache, error) {
	cacheDir := filepath.Join(projectRoot, ".sift")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath := filepath.Join(cacheDir, "cache.json")
	fc := &FileCache{
		entries: make(map[string]*CacheEntry),
		path:    cachePath,
	}

	// Try loading existing cache
	data, err := os.ReadFile(cachePath)
	if err == nil {
		json.Unmarshal(data, &fc.entries)
	}

	return fc, nil
}

// IsChanged checks whether a file has changed since the last scan.
// Returns true if the file needs to be rescanned.
func (fc *FileCache) IsChanged(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// Compute current hash
	hash, err := fc.hashFile(path)
	if err != nil {
		return true, err // Conservatively return true when unreadable
	}

	fc.mu.RLock()
	entry, exists := fc.entries[path]
	fc.mu.RUnlock()

	if !exists {
		return true, nil // New file, needs scanning
	}

	// Compare hash, size, modification time
	if entry.SHA256 != hash || entry.Size != info.Size() {
		return true, nil
	}

	return false, nil
}

// MarkScanned marks a file as scanned.
func (fc *FileCache) MarkScanned(path string, findings int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	hash, err := fc.hashFile(path)
	if err != nil {
		return err
	}

	fc.mu.Lock()
	fc.entries[path] = &CacheEntry{
		Path:     path,
		SHA256:   hash,
		Size:     info.Size(),
		ModTime:  info.ModTime(),
		LastScan: time.Now(),
		Findings: findings,
	}
	fc.mu.Unlock()

	return nil
}

// FilterChanged filters the file list to those needing a scan.
func (fc *FileCache) FilterChanged(files []string) ([]string, error) {
	var changed []string
	for _, f := range files {
		changed_, err := fc.IsChanged(f)
		if err != nil {
			changed = append(changed, f) // Conservative strategy
			continue
		}
		if changed_ {
			changed = append(changed, f)
		}
	}
	return changed, nil
}

// Save writes the cache to disk.
func (fc *FileCache) Save() error {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// Clean up non-existent files
	for path := range fc.entries {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			delete(fc.entries, path)
		}
	}

	data, err := json.MarshalIndent(fc.entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(fc.path, data, 0o644)
}

// Stats returns cache statistics.
func (fc *FileCache) Stats() map[string]int {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	totalFindings := 0
	for _, e := range fc.entries {
		totalFindings += e.Findings
	}

	return map[string]int{
		"cached_files":    len(fc.entries),
		"total_findings":  totalFindings,
	}
}

// Purge clears all cache entries.
func (fc *FileCache) Purge() error {
	fc.mu.Lock()
	fc.entries = make(map[string]*CacheEntry)
	fc.mu.Unlock()
	return fc.Save()
}

// hashFile computes the SHA256 hash of a file.
func (fc *FileCache) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
