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

// FileCache 提供基於 SHA256 的檔案變更偵測，支援增量掃描。
// 企業級功能：只掃描自上次以來變更的檔案，大幅減少重複掃描時間。
type FileCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry `json:"entries"`
	path     string
}

// CacheEntry 記錄單一檔案的快取狀態。
type CacheEntry struct {
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	LastScan  time.Time `json:"last_scan"`
	Findings  int       `json:"findings"`
}

// NewFileCache 建立或載入快取。
func NewFileCache(projectRoot string) (*FileCache, error) {
	cacheDir := filepath.Join(projectRoot, ".sift")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("建立快取目錄失敗: %w", err)
	}

	cachePath := filepath.Join(cacheDir, "cache.json")
	fc := &FileCache{
		entries: make(map[string]*CacheEntry),
		path:    cachePath,
	}

	// 嘗試載入既有快取
	data, err := os.ReadFile(cachePath)
	if err == nil {
		json.Unmarshal(data, &fc.entries)
	}

	return fc, nil
}

// IsChanged 檢查檔案自上次掃描後是否有變更。
// 回傳 true 表示需要重新掃描。
func (fc *FileCache) IsChanged(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// 計算目前 hash
	hash, err := fc.hashFile(path)
	if err != nil {
		return true, err // 無法讀取時保守地回傳需要掃描
	}

	fc.mu.RLock()
	entry, exists := fc.entries[path]
	fc.mu.RUnlock()

	if !exists {
		return true, nil // 新檔案，需要掃描
	}

	// 比較 hash、大小、修改時間
	if entry.SHA256 != hash || entry.Size != info.Size() {
		return true, nil
	}

	return false, nil
}

// MarkScanned 標記檔案已完成掃描。
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

// FilterChanged 從檔案清單中過濾出需要掃描的檔案。
func (fc *FileCache) FilterChanged(files []string) ([]string, error) {
	var changed []string
	for _, f := range files {
		changed_, err := fc.IsChanged(f)
		if err != nil {
			changed = append(changed, f) // 保守策略
			continue
		}
		if changed_ {
			changed = append(changed, f)
		}
	}
	return changed, nil
}

// Save 將快取寫入磁碟。
func (fc *FileCache) Save() error {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// 清理不存在的檔案
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

// Stats 回傳快取統計資訊。
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

// Purge 清除所有快取。
func (fc *FileCache) Purge() error {
	fc.mu.Lock()
	fc.entries = make(map[string]*CacheEntry)
	fc.mu.Unlock()
	return fc.Save()
}

// hashFile 計算檔案的 SHA256 hash。
func (fc *FileCache) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
