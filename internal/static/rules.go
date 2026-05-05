package static

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

func init() {
	embeddedRules = make(map[string]string)
	entries, err := fs.ReadDir(rulesFS, "rules")
	if err != nil {
		// 開發模式：從磁碟讀取
		loadRulesFromDisk()
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := rulesFS.ReadFile(filepath.Join("rules", entry.Name()))
		if err != nil {
			continue
		}
		embeddedRules[entry.Name()] = string(content)
	}
}

func loadRulesFromDisk() {
	// 開發備案：嘗試從 rules/ 目錄載入
	rulesDir := filepath.Join("internal", "static", "rules")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		if err != nil {
			continue
		}
		embeddedRules[entry.Name()] = string(content)
	}
}
