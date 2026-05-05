package config

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/BurntSushi/toml"
)

// Save 將設定寫入預設路徑。
func Save(cfg *Config) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("無法建立設定目錄 %s: %w", dir, err)
	}

	path, err := ConfigPath()
	if err != nil {
		return "", err
	}

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("無法寫入設定檔 %s: %w", path, err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		return "", fmt.Errorf("無法編碼設定: %w", err)
	}

	return path, nil
}

// Load 從預設路徑載入設定。如果設定檔不存在，回傳預設值。
func Load() (*Config, string, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, "", err
	}

	cfg := Default()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, path, nil
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, path, fmt.Errorf("設定檔格式錯誤 %s: %w", path, err)
	}

	// 環境變數覆蓋
	cfg.applyEnvOverrides()

	return cfg, path, nil
}

// applyEnvOverrides 以環境變數覆蓋設定值。
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("SIFT_LLM_PROVIDER"); v != "" {
		c.LLM.Provider = LLMProvider(v)
	}
	if v := os.Getenv("SIFT_LLM_API_KEY"); v != "" {
		c.LLM.APIKey = v
	}
	if v := os.Getenv("SIFT_LLM_MODEL"); v != "" {
		c.LLM.Model = v
	}
}

// Editor 開啟預設編輯器編輯設定檔。
func Editor() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	// 確保設定檔存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if _, err := Save(Default()); err != nil {
			return err
		}
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		switch runtime.GOOS {
		case "darwin":
			editor = "open -t"
		case "linux":
			editor = "nano"
		case "windows":
			editor = "notepad"
		}
	}

	var cmd *exec.Cmd
	if editor == "open -t" {
		cmd = exec.Command("open", "-t", path)
	} else {
		cmd = exec.Command(editor, path)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
