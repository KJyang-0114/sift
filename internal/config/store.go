package config

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/BurntSushi/toml"
)

// Save writes the configuration to the default path.
func Save(cfg *Config) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("unable to create config directory %s: %w", dir, err)
	}

	path, err := ConfigPath()
	if err != nil {
		return "", err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("unable to write config file %s: %w", path, err)
	}

	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("unable to encode config: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("unable to close config file %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("unable to restrict config file %s: %w", path, err)
		}
	}

	return path, nil
}

// Load loads configuration from the default path. Returns defaults if the config file does not exist.
func Load() (*Config, string, error) {
	return LoadFile("")
}

// LoadFile loads an explicit file, or the optional default file when path is empty.
// Explicit paths never silently fall back to defaults.
func LoadFile(path string) (*Config, string, error) {
	explicit := path != ""
	if !explicit {
		var err error
		path, err = ConfigPath()
		if err != nil {
			return nil, "", err
		}
	}

	cfg := Default()

	if _, err := os.Stat(path); !explicit && os.IsNotExist(err) {
		cfg.applyEnvOverrides()
		return cfg, path, nil
	}

	meta, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, path, fmt.Errorf("config file format error %s: %w", path, err)
	}
	if explicit {
		if undecoded := meta.Undecoded(); len(undecoded) > 0 {
			return nil, path, fmt.Errorf("config file contains unknown fields: %s", undecoded)
		}
	}

	// Environment variable overrides
	cfg.applyEnvOverrides()

	return cfg, path, nil
}

// applyEnvOverrides overrides config values with environment variables.
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

// Editor opens the config file in the default editor.
func Editor() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	// Ensure config file exists
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
