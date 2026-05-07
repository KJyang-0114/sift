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

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("unable to write config file %s: %w", path, err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		return "", fmt.Errorf("unable to encode config: %w", err)
	}

	return path, nil
}

// Load loads configuration from the default path. Returns defaults if the config file does not exist.
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
		return nil, path, fmt.Errorf("config file format error %s: %w", path, err)
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
