package config

import (
	"os"
	"runtime"
	"testing"
)

func setTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	return home
}

func clearLLMEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("SIFT_LLM_PROVIDER", "")
	t.Setenv("SIFT_LLM_API_KEY", "")
	t.Setenv("SIFT_LLM_MODEL", "")
}

func TestLoadAppliesEnvironmentOverridesWithoutConfigFile(t *testing.T) {
	setTestHome(t)
	t.Setenv("SIFT_LLM_PROVIDER", "openai")
	t.Setenv("SIFT_LLM_API_KEY", "test-key")
	t.Setenv("SIFT_LLM_MODEL", "test-model")

	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Provider != ProviderOpenAI {
		t.Fatalf("provider = %q, want %q", cfg.LLM.Provider, ProviderOpenAI)
	}
	if cfg.LLM.APIKey != "test-key" {
		t.Fatalf("API key = %q, want test-key", cfg.LLM.APIKey)
	}
	if cfg.LLM.Model != "test-model" {
		t.Fatalf("model = %q, want test-model", cfg.LLM.Model)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	setTestHome(t)
	clearLLMEnvironment(t)
	want := &Config{
		LLM:    LLMConfig{Provider: ProviderOpenAI, APIKey: "round-trip-key", Model: "test-model"},
		Scan:   ScanConfig{Timeout: 45, Concurrency: 2, Sandbox: "orbital"},
		Output: OutputConfig{Format: "json", Color: false},
	}

	path, err := Save(want)
	if err != nil {
		t.Fatal(err)
	}
	got, loadedPath, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("loaded path = %q, want %q", loadedPath, path)
	}
	if *got != *want {
		t.Fatalf("loaded config = %#v, want %#v", got, want)
	}
}

func TestSaveUsesRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	setTestHome(t)
	clearLLMEnvironment(t)

	path, err := Save(Default())
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("config permissions = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(configDirMust(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("config directory permissions = %04o, want 0700", got)
	}
}

func configDirMust(t *testing.T) string {
	t.Helper()
	dir, err := ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
