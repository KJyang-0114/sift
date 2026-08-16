package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileCacheLifecycle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app.go")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	cache, err := NewFileCache(root)
	if err != nil {
		t.Fatal(err)
	}
	assertChanged(t, cache, path, true)
	if err := cache.MarkScanned(path, 2); err != nil {
		t.Fatal(err)
	}
	assertChanged(t, cache, path, false)
	if err := cache.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewFileCache(root)
	if err != nil {
		t.Fatal(err)
	}
	stats := reloaded.Stats()
	if stats["cached_files"] != 1 || stats["total_findings"] != 2 {
		t.Fatalf("reloaded stats = %#v, want one file and two findings", stats)
	}
	if err := os.WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertChanged(t, reloaded, path, true)
	if err := reloaded.Purge(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Stats()["cached_files"]; got != 0 {
		t.Fatalf("cached files after purge = %d, want 0", got)
	}
}

func TestFilterChangedConservativelyIncludesUnreadableFiles(t *testing.T) {
	root := t.TempDir()
	changedPath := filepath.Join(root, "changed.go")
	unchangedPath := filepath.Join(root, "unchanged.go")
	missingPath := filepath.Join(root, "missing.go")
	for _, path := range []string{changedPath, unchangedPath} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cache, err := NewFileCache(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.MarkScanned(unchangedPath, 0); err != nil {
		t.Fatal(err)
	}

	got, err := cache.FilterChanged([]string{unchangedPath, changedPath, missingPath})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{changedPath, missingPath}
	if len(got) != len(want) {
		t.Fatalf("changed files = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("changed file %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFileCacheSaveAndStatsAreRaceFree(t *testing.T) {
	root := t.TempDir()
	cache, err := NewFileCache(root)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 200; i++ {
		path := filepath.Join(root, fmt.Sprintf("file-%03d.go", i))
		if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cache.MarkScanned(path, i%3); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := cache.Save(); err != nil {
				t.Errorf("Save() error: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = cache.Stats()
		}
	}()
	wg.Wait()
}

func assertChanged(t *testing.T, cache *FileCache, path string, want bool) {
	t.Helper()
	got, err := cache.IsChanged(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("IsChanged(%q) = %v, want %v", path, got, want)
	}
}
