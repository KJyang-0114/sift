package agent

import (
	"github.com/KJyang-0114/sift/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyPatchSupportedFormats(t *testing.T) {
	tests := []struct {
		name     string
		original string
		patch    string
		want     string
	}{
		{
			name:     "single hunk",
			original: "a\nunsafe\nz\n",
			patch:    "@@ -2,1 +2,1 @@\n- unsafe\n+ safe",
			want:     "a\nsafe\nz\n",
		},
		{
			name:     "multiple hunks",
			original: "one\ntwo\nthree\n",
			patch:    "@@ -1,1 +1,1 @@\n- one\n+ ONE\n@@ -3,1 +3,1 @@\n- three\n+ THREE",
			want:     "ONE\ntwo\nTHREE\n",
		},
		{
			name:     "file headers are ignored",
			original: "before\n",
			patch:    "diff --git a/app.go b/app.go\nindex 123..456 100644\n--- a/app.go\n+++ b/app.go\n@@ -1,1 +1,1 @@\n- before\n+ after",
			want:     "after\n",
		},
		{
			name:     "trailing whitespace is tolerated",
			original: "value  \nnext\n",
			patch:    "@@ -1,1 +1,1 @@\n- value\n+ safe",
			want:     "safe\nnext\n",
		},
		{
			name:     "simplified patch",
			original: "old\n",
			patch:    "- old\n+ new",
			want:     "new\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyPatch(tt.original, tt.patch)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("patched content = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyPatchRejectsInvalidOrNoOpPatch(t *testing.T) {
	tests := []struct {
		name  string
		patch string
	}{
		{name: "no changes", patch: "explanation only"},
		{name: "old content missing", patch: "@@ -1,1 +1,1 @@\n- absent\n+ replacement"},
		{name: "no-op replacement", patch: "@@ -1,1 +1,1 @@\n- original\n+ original"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const original = "original\n"
			got, err := applyPatch(original, tt.patch)
			if err == nil {
				t.Fatal("applyPatch returned nil error")
			}
			if got != original {
				t.Fatalf("content changed to %q after rejected patch", got)
			}
		})
	}
}

func TestApplyPatchIsAtomicWhenLaterHunkFails(t *testing.T) {
	const original = "one\ntwo\nthree\n"
	patch := "@@ -1,1 +1,1 @@\n- one\n+ ONE\n@@ -3,1 +3,1 @@\n- absent\n+ THREE"

	got, err := applyPatch(original, patch)
	if err == nil {
		t.Fatal("applyPatch returned nil error")
	}
	if !strings.Contains(err.Error(), "hunk 2 failed") {
		t.Fatalf("error = %q, want second-hunk diagnostic", err)
	}
	if got != original {
		t.Fatalf("content changed to %q after partial failure", got)
	}
}

func TestParseHunksSkipsMetadataAndComments(t *testing.T) {
	patch := "// file: app.go:1\n--- a/app.go\n+++ b/app.go\n@@ -1,1 +1,1 @@\n- old\n+ new"
	hunks := parseHunks(patch)
	if len(hunks) != 1 {
		t.Fatalf("hunks = %d, want 1", len(hunks))
	}
	if len(hunks[0].oldLines) != 1 || hunks[0].oldLines[0] != "old" {
		t.Fatalf("old lines = %#v, want [old]", hunks[0].oldLines)
	}
	if len(hunks[0].newLines) != 1 || hunks[0].newLines[0] != "new" {
		t.Fatalf("new lines = %#v, want [new]", hunks[0].newLines)
	}
}

func TestPatchRejectsAmbiguousAndSubstringMatches(t *testing.T) {
	for _, original := range []string{"old\nold\n", "prefix_old_suffix\n"} {
		got, err := applyPatch(original, "- old\n+ new")
		if err == nil || got != original {
			t.Fatalf("original=%q got=%q err=%v", original, got, err)
		}
	}
}

func TestApplyFixPreservesBackupAndRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.py")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixer := &Fixer{projectDir: dir}
	result := FixResult{Generated: true, Finding: core.Finding{Location: core.Location{Path: "app.py"}}, Patch: "- old\n+ new"}
	if err := fixer.ApplyFix(result); err != nil {
		t.Fatal(err)
	}
	result.Patch = "- new\n+ newer"
	if err := fixer.ApplyFix(result); err == nil {
		t.Fatal("overwrote existing backup")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new\n" {
		t.Fatalf("got %q", got)
	}
	if err := fixer.RollbackFix("app.py"); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "old\n" {
		t.Fatalf("rollback got %q", got)
	}
}
