package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func writePackageJSON(t *testing.T, root string) {
	t.Helper()
	content := []byte(`{"dependencies":{"definitely-not-a-real-sift-package":"1.0.0"}}`)
	if err := os.WriteFile(filepath.Join(root, "package.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPackageVerifierTransportFailureIsDiagnosticNotFinding(t *testing.T) {
	root := t.TempDir()
	writePackageJSON(t, root)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("registry unavailable")
	})}
	verifier := newPackageVerifier(client)
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}

	result := verifier.Analyze(context.Background(), request)
	if len(result.Findings) != 0 {
		t.Fatalf("transport failure created findings: %#v", result.Findings)
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(result.Diagnostics))
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Kind != core.DiagnosticIntegration || diagnostic.Code != "registry.unavailable" || diagnostic.Cause == nil {
		t.Fatalf("unexpected diagnostic: %#v", diagnostic)
	}
}

func TestPackageVerifierConfirmedMissingPackageBuildsEvidenceBackedFinding(t *testing.T) {
	root := t.TempDir()
	writePackageJSON(t, root)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	verifier := newPackageVerifier(client)
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}

	result := verifier.Analyze(context.Background(), request)
	if len(result.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Source != "package-verifier" || finding.Location.Path != "package.json" {
		t.Fatalf("unexpected finding provenance/location: %#v", finding)
	}
	if finding.Confidence != core.ConfidenceHigh || len(finding.Evidence) != 1 || finding.Evidence[0].Kind != core.EvidenceDependency {
		t.Fatalf("finding lacks dependency evidence: %#v", finding)
	}
}
