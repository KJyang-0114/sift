package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestParseGoModIncludesRequireBlocksAndIgnoresOtherDirectives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.mod")
	content := `module example.com/self
go 1.25.5
require example.com/single v1.0.0
require (
 github.com/BurntSushi/toml v1.6.0
 "example.com/quoted" v1.0.0 // indirect
 example.com/single v1.0.0
)
replace (
 example.com/single => ../local
)
exclude example.com/removed v1.0.0
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com/single", "github.com/BurntSushi/toml", "example.com/quoted"}
	if got := parseGoMod(path); !reflect.DeepEqual(got, want) {
		t.Fatalf("modules=%#v want=%#v", got, want)
	}
}

func TestGoProxyUsesCaseEscaping(t *testing.T) {
	verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/github.com/!burnt!sushi/toml/@latest" {
			t.Fatalf("proxy path=%s", request.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: request}, nil
	})})
	state, err := verifier.verifyPackage(context.Background(), "go", "github.com/BurntSushi/toml")
	if state != packageExists || err != nil {
		t.Fatalf("state=%v err=%v", state, err)
	}
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
	verifier.retryDelay = 0
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

func TestRegistryHTTPFailuresNeverCreateFindings(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			root := t.TempDir()
			writePackageJSON(t, root)
			attempts := 0
			verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				attempts++
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header), Request: request}, nil
			})})
			verifier.retryDelay = 0
			request, err := core.NewScanRequest(root, []string{"."})
			if err != nil {
				t.Fatal(err)
			}
			result := verifier.Analyze(context.Background(), request)
			if len(result.Findings) != 0 || len(result.Diagnostics) != 1 || !result.HasErrors() {
				t.Fatalf("HTTP %d: %#v", status, result)
			}
			wantAttempts := 3
			if status == 401 || status == 403 {
				wantAttempts = 1
			}
			if attempts != wantAttempts {
				t.Fatalf("attempts=%d want=%d", attempts, wantAttempts)
			}
		})
	}
}

func TestRegistryResponseClassificationAcrossEcosystems(t *testing.T) {
	for _, ecosystem := range []string{"npm", "pypi", "cargo", "go"} {
		for _, status := range []int{200, 204, 404, 401, 429, 500} {
			t.Run(ecosystem+"/"+http.StatusText(status), func(t *testing.T) {
				verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"crate":{"name":"example"}}`)), Header: make(http.Header), Request: request}, nil
				})})
				verifier.retryDelay = 0
				state, err := verifier.verifyPackage(context.Background(), ecosystem, "example")
				want := packageUnknown
				if status == 200 {
					want = packageExists
				}
				if status == 404 && ecosystem != "go" {
					want = packageMissing
				}
				if state != want || (err != nil) != (want == packageUnknown) {
					t.Fatalf("state=%v want=%v err=%v", state, want, err)
				}
			})
		}
	}
}

func TestCargoInvalidSuccessBodyIsUnknown(t *testing.T) {
	for _, body := range []string{"broken", `{}`, `{"crate":{"name":"different"}}`, strings.Repeat("x", 1024*1024+1)} {
		verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
		})})
		state, err := verifier.verifyPackage(context.Background(), "cargo", "example")
		if state != packageUnknown || err == nil {
			t.Fatalf("state=%v err=%v", state, err)
		}
	}
}

func TestScopedNPMNotFoundIsUnknown(t *testing.T) {
	verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found")), Header: make(http.Header), Request: request}, nil
	})})
	state, err := verifier.verifyPackage(context.Background(), "npm", "@private/example")
	if state != packageUnknown || err == nil {
		t.Fatalf("private package state=%v err=%v", state, err)
	}
}

func TestRegistryRecoversFromTransientFailure(t *testing.T) {
	attempts := 0
	verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		status := 503
		if attempts == 2 {
			status = 200
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("fixture")), Header: make(http.Header), Request: request}, nil
	})})
	verifier.retryDelay = 0
	state, err := verifier.verifyPackage(context.Background(), "npm", "example")
	if state != packageExists || err != nil || attempts != 2 {
		t.Fatalf("state=%v err=%v attempts=%d", state, err, attempts)
	}
}

func TestRegistryHonorsLongRetryAfterWithoutSleeping(t *testing.T) {
	attempts := 0
	verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("rate limited")), Header: http.Header{"Retry-After": []string{"60"}}, Request: request}, nil
	})})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := verifier.verifyPackage(ctx, "npm", "example")
	if state != packageUnknown || err == nil || attempts != 1 || ctx.Err() != nil {
		t.Fatalf("state=%v err=%v attempts=%d ctx=%v", state, err, attempts, ctx.Err())
	}
}

func TestRegistryRetryWaitRespectsCancellation(t *testing.T) {
	attempts := 0
	verifier := newPackageVerifier(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("fixture")), Header: make(http.Header), Request: request}, nil
	})})
	verifier.retryDelay = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	state, err := verifier.verifyPackage(ctx, "npm", "example")
	if state != packageUnknown || !errors.Is(err, context.DeadlineExceeded) || attempts != 1 {
		t.Fatalf("state=%v err=%v attempts=%d", state, err, attempts)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  time.Duration
		valid bool
	}{
		{"0", 0, true}, {"2", 2 * time.Second, true}, {"9223372036854775807", 3 * time.Second, true},
		{"-1", 0, false}, {"invalid", 0, false},
		{now.Add(time.Second).Format(http.TimeFormat), time.Second, true},
		{now.Add(-time.Second).Format(http.TimeFormat), 0, true},
	} {
		got, valid := retryAfterDelay(test.value, now)
		if got != test.want || valid != test.valid {
			t.Fatalf("Retry-After %q = %v, %v", test.value, got, valid)
		}
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
