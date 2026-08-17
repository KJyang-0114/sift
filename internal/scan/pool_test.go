package scan

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
)

func TestWorkerPoolLimitsConcurrencyAndPreservesOrder(t *testing.T) {
	pool := NewWorkerPool(2, time.Second)
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	var active atomic.Int32
	var maximum atomic.Int32
	jobs := make([]Job, 8)
	for i := range jobs {
		name := strconv.Itoa(i)
		jobs[i] = Job{Name: name, Analyze: func() ([]static.Finding, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			return []static.Finding{{ID: name}}, nil
		}}
	}

	done := make(chan []BatchResult, 1)
	go func() { done <- pool.Run(jobs) }()
	<-started
	<-started
	close(release)
	results := <-done

	if maximum.Load() > 2 {
		t.Fatalf("observed %d concurrent jobs, want at most 2", maximum.Load())
	}
	for i, result := range results {
		want := strconv.Itoa(i)
		if result.Name != want || len(result.Findings) != 1 || result.Findings[0].ID != want {
			t.Fatalf("result %d = %#v, want job %q in input order", i, result, want)
		}
	}
}

func TestWorkerPoolStatsCountFailures(t *testing.T) {
	pool := NewWorkerPool(1, time.Second)
	pool.Run([]Job{
		{Name: "ok", Analyze: func() ([]static.Finding, error) { return nil, nil }},
		{Name: "failed", Analyze: func() ([]static.Finding, error) { return nil, errors.New("failed") }},
	})

	got := pool.Stats()
	for _, fragment := range []string{"workers=1", "jobs=2", "completed=2", "failed=1"} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("Stats() = %q, want fragment %q", got, fragment)
		}
	}
}

func TestScanWithCacheAnalyzesChangedAndUncertainFiles(t *testing.T) {
	pool := NewWorkerPool(2, time.Second)
	changed := map[string]bool{"changed.go": true, "unchanged.go": false}
	var mu sync.Mutex
	var analyzed []string
	marked := map[string]int{}

	findings, err := pool.ScanWithCache(
		[]string{"unchanged.go", "changed.go", "uncertain.go", "broken.go"},
		func(path string) ([]static.Finding, error) {
			mu.Lock()
			analyzed = append(analyzed, path)
			mu.Unlock()
			if path == "broken.go" {
				return nil, errors.New("analysis failed")
			}
			return []static.Finding{{ID: path}}, nil
		},
		func(path string) (bool, error) {
			if path == "uncertain.go" || path == "broken.go" {
				return false, errors.New("cache unavailable")
			}
			return changed[path], nil
		},
		func(path string, count int) error {
			mu.Lock()
			marked[path] = count
			mu.Unlock()
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(analyzed) != 3 {
		t.Fatalf("analyzed files = %#v, want three changed/uncertain files", analyzed)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want successful results from two files", findings)
	}
	if marked["changed.go"] != 1 || marked["uncertain.go"] != 1 {
		t.Fatalf("marked = %#v, want successful files recorded", marked)
	}
	if _, exists := marked["broken.go"]; exists {
		t.Fatalf("failed file was marked scanned: %#v", marked)
	}
}
