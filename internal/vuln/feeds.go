package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultOSVURL = "https://api.osv.dev"
	defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	osvBatchLimit     = 1000 // documented querybatch maximum
	maxBatchResponse  = 32 << 20
	maxVulnResponse   = 4 << 20
	maxKEVResponse    = 32 << 20
	detailConcurrency = 8
)

// osvVuln is the subset of the OSV schema used to build findings.
// https://ossf.github.io/osv-schema/
type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

// kevEntry is one CISA Known Exploited Vulnerabilities catalog record.
type kevEntry struct {
	CVEID         string `json:"cveID"`
	DateAdded     string `json:"dateAdded"`
	DueDate       string `json:"dueDate"`
	RansomwareUse string `json:"knownRansomwareCampaignUse"`
}

type feedClient struct {
	http       *http.Client
	osvURL     string
	kevURL     string
	retryDelay time.Duration
}

// queryOSV returns advisory IDs per dependency key, following pagination tokens.
func (c *feedClient) queryOSV(ctx context.Context, deps []Dependency) (map[string][]string, error) {
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version   string `json:"version"`
		PageToken string `json:"page_token,omitempty"`
	}
	ids := make(map[string][]string, len(deps))
	pending := make([]query, len(deps))
	owners := make([]string, len(deps))
	for i, dep := range deps {
		pending[i].Package.Name = dep.Name
		pending[i].Package.Ecosystem = dep.Ecosystem
		pending[i].Version = dep.Version
		owners[i] = dep.key()
	}
	for len(pending) > 0 {
		var nextQueries []query
		var nextOwners []string
		for start := 0; start < len(pending); start += osvBatchLimit {
			end := min(start+osvBatchLimit, len(pending))
			var response struct {
				Results []struct {
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulns"`
					NextPageToken string `json:"next_page_token"`
				} `json:"results"`
			}
			body, err := json.Marshal(map[string]any{"queries": pending[start:end]})
			if err != nil {
				return nil, err
			}
			if err := c.doJSON(ctx, http.MethodPost, c.osvURL+"/v1/querybatch", body, maxBatchResponse, &response); err != nil {
				return nil, fmt.Errorf("OSV querybatch: %w", err)
			}
			if len(response.Results) != end-start {
				return nil, fmt.Errorf("OSV querybatch returned %d results for %d queries", len(response.Results), end-start)
			}
			for i, result := range response.Results {
				owner := owners[start+i]
				for _, vuln := range result.Vulns {
					ids[owner] = append(ids[owner], vuln.ID)
				}
				if result.NextPageToken != "" {
					next := pending[start+i]
					next.PageToken = result.NextPageToken
					nextQueries = append(nextQueries, next)
					nextOwners = append(nextOwners, owner)
				}
			}
		}
		pending, owners = nextQueries, nextOwners
	}
	return ids, nil
}

// fetchVulns loads advisory details concurrently; failures are returned per ID.
func (c *feedClient) fetchVulns(ctx context.Context, ids []string) (map[string]osvVuln, map[string]error) {
	vulns := make(map[string]osvVuln, len(ids))
	failures := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan string)
	for range min(detailConcurrency, len(ids)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				var vuln osvVuln
				err := c.doJSON(ctx, http.MethodGet, c.osvURL+"/v1/vulns/"+url.PathEscape(id), nil, maxVulnResponse, &vuln)
				mu.Lock()
				if err != nil {
					failures[id] = err
				} else {
					vulns[id] = vuln
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()
	return vulns, failures
}

// fetchKEV loads the CISA KEV catalog keyed by CVE ID.
func (c *feedClient) fetchKEV(ctx context.Context) (map[string]kevEntry, error) {
	var catalog struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.kevURL, nil, maxKEVResponse, &catalog); err != nil {
		return nil, fmt.Errorf("CISA KEV catalog: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CISA KEV catalog is empty")
	}
	entries := make(map[string]kevEntry, len(catalog.Vulnerabilities))
	for _, entry := range catalog.Vulnerabilities {
		entries[strings.ToUpper(entry.CVEID)] = entry
	}
	return entries, nil
}

// doJSON performs a bounded request, retrying transient failures at most twice.
func (c *feedClient) doJSON(ctx context.Context, method, target string, body []byte, limit int64, out any) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(c.retryDelay * time.Duration(1<<(attempt-1)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("User-Agent", "sift (+https://github.com/KJyang-0114/sift)")
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := c.http.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
		response.Body.Close()
		switch {
		case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
			lastErr = fmt.Errorf("HTTP %d (%s)", response.StatusCode, http.StatusText(response.StatusCode))
			continue
		case response.StatusCode != http.StatusOK:
			return fmt.Errorf("HTTP %d (%s)", response.StatusCode, http.StatusText(response.StatusCode))
		case readErr != nil:
			return fmt.Errorf("read response: %w", readErr)
		case int64(len(data)) > limit:
			return fmt.Errorf("response exceeds %d bytes", limit)
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("invalid JSON response: %w", err)
		}
		return nil
	}
	return lastErr
}
