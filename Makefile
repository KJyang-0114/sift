.PHONY: build install fmt-check test test-race lint ci clean release release-dry-run snapshot run

BINARY := sift
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sift/

install: build
	sudo mv $(BINARY) /usr/local/bin/

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))"

lint:
	go vet ./...

ci: fmt-check lint test build

clean:
	rm -f $(BINARY)
	go clean

# Releases are published by .github/workflows/release.yml when a v* tag is pushed.
release:
	@echo "Push a v* tag to release (see .github/workflows/release.yml)." && exit 1

snapshot:
	goreleaser release --snapshot --clean

release-dry-run: snapshot

run: build
	./$(BINARY) scan .
