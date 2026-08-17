.PHONY: build install fmt-check test test-race lint ci clean release

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

release:
	@echo "Creating release with GoReleaser..."
	goreleaser release --clean

release-dry-run:
	goreleaser release --skip=publish --clean --snapshot

run: build
	./$(BINARY) scan .
