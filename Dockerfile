# Sift with a pinned Semgrep, for any CI system:
#   docker run --rm -v "$PWD:/src" ghcr.io/kjyang-0114/sift scan . --fail-on high

FROM golang:1.26-bookworm AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/sift ./cmd/sift

FROM python:3.13-slim
COPY .github/requirements-semgrep.txt /tmp/requirements-semgrep.txt
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir -r /tmp/requirements-semgrep.txt \
 && rm /tmp/requirements-semgrep.txt \
 # Mounted repositories are owned by the host user; allow --diff to read them.
 && git config --system --add safe.directory '*' \
 && useradd --create-home --uid 10001 sift
COPY --from=build /out/sift /usr/local/bin/sift
USER sift
WORKDIR /src
ENTRYPOINT ["sift"]
CMD ["scan", "."]
