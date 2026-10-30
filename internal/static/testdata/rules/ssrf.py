# Semgrep rule tests for ssrf.yaml: run with
#   semgrep --test --config internal/static/rules/ssrf.yaml internal/static/testdata/rules/
import httpx
import requests


def fetch(user_url, session, client, settings, cache):
    # ruleid: sift.ssrf-http-request
    requests.get(user_url)
    # ruleid: sift.ssrf-http-request
    session.get(user_url)
    # ruleid: sift.ssrf-http-request
    client.get(user_url)
    # ruleid: sift.ssrf-http-request
    httpx.get(user_url)
    # ok: sift.ssrf-http-request
    settings.get("timeout")
    # ok: sift.ssrf-http-request
    cache.get(user_url)
    # ok: sift.ssrf-http-request
    client.get("https://api.example.com/health")
