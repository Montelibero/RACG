# Developer Run Notes

Use this when running from source in this repository.

## Run from source

```bash
GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local go run ./cmd/racg serve -listen-addr 127.0.0.1 -port 8777
```

## Run tests

```bash
GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local go test ./... -count=1
```

## Client smoke test

Start `racg serve`, copy the pairing code from the TUI, then in another terminal:

```bash
export RACG_CLIENT_CONFIG=/tmp/racg-client.json
GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local \
  go run ./cmd/racg login --host http://127.0.0.1:8777 --pairing-code ABC123

GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local \
  go run ./cmd/racg run --no-wait -- /bin/sh -c 'while true; do date +"tick %H:%M:%S"; sleep 3; done'
```

After approving in the TUI:

```bash
GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local \
  go run ./cmd/racg request logs <request_id> --live

GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOTOOLCHAIN=local \
  go run ./cmd/racg request cancel <request_id>
```

## Release

Release builds are produced by `.github/workflows/release.yml`.

1. Update `internal/version/version.go`.
2. Commit and push `main`.
3. Create and push an annotated tag:

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

The workflow runs tests, builds Linux `amd64` and `arm64` archives, and publishes a GitHub Release with checksums. If a release tag needs to be rebuilt after a fix, move the tag intentionally and run the release workflow for that tag.
