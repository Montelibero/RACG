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
