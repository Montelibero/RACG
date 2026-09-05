# Linux approver development preview

This is an isolated Go module so graphics/CGO dependencies do not enter the
standalone server build. It is not yet the networked approval application.

Build here with Go 1.22.2 or later:

```sh
go build -o racg-approver .
./racg-approver --help
```

Run model and widget tests without a display using `go test -tags ci ./...`.
The native build must also be checked separately; the CI tag does not verify
window-manager integration.

The preview accepts a trusted server profile and a signed request JSON file.
Profile shape:

```json
{"server_id":"your-server","public_key":"base64-encoded-Ed25519-public-key"}
```

The profile must come from trusted SSH enrollment, not the broker or the request.
Verification authenticates the exact signed operation bytes; it does not prove
that the operation is safe, fresh or still pending. Control/formatting characters
are escaped in the display. Invalid signatures clear the preview.

No signing keys are loaded and no approvals, network connections or executions
are performed. Nothing is saved. Timed key unlocking, service connectivity,
notifications and approval actions remain unfinished.

Linux graphics build requirements: https://docs.fyne.io/started/quick/
