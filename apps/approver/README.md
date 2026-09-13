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

Signing-key management is local. `Create encrypted key` makes an Ed25519 device
key and stores it in an age v1 passphrase-encrypted file (scrypt) with mode
0600; creation refuses to overwrite an existing file. `Unlock key` keeps the
private key only in process memory, and `Lock now` or the configured auto-lock
prevents further signatures. Go cannot guarantee that every transient copy of
key material is erased from memory.

After verifying a request, `Allow once` and `Deny` create a signed protocol
envelope in the Decision tab. The operator must copy it explicitly. Envelopes
are not sent anywhere by the current CLI and are not approvals until a service
connection delivers them to the authority, which separately checks device
enrollment, revocation, validity and pending state. The key unlock timer is
independent from decision validity and future grants.

The module now also contains a peer-reviewed protocol transport and atomic local
profile storage for the next service-connected slice. It can poll an authority
signed pending-request snapshot, verify it against the pinned server key, submit
a locally signed decision and verify the authority receipt. This transport is
not wired into the CLI/window yet, and no background connection starts by
default. The broker remains untrusted: request, receipt and snapshot signatures
are verified locally.

The current CLI still performs no network connections or executions and saves no
server profile or request. Service UI wiring, live notifications and download
delivery remain unfinished.

Linux graphics build requirements: https://docs.fyne.io/started/quick/
