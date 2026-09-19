# RACG Approver Android

Build without Android Studio:

```sh
./build-docker.sh dist
```

Outputs a debug APK under `dist/`. Without release signing it also produces an
unsigned release APK.

Debug builds use the repository-local `docker/debug.keystore` so local APK
updates keep the same signature. This keystore is intentionally for debug
builds only and is not a release credential.

For a signed release, create and keep a local release identity:

```sh
./prepare-release-key.sh
./build-docker.sh dist
```

The identity files are ignored by git and created with mode `0600`. Back them up
before relying on the release APK; without the original identity, Android will
not accept an update as the same app.

The setup QR is generated only by trusted desktop administration and contains:

```json
{"v":2,"kind":"racg.approver.setup","server_id":"...","server_public_key":"BASE64_ED25519","approver_id":"...","endpoint":"tcp://host:port","enrollment_token":"BASE64_ONE_TIME_TOKEN"}
```

Version 1 remains accepted for an already-enrolled profile. Version 2 carries a
one-time token; the phone generates an Ed25519 key, signs the enrollment with
that key, consumes the token through the broker, and verifies the authority
receipt before persisting setup. The token is not saved after enrollment.

The approvals screen fetches an authority-signed pending snapshot, verifies every
request, displays its digest and operation, and submits verified
`ALLOW_ONCE`/`DENY` receipts. Multiple setup QRs can be added; their pending
queues are polled independently and merged into one aggregate list. One server
being offline does not hide verified approvals from other servers.

The server-management screen lists configured profiles and can remove one from
the phone. Removal is explicitly local: server-side access stays active until an
administrator revokes that device.

The management screen can also create a one-time transfer QR. The new phone
scans it, generates its own approval and poll keys, enrolls them through the
authority, and verifies the transfer receipt. The old phone remains active; no
private key is included in the QR or transferred between phones.

The approval key is a non-exportable ECDSA P-256 signing key in Android
Keystore. It cannot be used until the user completes strong biometric or
device-credential authentication; successful unlock opens a short signing
window.

Android can also run a foreground watcher. It uses a separate non-exportable
poll key that authorizes signed pending-list reads only and cannot submit
decisions. The service aggregates all configured servers, posts per-request
notifications, clears notifications that are no longer pending, and opens the
app when tapped.
