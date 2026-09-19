# RACG Approver Android

Build without Android Studio:

```sh
./build-docker.sh dist
```

Outputs a debug APK and an unsigned release APK under `dist/`.

Debug builds use the repository-local `docker/debug.keystore` so local APK
updates keep the same signature. This keystore is intentionally for debug
builds only and is not a release credential.

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

The device key is a non-exportable ECDSA P-256 signing key in Android Keystore.
It cannot be used until the user completes strong biometric or device-credential
authentication; successful unlock opens a short signing window. This build still
supports one saved server and foreground refresh rather than an aggregate
background queue.
