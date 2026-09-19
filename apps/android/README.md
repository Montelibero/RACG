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
`ALLOW_ONCE`/`DENY` receipts.

This is not release-ready. It currently supports one saved server and foreground refresh rather than an aggregate background queue. Biometric/device-credential confirmation is a UI gate; the software Ed25519 key is not yet hardware-backed or cryptographically bound to the authentication ceremony.
