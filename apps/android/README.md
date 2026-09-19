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
{"v":1,"kind":"racg.approver.setup","server_id":"...","server_public_key":"BASE64_ED25519","approver_id":"...","endpoint":"tcp://host:port"}
```

The current mobile build parses and persists this payload, creates an Ed25519 device key encrypted with an Android Keystore wrapping key, and speaks the signed sequential-JSON broker protocol. The approvals screen can fetch an authority-signed pending snapshot, verify every request, display its digest and operation, and submit verified `ALLOW_ONCE`/`DENY` receipts.

This is not release-ready. It currently supports one saved server and foreground refresh rather than an aggregate background queue. Biometric/device-credential confirmation is a UI gate; the software Ed25519 key is not yet hardware-backed or cryptographically bound to the authentication ceremony.
