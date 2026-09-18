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

The current mobile build parses and persists this payload and creates an Ed25519 device key encrypted with an Android Keystore wrapping key. Network transport, biometric unlock, signed pending lists and decisions are not connected yet.
