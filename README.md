# Aquari One Kotlin / Android SDK

Official Aquari One packages for Kotlin and Android public clients.

## Modules

- `one.aquari:aquari-core` — OAuth/OpenID Connect, Passport, public Passport, trust, transport, and structured errors.
- `one.aquari:aquari-android` — system-browser authorization, callback/session orchestration, and injectable protected-storage contracts.

## Requirements

- Android API 26+ (Android 8.0+)
- Java 17 toolchain for the Android build

## Security boundary

Android applications are public OAuth clients. Use Authorization Code with S256 PKCE and do not bundle a client secret, machine API key, or privileged issuer credential.

The Android module deliberately does not ship a plaintext token store. Production applications must provide storage backed by Android Keystore or an equivalent protected mechanism.

Aquari authenticates the person and exposes portable Passport and trust data. The consuming application decides its own local roles and permissions.

## Documentation

See `https://docs.aquari.one/sdks/kotlin` for the integration guide and API reference.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-kotlin
GitHub read-only mirror: https://github.com/AquariOne/aquari-kotlin

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
