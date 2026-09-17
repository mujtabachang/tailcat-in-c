# Changelog

## 0.1.0 - C++ rewrite

- Replaced the Go codebase with a native C++20 implementation.
- Added DERP authentication and relay transport in C++.
- Added X25519 + pre-shared-key session derivation and XChaCha20-Poly1305 payload encryption.
- Added compact Tailcat CBOR address parsing/generation.
- Added stdin/stdout pipe, TCP serve, forward, browse, ping, and parse commands.
- Added CMake/vcpkg builds and CI for Linux, macOS, and Windows.
- Removed Go modules, GoReleaser, Nix/Go build tooling, and Go/WASM demo code.

See README.md for the current upstream-interoperability and feature-parity limitations.
