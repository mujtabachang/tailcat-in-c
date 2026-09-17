# Releasing Tailcat in C++

The canonical version is stored in the root [VERSION](VERSION) file. A change to `VERSION` on `main` triggers `.github/workflows/release.yml`.

Manual workflow dispatch remains available for explicitly requested builds, but normal project releases should be made by a reviewed version bump on `main`.

## Release quality gate

Before changing `VERSION`:

1. The exact current `main` commit must pass the Linux, macOS, and Windows `build` matrix.
2. Transport changes must preserve the C++↔C++ and pinned upstream Go↔C++ interoperability gate.
3. SSH changes must preserve the separate embedded-SSH interoperability gate.
4. Update the feature matrix in `README.md`; do not describe a partial feature as complete.
5. While required parity items remain, use a prerelease semantic version such as `0.2.0-beta.1`.

## Create a release

1. Merge intended changes to `main`.
2. Confirm the quality gates above.
3. Change `VERSION` to the new semantic version and commit it to `main`.
4. The release workflow validates that the tag does not already exist.
5. It configures, builds, and runs CTest on Linux x86_64, macOS arm64, and Windows x86_64.
6. It installs each executable into a clean staging directory and verifies `tailcat --version`.
7. Only after all platform jobs succeed does it create the Git tag and GitHub Release.

A hyphenated version such as `0.2.0-beta.1` is automatically marked as a prerelease when triggered by a `VERSION` push.

## Release artifacts

Each release contains:

- `tailcat-<version>-linux-x86_64.tar.gz`
- `tailcat-<version>-macos-arm64.tar.gz`
- `tailcat-<version>-windows-x86_64.zip`
- `SHA256SUMS`

The tag points to the exact `main` commit used to build those artifacts.

## Manual dispatch

Actions → **release** → **Run workflow** can still be used from `main`. Supply a semantic version without the `v` prefix and choose whether it is a prerelease. Existing tags are rejected.

## Local versioned build

The default comes from `VERSION`:

```sh
cmake --preset linux
cmake --build --preset linux
ctest --preset linux
./build/linux/tailcat --version
```

An explicit development override remains possible:

```sh
cmake --preset linux -DTAILCAT_VERSION=0.2.0-beta.1
```
