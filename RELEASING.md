# Releasing Tailcat in C++

Releases are created by `.github/workflows/release.yml`. The workflow is intentionally manual and only permits releases from the `main` branch.

## Release quality gate

Before starting a release:

1. `main` must be green on Linux, macOS, and Windows.
2. The version must describe the implementation honestly. While upstream feature parity and comprehensive interoperability coverage are still incomplete, use a prerelease version such as `0.1.0-alpha.1` and enable the GitHub **prerelease** flag.
3. Review the feature-status table in `README.md`. A release must not be described as a drop-in upstream replacement while required rows remain partial or missing.
4. Security-sensitive protocol, SSH, file-service, SOCKS, UDP, direct-path, and key-handling changes should have tests that exercise their failure paths, not only successful connections.

## Create a release

1. Merge all intended changes into `main`.
2. Confirm the normal `build` workflow passed for the exact `main` commit.
3. Open **Actions → release → Run workflow** in GitHub.
4. Select `main`.
5. Enter a semantic version without the `v` prefix, for example `0.1.0-alpha.1` or, once stable, `1.0.0`.
6. Enable **prerelease** when appropriate.
7. Run the workflow.

The workflow validates the branch and version, rejects an existing tag, builds and tests on Linux, macOS, and Windows, installs the release files, and verifies that `tailcat --version` reports the requested version.

If every platform succeeds, the publish job creates the `v<version>` tag at the exact `main` commit used by the workflow and publishes a GitHub Release with generated release notes.

## Release artifacts

Each release contains:

- `tailcat-<version>-linux-x86_64.tar.gz`
- `tailcat-<version>-macos-arm64.tar.gz`
- `tailcat-<version>-windows-x86_64.zip`
- `SHA256SUMS`

The version passed by the release workflow is forwarded to CMake as `TAILCAT_VERSION`, keeping the binary version and GitHub tag in sync.

## Local versioned build

```sh
cmake --preset linux -DTAILCAT_VERSION=0.1.0-alpha.1
cmake --build --preset linux
ctest --preset linux
./build/linux/tailcat --version
```

Use the matching `macos` or `windows` preset on those platforms.
