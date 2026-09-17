# Releasing Tailcat in C++

Releases are created by the GitHub Actions workflow in `.github/workflows/release.yml`.
The workflow is intentionally manual and only permits releases from the `main` branch.

## Create a release

1. Merge all intended changes into `main` and make sure the normal `build` workflow is green.
2. Open **Actions → release → Run workflow** in GitHub.
3. Select the `main` branch.
4. Enter a semantic version without the `v` prefix, such as `0.1.0` or `0.2.0-rc.1`.
5. Optionally enable **prerelease** for alpha, beta, or release-candidate builds.
6. Run the workflow.

The workflow validates that it is running from `main`, validates the version, rejects an existing tag, builds and tests on Linux, macOS, and Windows, and verifies that `tailcat --version` reports the requested version.

If every platform succeeds, the publish job creates the `v<version>` tag at the exact `main` commit used by the workflow and publishes a GitHub Release with generated release notes.

## Release artifacts

Each release contains:

- `tailcat-<version>-linux-x86_64.tar.gz`
- `tailcat-<version>-macos-arm64.tar.gz`
- `tailcat-<version>-windows-x86_64.zip`
- `SHA256SUMS`

The version passed by the release workflow is forwarded to CMake as `TAILCAT_VERSION`, so the binary version and GitHub tag stay in sync.

## Local versioned build

A version can also be injected into a local build:

```sh
cmake --preset linux -DTAILCAT_VERSION=0.1.0
cmake --build --preset linux
./build/linux/tailcat --version
```

Use the matching `macos` or `windows` preset on those platforms.
