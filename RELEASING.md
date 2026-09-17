# Releasing

Releases are built entirely from the C++ CMake project.

1. Ensure Linux, macOS, and Windows CI are green on `main`.
2. Update the version in `CMakeLists.txt` and `CHANGELOG.md`.
3. Create and push a `v*` tag.
4. The release workflow builds and uploads one binary artifact per supported OS.

No Go toolchain or GoReleaser step is used.
