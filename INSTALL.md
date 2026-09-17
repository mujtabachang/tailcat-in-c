# Installing Tailcat in C++

Tailcat in C++ uses CMake and a C++20 compiler. The shipped implementation has no Go toolchain or Go runtime requirement.

## Build requirements

- CMake 3.24+
- Ninja
- a C++20 compiler
- Git/network access during CMake configure so pinned native dependencies can be fetched

For the current SSH-oriented commands:

- `tailcat ssh` requires a system OpenSSH `ssh` client in `PATH`.
- `tailcat cp` requires a system OpenSSH `scp` client in `PATH`.
- `tailcat serve ssh` currently requires a local SSH daemon reachable on the host loopback SSH target; see README.md for the current SSH parity status.

## Build from source

Clone the repository and choose the preset for your platform.

### Linux

```sh
cmake --preset linux
cmake --build --preset linux
ctest --preset linux
sudo cmake --install build/linux
```

### macOS

```sh
cmake --preset macos
cmake --build --preset macos
ctest --preset macos
sudo cmake --install build/macos
```

### Windows

Run from a shell with CMake, Ninja, and a supported C++20 compiler available:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
cmake --install build/windows
```

The GitHub Actions Windows build uses the `windows` preset and runs the same CTest suite used on Linux and macOS.

## What is installed

CMake installs the `tailcat` executable (`tailcat.exe` on Windows). The data plane and protocol implementation are linked into that executable; there is no separate Go helper process or daemon to install.

## Compatibility status

The native DERP/WireGuard/lwIP TCP path is implemented and is exercised by the cross-platform test suite. The project is still completing upstream Tailcat feature parity, notably direct NAT traversal, embedded SSH/SFTP/file services, SOCKS5, exit-node behavior, and UDP. See the feature table in [README.md](README.md) before depending on an upstream command that is not yet marked complete.

For production-like use during the parity phase, prefer a prerelease build and keep the exact version available for diagnostics.
