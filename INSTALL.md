# Installing Tailcat in C++

Tailcat in C++ is a native C++20 application. The shipped executable has no Go runtime or Go helper requirement.

## Download a release

GitHub Releases provide prebuilt archives for:

- Linux x86_64
- macOS arm64
- Windows x86_64
- `SHA256SUMS` for integrity verification

Prerelease versions are used while upstream feature parity is still incomplete.

## Build requirements

- CMake 3.24+
- Ninja
- a C++20 compiler
- Git/network access during configure for pinned native dependencies

Command-specific runtime tools:

- `tailcat ssh` requires a system OpenSSH `ssh` executable.
- `tailcat cp` requires a system `scp` executable.
- `tailcat serve ssh` and `tailcat serve no-auth-ssh` use Tailcat's embedded libssh server; a host `sshd` is **not** required.

## Build from source

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

Run in a shell with CMake, Ninja, and the configured C++20 toolchain:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
cmake --install build/windows
```

The Windows build statically links the MinGW runtime used by the GitHub release build. libssh uses the pinned Mbed TLS backend on Windows.

## Versioned local build

The default version comes from the repository's `VERSION` file. It can be overridden for development:

```sh
cmake --preset linux -DTAILCAT_VERSION=0.2.0-beta.1
cmake --build --preset linux
./build/linux/tailcat --version
```

## SSH server setup

Authenticated SSH:

```sh
tailcat serve --ssh-authorized-keys="$HOME/.ssh/authorized_keys" ssh
```

Address/tunnel-auth-only SSH:

```sh
tailcat serve no-auth-ssh
```

The latter grants shell access to any peer that can establish the Tailcat session. Protect the `tc...` address and use `--allow` when possible.

## Compatibility status

The DERP/WireGuard/lwIP TCP data path is live-tested against both the C++ implementation and a pinned upstream Go Tailcat reference. Embedded SSH remote exec and Unix PTY behavior are also tested between separate runners.

Still incomplete: SFTP/`files`/`recv`/`ls`, Windows ConPTY parity, SOCKS UDP, exit-node forwarding, full application UDP forwarding, SSH DNS safety probing, and direct NAT traversal. See [README.md](README.md) for the current matrix.
