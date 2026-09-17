<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

# Tailcat in C++

This repository is a native C++20 rewrite of [tailscale/tailcat](https://github.com/tailscale/tailcat).
The goal is to preserve Tailcat's user-facing model while removing the Go toolchain and Go source code entirely.

## Rewrite status

The repository is a C++20/CMake project with builds for Linux, macOS, and Windows. The original Go implementation and Go-specific build/release tooling have been removed.

A native **direct TCP bootstrap transport** is now implemented, so the basic netcat-style stdin/stdout path is usable while the Tailcat-compatible data plane is being ported. Running `tailcat` starts a listener on an ephemeral port and prints a `tcp://HOST:PORT` endpoint. Another C++ Tailcat process can connect to that endpoint.

**Important:** `tcp://` bootstrap mode is not encrypted and is not compatible with upstream Tailcat `tc...` addresses. Upstream Tailcat depends deeply on Tailscale's Go-only userspace WireGuard, magicsock/DERP, and userspace TCP/IP stack. This rewrite deliberately does not hide those dependencies behind a Go shared library or subprocess. The DERP/WireGuard-compatible C++ transport is still being implemented.

## Build

Requirements:

- CMake 3.24+
- Ninja
- A C++20 compiler
  - Linux: GCC or Clang
  - macOS: Apple Clang
  - Windows: MSVC or clang-cl

### Linux

```sh
cmake --preset linux
cmake --build --preset linux
ctest --preset linux
```

### macOS

```sh
cmake --preset macos
cmake --build --preset macos
ctest --preset macos
```

### Windows

From a Developer PowerShell:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
```

The resulting executable is under `build/<platform>/tailcat` (`tailcat.exe` on Windows).

## Working native TCP mode

Start the listener:

```sh
$ tailcat
# 🐈 Native TCP listener: tcp://192.168.1.20:49152
# Direct TCP bootstrap mode; upstream tc... addresses are not supported yet.
```

Then connect from a machine that can reach that host and port:

```sh
$ echo hello | tailcat tcp://192.168.1.20:49152
```

The listener prints `hello` and exits when the peer closes its sending side.

By default the listener binds to all local interfaces and asks the operating system for a free port. You can choose the bind address and/or port explicitly:

```sh
tailcat --bind=127.0.0.1 --port=9000
# or
tailcat listen --bind=0.0.0.0 --port=9000
```

IPv6 client endpoints use bracket notation, for example `tcp://[::1]:9000`.

Do not expose bootstrap mode to an untrusted network expecting Tailcat security: it is plain TCP. The eventual `tc...` transport will provide the WireGuard/DERP behavior of upstream Tailcat.

## Current CLI surface

Implemented now:

```text
tailcat [--bind=ADDR] [--port=N]
tailcat listen [--bind=ADDR] [--port=N]
tailcat tcp://HOST:PORT
```

Recognized but waiting on the native Tailcat data plane:

```text
tailcat <tc-address> [port]
tailcat serve ...
tailcat forward ...
tailcat browse ...
tailcat cp ...
tailcat recv ...
tailcat ssh ...
tailcat socks ...
tailcat ping ...
tailcat genkey ...
tailcat parse ...
```

`--help`, `--version`, and platform initialization are implemented.

## Porting plan

The remaining compatibility work is intentionally split into independent layers:

1. Tailcat address encoding/decoding and CBOR wire types.
2. Native Curve25519/WireGuard key handling.
3. DERP-over-HTTPS client and framing.
4. Discovery messages and endpoint exchange.
5. Userspace WireGuard packet transport.
6. Userspace TCP/UDP stack and stream multiplexing.
7. CLI parity: pipe over `tc...`, serve, forward, browse, ping, SOCKS, SSH, files, recv, and cp.
8. Interop tests against an upstream Go Tailcat binary until the Go reference can be removed from CI fixtures as well.

The acceptance criterion for the rewrite is interoperability with upstream Tailcat addresses and peers without linking, embedding, generating, or executing Go code in the shipped implementation.

## CI

GitHub Actions builds and runs CTest on:

- Ubuntu
- macOS
- Windows

See `.github/workflows/build.yml`.

## License

BSD-3-Clause, matching upstream. See [LICENSE](LICENSE).

## Upstream

Original project: https://github.com/tailscale/tailcat
