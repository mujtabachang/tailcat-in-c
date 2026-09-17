<p align="center">
  <strong>tailcat-in-c</strong><br>
  A native C++20 rewrite of Tailscale's Tailcat experiment.
</p>

# Tailcat in C++

This repository is a clean C++20 rewrite of [`tailscale/tailcat`](https://github.com/tailscale/tailcat). It contains no Go source code, no Go module, and no Go toolchain requirement.

Tailcat provides an encrypted point-to-point pipe and TCP forwarding over Tailscale DERP relays without requiring a Tailscale account or root/admin privileges. The C++ implementation uses:

- Boost.Asio for portable networking
- OpenSSL for TLS to DERP relays
- libsodium for Curve25519/NaCl DERP authentication and XChaCha20-Poly1305 end-to-end payload encryption
- CMake + vcpkg for Linux, macOS, and Windows builds

## Compatibility status

The `tc...` address encoder/decoder follows Tailcat's compact CBOR fields for the server public key, pre-shared key, region ID, and embedded DERP nodes. The transport is intentionally **C++-peer-to-C++-peer** in this first rewrite: it sends Tailcat's encrypted multiplexing protocol over DERP rather than embedding Tailscale's Go `magicsock`, WireGuard engine, and gVisor netstack.

That means current C++ binaries do **not** establish data-plane sessions with upstream Go Tailcat binaries. This is the main remaining interoperability item. The rewrite is relay-first; direct UDP NAT traversal is also not implemented yet.

## Features

Implemented in native C++:

- encrypted stdin/stdout pipe
- `serve` for selected localhost TCP ports
- `serve all` for all localhost TCP ports
- `serve exit-node` for arbitrary TCP destinations
- `forward` local TCP ports through a Tailcat server
- `browse` as a local port-80 forward plus browser launch
- encrypted ping/pong diagnostics
- parsing and generating compact `tc...` addresses
- DERP map lookup from `https://tailcat.dev/derpmap.json`
- embedded DERP relay details in generated addresses
- Linux, macOS, and Windows CI builds

Not yet ported from the Go project: direct UDP path upgrade, UDP forwarding, built-in SSH/SFTP, `cp`, `ls`, SOCKS, and the browser/WASM demo.

## Build

The recommended build uses vcpkg manifest mode.

```sh
git clone https://github.com/mujtabachang/tailcat-in-c.git
cd tailcat-in-c

# Point VCPKG_ROOT at an existing vcpkg checkout.
cmake --preset ninja-multi-vcpkg
cmake --build --preset ninja-multi-vcpkg --config Release
ctest --test-dir build -C Release --output-on-failure
```

On Linux distributions where Boost, OpenSSL, and libsodium development packages are already installed, a normal CMake build also works:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

See [INSTALL.md](INSTALL.md) for platform notes.

## Usage

Start a server that pipes a client's bytes to stdout and sends its stdin back to the client:

```sh
tailcat
# Selected bootstrap relay region ...
# 🐈 Server listening with new address: tc...
```

Connect from another machine:

```sh
echo hello | tailcat tc...
```

Expose selected localhost services:

```sh
tailcat serve 8080,8443
# 🐈 Server listening with new address: tc...
```

Connect directly to one served TCP port:

```sh
tailcat tc... 8080
```

Forward remote ports to ordinary local listeners:

```sh
tailcat forward tc... 18080:8080 3306
```

Use a server as a TCP exit node:

```sh
# server
tailcat serve exit-node

# client
tailcat forward tc... 3001:172.23.52.30:3001
```

Open a browser to a server exposing local port 80:

```sh
tailcat browse tc...
```

Inspect an address or measure relay round-trip time:

```sh
tailcat parse tc...
tailcat ping tc...
```

## Security model

A generated Tailcat address contains both the server public key and a random 256-bit pre-shared key. Treat the complete address as a secret capability. A peer derives a per-pair key from X25519 plus the pre-shared key and encrypts each application packet with XChaCha20-Poly1305 before it is sent through DERP.

DERP sees source/destination public keys and encrypted packet sizes/timing, but not application plaintext. TLS additionally protects the client-to-DERP hop.

The implementation is new and has not received an independent cryptographic or security audit. Do not treat it as a drop-in security-equivalent replacement for upstream Tailcat's WireGuard data plane yet.

## Project layout

```text
include/tailcat/   public C++ headers
src/               implementation and CLI
tests/             native unit tests
.github/workflows/ cross-platform CI and release builds
```

## License and attribution

This fork retains the upstream BSD-3-Clause license. Tailcat is originally a Tailscale project; this rewrite is not an official Tailscale product.
