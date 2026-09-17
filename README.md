<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

# Tailcat in C++

This repository is a native C++20 rewrite of [tailscale/tailcat](https://github.com/tailscale/tailcat).
It speaks Tailcat's `tc...` address format and runs without a Go runtime, Go source tree, or Go helper process.

## What works

The native implementation currently includes:

- Tailcat CBOR/base64url address encoding and decoding
- X25519 node identities and optional WireGuard preshared keys
- DERP v2 over verified HTTPS/TLS
- MEOW/MEOWED Tailcat rendezvous
- WireGuard handshakes and encrypted transport packets
- a userspace IPv6/TCP stack based on lwIP
- default stdin/stdout pipe mode
- `ping` and `parse`
- selected-port `serve`
- local TCP `forward`, including OS-assigned local port `0`
- `ssh` through the system OpenSSH client
- `cp` through the system `scp` client
- Linux, macOS, and Windows CMake/CTest builds

The implementation is native C/C++. It does not link, execute, generate, or embed Go code.

## SSH

SSH is the highest-priority workflow in this rewrite.

### Server

The current native server exposes an SSH daemon already listening on the server machine's loopback port 22:

```sh
tailcat serve ssh
# Selected bootstrap relay region ...
# 🐈 Server listening with new address: tc...
```

`serve ssh` checks `127.0.0.1:22` before publishing the Tailcat address and fails immediately if no local SSH server is running. The SSH daemon does **not** need to be reachable from the public network; Tailcat carries the connection to it through WireGuard over DERP.

You can also expose an alternate local SSH port as a normal served port:

```sh
tailcat serve 2222
```

### Client

Connect with:

```sh
tailcat ssh tc...
tailcat ssh user@tc...
tailcat ssh tc... uname -a
tailcat ssh -p 2222 user@tc...
```

The C++ executable starts the system `ssh` client with a safe `ProxyCommand` that runs Tailcat itself as the byte-stream transport. That means normal OpenSSH features such as key authentication, `ssh-agent`, PTYs, interactive shells, remote commands, and `~/.ssh/config` continue to be handled by OpenSSH rather than by a partial custom SSH client.

Tailcat's ProxyCommand path uses unbuffered binary stdin/stdout, including binary mode on Windows, so SSH handshake and interactive packets are forwarded immediately rather than waiting for stdio buffers to fill.

File copies to an SSH/SFTP-capable server use the same tunnel:

```sh
tailcat cp ./report.pdf tc...:/tmp/report.pdf
tailcat cp -r ./directory user@tc...:/tmp/
tailcat cp -P 2222 ./report.pdf user@tc...:/tmp/
```

The remaining SSH parity item with upstream Tailcat is its **embedded** SSH/SFTP server (`serve ssh`, `no-auth-ssh`, authorized-key sources and ForceCommand). This branch currently bridges `serve ssh` to the host's existing `sshd`; it does not yet embed its own SSH daemon.

## Pipe mode

Start a server:

```sh
tailcat
# 🐈 Server listening with new address: tc...
```

Then send bytes from another machine:

```sh
echo hello | tailcat tc...
```

The raw connection is binary-safe and is also the transport used by the OpenSSH ProxyCommand.

## Serve TCP ports

Expose localhost services on selected Tailcat TCP ports:

```sh
tailcat serve 8080 8443
```

A client can connect directly:

```sh
tailcat tc... 8080
```

or make the remote service available as an ordinary local socket:

```sh
tailcat forward tc... 18080:8080
```

Use local port `0` to let the operating system choose an unused port:

```sh
tailcat forward tc... 0:8080
```

## Build

Requirements:

- CMake 3.24+
- Ninja
- a C++20 compiler
- network access during configure so pinned native dependencies can be fetched

Linux:

```sh
cmake --preset linux
cmake --build --preset linux
ctest --preset linux
```

macOS:

```sh
cmake --preset macos
cmake --build --preset macos
ctest --preset macos
```

Windows, from a Developer PowerShell:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
```

The resulting executable is under `build/<platform>/tailcat` (`tailcat.exe` on Windows).

## Native dependencies

CMake pins native dependencies for reproducibility:

- libsodium for Curve25519/NaCl primitives
- wireguard-lwip's C WireGuard implementation
- lwIP for the userspace TCP/IP stack
- libcurl for verified HTTPS/TLS transport
- nlohmann/json for DERP-map JSON

There is no Go dependency.

## Compatibility status

The core `tc...`/DERP/WireGuard/TCP path is implemented. The remaining upstream feature-parity work is direct NAT traversal, the embedded SSH/SFTP server, DNS TXT address lookup and its SSH safety probe, `recv`/`files`/`ls`, SOCKS, exit-node/UDP forwarding, reusable saved-key management, and a few convenience commands.

Until direct-path discovery is implemented, native C++ connections remain DERP-relayed. WireGuard still provides end-to-end encryption; DERP carries ciphertext.

## CI and releases

GitHub Actions builds and runs CTest on Ubuntu, macOS, and Windows. A separate manual release workflow creates native archives and checksums from `main`.

## License

BSD-3-Clause, matching upstream. See [LICENSE](LICENSE).

## Upstream

Original project: https://github.com/tailscale/tailcat
