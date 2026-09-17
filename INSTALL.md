# Installing tailcat-in-c

## Dependencies

A C++20 compiler, CMake 3.24+, Boost.Asio/Boost.JSON, OpenSSL, and libsodium are required. vcpkg manifest mode is the supported cross-platform dependency path.

## Linux

With vcpkg:

```sh
cmake --preset ninja-multi-vcpkg
cmake --build --preset ninja-multi-vcpkg --config Release
```

Or install your distribution's Boost, OpenSSL development, and libsodium development packages and use a normal CMake build.

## macOS

Install Xcode Command Line Tools, CMake, Ninja, and vcpkg, then:

```sh
cmake --preset ninja-multi-vcpkg
cmake --build --preset ninja-multi-vcpkg --config Release
```

The GitHub Actions macOS target builds for Apple Silicon (`arm64-osx`).

## Windows

Use Visual Studio 2022 Build Tools (or Visual Studio 2022), CMake, Ninja, and vcpkg from a Developer PowerShell:

```powershell
cmake --preset ninja-multi-vcpkg
cmake --build --preset ninja-multi-vcpkg --config Release
ctest --test-dir build -C Release --output-on-failure
```

The Windows CI/release target is `x64-windows`.

## Install

```sh
cmake --install build --config Release --prefix /desired/prefix
```

The executable is installed under `bin/`.
