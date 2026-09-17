# Installing Tailcat in C++

The rewrite uses CMake and a C++20 compiler. There is no Go toolchain requirement.

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

Run from a Developer PowerShell with CMake, Ninja, and MSVC available:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
cmake --install build/windows
```

## Current status

The native C++ build is available on all three target platforms. The data-plane rewrite is still in progress, so this branch is not yet a drop-in replacement for upstream Tailcat. See README.md for the compatibility roadmap.
