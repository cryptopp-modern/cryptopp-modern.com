---
title: Installation
weight: 10
description: "Step-by-step installation guide for cryptopp-modern on Windows, Linux, and macOS. Build from source with CMake, GNUmakefile, Visual Studio, or nmake."
---

cryptopp-modern is distributed as source releases. Download the latest release package, build, and install on Windows, Linux, and macOS.

## Build Systems

cryptopp-modern can be built with either CMake or the provided GNUmakefile, with additional Visual Studio and nmake options on Windows. Choose the option that best fits your development environment.

| Build System | Best For |
|--------------|----------|
| **CMake** | IDE integration, presets, `find_package()` support |
| **GNUmakefile** | Traditional Make-based workflows, Linux/macOS |
| **Visual Studio** | Native Windows development with full IDE |
| **nmake** | Windows command-line builds without IDE |

---

## Building with CMake

CMake is one of the supported build systems for cryptopp-modern. It provides IDE integration, presets for common configurations, and proper `find_package()` support for consuming projects.

### Linux / macOS

```bash
# Download and extract release
cd /tmp
wget https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.11.0/cryptopp-modern-2025.11.0.zip
unzip -q cryptopp-modern-2025.11.0.zip -d cryptopp
cd cryptopp

# Configure with default preset (Release, Ninja)
cmake --preset=default

# Build
cmake --build build/default -j$(nproc)

# Run tests
./build/default/cryptest.exe v

# Install
sudo cmake --install build/default --prefix /usr/local
```

### Windows (MSVC)

```powershell
# Download and extract release, then in the extracted folder:

# Configure with MSVC preset
cmake --preset=msvc

# Build Release configuration
cmake --build build\msvc --config Release

# Run tests
.\build\msvc\Release\cryptest.exe v

# Install (run as Administrator)
cmake --install build\msvc --prefix C:\cryptopp
```

### Windows (MinGW)

```bash
# Download and extract release, then in the extracted folder:

# Configure with default preset
cmake --preset=default

# Build (use -j4 or similar if nproc is unavailable)
cmake --build build/default -j$(nproc)

# Run tests
./build/default/cryptest.exe v
```

### CMake Presets

The project includes pre-configured build presets:

| Preset | Generator | Build Type | Description |
|--------|-----------|------------|-------------|
| `default` | Ninja | Release | Default build for Linux/macOS/MinGW |
| `debug` | Ninja | Debug | Debug build with symbols |
| `msvc` | Visual Studio 17 2022 | - | Windows MSVC build |
| `msvc-release` | Visual Studio 17 2022 | Release | MSVC release build |
| `no-asm` | Ninja | Release | Pure C++ (no assembly) |

```bash
# List all available presets
cmake --list-presets
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CRYPTOPP_BUILD_TESTING` | `ON` | Build the test executable |
| `CRYPTOPP_INSTALL` | `ON` | Generate install targets |
| `CRYPTOPP_DISABLE_ASM` | `OFF` | Disable all assembly optimisations |
| `CRYPTOPP_USE_OPENMP` | `OFF` | Enable OpenMP for parallel algorithms |

```bash
# Example: Build without assembly
cmake -B build -DCRYPTOPP_DISABLE_ASM=ON
cmake --build build
```

---

## Building with GNUmakefile

The GNUmakefile provides a straightforward Make-based build for cryptopp-modern, suitable for classic command-line workflows and packaging scripts.

### Linux

```bash
# Prepare build environment
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  g++ \
  make \
  wget \
  unzip

# Download and extract
cd /tmp
wget https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.11.0/cryptopp-modern-2025.11.0.zip
unzip -q cryptopp-modern-2025.11.0.zip -d cryptopp
cd cryptopp

# Build and install
make -j$(nproc)
sudo make install PREFIX=/usr/local
sudo ldconfig

# Verify installation
./cryptest.exe v
```

### Windows (MinGW)

```bash
# Download release from:
# https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.11.0/cryptopp-modern-2025.11.0.zip

# Extract the zip file
# Open MinGW terminal and navigate to extracted folder

# Build (use -j4 or similar if nproc is unavailable)
mingw32-make.exe -j$(nproc)

# Test
./cryptest.exe v
```

### macOS

```bash
# Download and extract
cd /tmp
curl -L -O https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.11.0/cryptopp-modern-2025.11.0.zip
unzip -q cryptopp-modern-2025.11.0.zip -d cryptopp
cd cryptopp

# Build and install
make -j$(sysctl -n hw.ncpu)
sudo make install PREFIX=/usr/local

# Verify installation
./cryptest.exe v
```

---

## Building with Visual Studio

Visual Studio provides native Windows development with full IDE support, debugging, and IntelliSense.

```cmd
# Clone or download the source
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Open cryptest.sln in Visual Studio
# Build → Build Solution (Ctrl+Shift+B)
```

The solution includes projects for:
- `cryptlib` - Static library
- `cryptdll` - Dynamic library (DLL)
- `cryptest` - Test executable

---

## Building with nmake

nmake provides Windows command-line builds without requiring the full Visual Studio IDE, using the MSVC compiler toolchain.

```cmd
# Open "Developer Command Prompt for VS" or "x64 Native Tools Command Prompt"

# Clone or download the source
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Build
nmake /f cryptest.nmake

# Test
cryptest.exe v
```

---

## Building from Git Source

**Note:** For most users, we recommend using the [release packages](#downloads). Building from git is intended for developers who want to contribute or test unreleased changes.

### Linux / macOS (GNUmakefile)

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
make -j$(nproc)
sudo make install PREFIX=/usr/local
sudo ldconfig  # Linux only
```

### Linux / macOS / Windows (CMake)

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
cmake --preset=default
cmake --build build/default
```

### Windows (MinGW)

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
mingw32-make.exe -j10
```

## Prerequisites

### All Platforms
- C++11 (or newer) compatible compiler

### For CMake Builds
- CMake 3.20 or higher
- Ninja (recommended) or Make

### Linux
- GCC 4.8+ or Clang 3.4+
- GNU Make (for GNUmakefile builds)

**Install on Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build
```

**Install on Fedora/RHEL:**
```bash
sudo dnf install gcc-c++ make cmake ninja-build
```

### macOS
- Xcode Command Line Tools

```bash
xcode-select --install
brew install cmake ninja  # For CMake builds
```

### Windows

**For CMake builds:**
- [CMake](https://cmake.org/download/) 3.20 or higher
- [Ninja](https://ninja-build.org/) (recommended generator)
- Compiler: [MinGW-w64](https://www.mingw-w64.org/downloads/) or Visual Studio 2022

**For GNUmakefile builds:**
- [MinGW-w64](https://www.mingw-w64.org/downloads/)

**For Visual Studio builds:**
- Visual Studio 2022 (or 2019) with "Desktop development with C++" workload

**For nmake builds:**
- Visual Studio Build Tools (includes nmake and MSVC compiler)

## Build Configuration

### Static Library (Default)

The default `make` command produces `libcryptopp.a`, a static library:

```bash
make
```

This produces `libcryptopp.a` which can be linked statically into your applications.

### Dynamic/Shared Library

```bash
make dynamic
```

This produces `libcryptopp.so` on Linux, `libcryptopp.dylib` on macOS, or `libcryptopp.dll` on Windows.

### Debug Build

```bash
make CXXFLAGS="-g -O0"
```

### Custom C++ Standard

```bash
# Build with C++11
make CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++11"

# Build with C++17
make CXXFLAGS="-DNDEBUG -g2 -O3 -std=c++17"
```

## Custom Installation Location

```bash
# Install to custom prefix
make install PREFIX=/opt/cryptopp-modern

# Install to user directory (no sudo needed)
make install PREFIX=$HOME/.local
```

## Verify Installation

Run the validation tests:

```bash
# Quick validation
./cryptest.exe v

# Full test vectors
./cryptest.exe tv all
```

**Expected output:**
```
All tests passed!
```

## Using in Your Project

### Compiler Flags

```bash
# Compile
g++ -std=c++11 myapp.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp

# With static linking
g++ -std=c++11 myapp.cpp -I/usr/local/include -L/usr/local/lib -lcryptopp -static
```

### CMake (find_package)

If you built cryptopp-modern with CMake and installed it, you can use `find_package()`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyApp)

find_package(cryptopp-modern REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE cryptopp::cryptopp)
```

Build your project:

```bash
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/cryptopp-install
cmake --build build
```

### CMake (Manual)

If you installed with GNUmakefile or need manual configuration:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp)

set(CMAKE_CXX_STANDARD 11)

find_library(CRYPTOPP_LIB cryptopp PATHS /usr/local/lib)
include_directories(/usr/local/include)

add_executable(myapp main.cpp)
target_link_libraries(myapp ${CRYPTOPP_LIB})
```

### Makefile

```makefile
CXX = g++
CXXFLAGS = -std=c++11 -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lcryptopp

myapp: main.cpp
	$(CXX) $(CXXFLAGS) -o myapp main.cpp $(LDFLAGS)
```

## Advanced Build Options

For advanced build options including sanitisers, code coverage, SIMD feature flags, and more, see the detailed documentation in the source distribution:

- `CMAKE.md` - Full CMake build system reference
- `GNUMAKEFILE.md` - Full GNUmakefile build system reference

## Downloads

- **Latest Release:** [GitHub Releases](https://github.com/cryptopp-modern/cryptopp-modern/releases/latest)
- **All Releases:** [Release History](https://github.com/cryptopp-modern/cryptopp-modern/releases)

{{< callout type="info" >}}
The examples on this page use version `2025.11.0`. Replace with the current release version as needed.
{{< /callout >}}

## Next Steps

- [Quick Start Guide](../quick-start) - Get started with your first program
- [Beginner's Guide](../../guides/beginners-guide) - Complete tutorial for beginners
- [Security Concepts](../../guides/security-concepts) - Essential security practices
