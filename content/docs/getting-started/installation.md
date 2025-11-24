---
title: Installation
weight: 10
---

cryptopp-modern is distributed as source releases. Download the latest release package, build, and install on Windows, Linux, and macOS.

## Build from Release (Recommended)

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

# Build
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

## Advanced: Building from Git Source

**Note:** For most users, we recommend using the release packages above. Building from git is intended for developers who want to contribute or test unreleased changes.

### Linux

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
make -j$(nproc)
sudo make install PREFIX=/usr/local
sudo ldconfig
```

### Windows (MinGW)

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
mingw32-make.exe -j$(nproc)
```

### Windows (Visual Studio)

```cmd
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
# Open cryptest.sln in Visual Studio
# Build → Build Solution (Ctrl+Shift+B)
```

### Windows (Command Line nmake)

```cmd
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern
nmake /f cryptest.nmake
```

## Prerequisites

### All Platforms
- C++11 (or newer) compatible compiler

### Linux
- GCC 4.8+ or Clang 3.4+
- GNU Make

**Install on Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential
```

**Install on Fedora/RHEL:**
```bash
sudo dnf install gcc-c++ make
```

### macOS
- Xcode Command Line Tools

```bash
xcode-select --install
```

### Windows

**Option 1: MinGW (Recommended for static builds)**
- [MinGW-w64](https://www.mingw-w64.org/downloads/)

**Option 2: Visual Studio**
- Visual Studio 2010 or later
- C++ Desktop Development workload

**Option 3: MSVC Command Line**
- Visual Studio Build Tools
- nmake

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

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp)

set(CMAKE_CXX_STANDARD 11)

# Find cryptopp
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

## Downloads

- **Latest Release:** [cryptopp-modern-2025.11.0](https://github.com/cryptopp-modern/cryptopp-modern/releases/latest)
- **All Releases:** [Release History](https://github.com/cryptopp-modern/cryptopp-modern/releases)

## Next Steps

- [Quick Start Guide](../quick-start) - Get started with your first program
- [Beginner's Guide](../../guides/beginners-guide) - Complete tutorial for beginners
- [Security Concepts](../../guides/security-concepts) - Essential security practices
