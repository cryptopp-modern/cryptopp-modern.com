---
title: Migration from Crypto++ 8.9.0
weight: 20
description: "Step-by-step guide to migrate from Crypto++ 8.9.0 to cryptopp-modern. Drop-in compatible with calendar versioning, new algorithms, and backward compatibility maintained."
---

cryptopp-modern is designed to be a drop-in replacement for Crypto++ 8.9.0. Most existing code will work without changes, but there are a few important differences to be aware of.

## What's Changed?

### Version Numbering

The most significant change is the switch from traditional versioning to calendar versioning.

**Crypto++ 8.9.0:**
```cpp
// Old version format: MAJOR.MINOR.PATCH
// Encoded as: (MAJOR * 100) + (MINOR * 10) + PATCH
int version = CRYPTOPP_VERSION;  // 890 for version 8.9.0
int major = version / 100;        // 8
int minor = (version / 10) % 10;  // 9
int patch = version % 10;         // 0
```

**cryptopp-modern 2025.11.0:**
```cpp
// New version format: YEAR.MONTH.INCREMENT
// Encoded as: (YEAR * 10000) + (MONTH * 100) + INCREMENT
int version = CRYPTOPP_VERSION;   // 202511000 for 2025.11.0
int year = version / 10000;       // 2025
int month = (version / 100) % 100; // 11
int increment = version % 100;    // 0
```

### Why Calendar Versioning?

The upstream Crypto++ project's versioning scheme created a technical limitation:
- Version 8.9.0 encodes to `890`
- Version 8.10.0 would theoretically encode to `8100`, but the current system can't represent it
- Calendar versioning removes this limitation and provides clear release timing

### Migration Impact

If your code checks the library version, you'll need to update the parsing logic:

```cpp
// Before (Crypto++ 8.9.0)
#if CRYPTOPP_VERSION >= 890
    // Use features from 8.9.0
#endif

// After (cryptopp-modern)
#if CRYPTOPP_VERSION >= 202511000  // 2025.11.0
    // Use features from 2025.11.0
#endif

// Better approach: Check for feature availability
#ifdef CRYPTOPP_BLAKE3_H
    // BLAKE3 is available
#endif
```

## What Hasn't Changed?

### Namespace

The `CryptoPP` namespace remains unchanged:

```cpp
// Still works exactly the same
CryptoPP::SHA256 hash;
CryptoPP::AES::Encryption enc;
CryptoPP::AutoSeededRandomPool prng;
```

### Header Structure

All headers remain in the same location:

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
// All existing includes work unchanged
```

### API Compatibility

All existing Crypto++ 8.9.0 APIs work identically:

```cpp
// Encryption code from Crypto++ 8.9.0 works unchanged
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
prng.GenerateBlock(key, key.size());

CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv, iv.size());
// ... continues exactly the same
```

### Build Process

The same build commands work:

```bash
# Linux/macOS
make
make install

# Windows (MinGW)
mingw32-make.exe

# Windows (Visual Studio)
# Open cryptest.sln and build
```

## New Features

### BLAKE3 Hash Function

```cpp
#include <cryptopp/blake3.h>

CryptoPP::BLAKE3 hash;
std::string message = "Hello, cryptopp-modern!";
std::string digest;

CryptoPP::StringSource(message, true,
    new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(digest))));
```

See the [BLAKE3 documentation](../algorithms/blake3) for details.

### Argon2 Password Hashing

```cpp
#include <cryptopp/argon2.h>

CryptoPP::Argon2id argon2;
CryptoPP::SecByteBlock hash(32);

argon2.DeriveKey(
    hash, hash.size(),
    (const CryptoPP::byte*)password.data(), password.size(),
    salt, salt.size(),
    nullptr, 0, nullptr, 0,
    2,      // Time cost
    65536   // Memory cost (64 MB)
);
```

See the [Argon2 documentation](../algorithms/argon2) for details.

## Source Code Organization

The source code structure has been improved in cryptopp-modern 2025.12.0:

**Before (Crypto++ 8.9.0):**
- All 204+ source files in root directory
- Difficult to navigate
- No logical grouping

**After (cryptopp-modern 2025.12.0):**
- Files organized in `src/` subdirectories:
  - `src/core/` - Core functionality
  - `src/hash/` - Hash functions
  - `src/symmetric/` - Symmetric encryption
  - `src/pubkey/` - Public key cryptography
  - `src/kdf/` - Key derivation
  - And more...

**Impact:** None for library users. The include structure remains flat:

```cpp
// Still use flat includes
#include <cryptopp/sha.h>      // Not <cryptopp/hash/sha.h>
#include <cryptopp/aes.h>      // Not <cryptopp/symmetric/aes.h>
```

## Migration Checklist

### For All Projects

- [ ] Update version checking code (if any)
- [ ] Test build with cryptopp-modern
- [ ] Run existing test suite
- [ ] Update dependencies in build files

### Optional Enhancements

- [ ] Consider using BLAKE3 instead of older hash functions
- [ ] Upgrade password hashing to Argon2
- [ ] Review and update deprecated algorithm usage

## Step-by-Step Migration

### 1. Replace the Library

**Linux/macOS:**
```bash
# Remove old Crypto++ (if installed)
sudo make uninstall  # In Crypto++ directory

# Install cryptopp-modern
cd /tmp
wget https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.11.0/cryptopp-modern-2025.11.0.zip
unzip cryptopp-modern-2025.11.0.zip -d cryptopp-modern
cd cryptopp-modern
make -j$(nproc)
sudo make install PREFIX=/usr/local
sudo ldconfig
```

**Windows (MinGW):**
```bash
# Download and extract cryptopp-modern-2025.11.0.zip
# Build
mingw32-make.exe -j$(nproc)
```

### 2. Update Version Checks

**Before:**
```cpp
#if CRYPTOPP_VERSION >= 890
    // Feature available in 8.9.0+
#endif
```

**After:**
```cpp
// Option 1: Update version number
#if CRYPTOPP_VERSION >= 202511000
    // Feature available in cryptopp-modern 2025.11.0+
#endif

// Option 2: Feature detection (better)
#ifdef CRYPTOPP_BLAKE3_H
    // BLAKE3 available
#endif
```

### 3. Test Your Application

```bash
# Rebuild your application
make clean
make

# Run tests
./run_tests

# Verify functionality
./your_app --test
```

### 4. Update Documentation

Update your project's documentation to reflect the new library:

```markdown
## Dependencies

- cryptopp-modern 2025.11.0 or later
  (formerly Crypto++ 8.9.0)
```

## Common Migration Scenarios

### Scenario 1: Basic Usage (No Changes Needed)

```cpp
// This code works identically in both libraries
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

CryptoPP::SHA256 hash;
// ... use hash as before
```

**Action:** None required.

### Scenario 2: Version-Dependent Code

```cpp
// Before
#if CRYPTOPP_VERSION >= 890
    useNewFeature();
#else
    useOldFeature();
#endif

// After - Update version number
#if CRYPTOPP_VERSION >= 202511000
    useNewFeature();
#else
    useOldFeature();
#endif
```

**Action:** Update version constants.

### Scenario 3: Version Display

```cpp
// Before
std::cout << "Using Crypto++ " << CRYPTOPP_VERSION << std::endl;
// Output: Using Crypto++ 890

// After - Parse new format
int year = CRYPTOPP_VERSION / 10000;
int month = (CRYPTOPP_VERSION / 100) % 100;
int increment = CRYPTOPP_VERSION % 100;
std::cout << "Using cryptopp-modern " << year << "." << month << "." << increment << std::endl;
// Output: Using cryptopp-modern 2025.11.0
```

**Action:** Update version display logic.

### Scenario 4: CMake Projects

```cmake
# Before
find_package(cryptopp REQUIRED)
target_link_libraries(myapp cryptopp-static)

# After - Same, but points to cryptopp-modern
find_package(cryptopp REQUIRED)
target_link_libraries(myapp cryptopp-static)
```

**Action:** None required (library name unchanged).

## Compatibility Notes

### Binary Compatibility

cryptopp-modern maintains binary compatibility with Crypto++ 8.9.0:
- Same ABI
- Same class layouts
- Same symbol names

You can typically replace the library without recompiling (though recompiling is recommended).

### Source Compatibility

100% source compatible for all Crypto++ 8.9.0 APIs.

### Deprecated Features

cryptopp-modern maintains deprecated features from Crypto++ 8.9.0 for compatibility, but new code should avoid:

- **SHA-1**: Use SHA-256 or BLAKE3
- **MD5**: Use SHA-256 or BLAKE3
- **DES/3DES**: Use AES
- **RC4**: Use ChaCha20

## Rollback Plan

If you need to rollback to Crypto++ 8.9.0:

**Linux/macOS:**
```bash
# Uninstall cryptopp-modern
cd /path/to/cryptopp-modern
sudo make uninstall

# Reinstall Crypto++ 8.9.0
cd /path/to/cryptopp-890
sudo make install
sudo ldconfig
```

**Windows:**
Simply rebuild with the old library files.

## Getting Help

If you encounter migration issues:

1. **Check the documentation**: Review algorithm-specific pages
2. **Search existing issues**: [GitHub Issues](https://github.com/cryptopp-modern/cryptopp-modern/issues)
3. **Report problems**: Open a new issue with:
   - Code that worked in Crypto++ 8.9.0
   - Error messages from cryptopp-modern
   - Platform and compiler details

## Benefits of Migration

### Security
- Regular security updates
- Modern algorithms (BLAKE3, Argon2)
- Faster patching of vulnerabilities

### Performance
- BLAKE3: Significantly faster than SHA-2
- Continued optimizations
- Better multi-core utilization

### Maintenance
- Active development
- Regular releases
- Community support

### Future-Proofing
- Calendar versioning removes version encoding limits
- Clear upgrade path
- Long-term sustainability

## Conclusion

Migration from Crypto++ 8.9.0 to cryptopp-modern is straightforward:

1. Most code works unchanged
2. Update version parsing if needed
3. Optionally adopt new features (BLAKE3, Argon2)
4. Enjoy improved organization and active maintenance

The effort is minimal, and the benefits are substantial.
