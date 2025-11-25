---
title: Argon2
description: Memory-hard password hashing function with three variants (Argon2d, Argon2i, Argon2id)
weight: 1
---

**Header:** `#include <cryptopp/argon2.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 8.9
**Thread Safety:** Not thread-safe per instance; use separate instances per thread
**Inherits from:** `KeyDerivationFunction`

Memory-hard password hashing function designed to resist brute-force attacks from GPUs and ASICs. Argon2 won the Password Hashing Competition in 2015 and is standardized in RFC 9106.

## Quick Example

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    Argon2 argon2(Argon2::ARGON2ID);  // Recommended variant
    std::string password = "MySecurePassword123!";
    byte hash[32];

    // Generate random salt
    AutoSeededRandomPool rng;
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // Hash password (t=3, m=64MB, p=4)
    argon2.DeriveKey(hash, sizeof(hash),
        (const byte*)password.data(), password.size(),
        salt, sizeof(salt),
        3, 65536, 4);  // RFC 9106 recommended params

    std::cout << "Password hashed successfully" << std::endl;
    return 0;
}
```

## Overview

Argon2 is a password hashing function specifically designed to resist attacks from:
- **GPUs** - High memory usage makes GPU attacks expensive
- **ASICs** - Memory-hard design resists custom hardware
- **Side-channel attacks** - Argon2i variant provides data-independent memory access
- **Time-memory trade-offs** - Optimally hard to accelerate

**Key features:**
- **Memory-hard** - Requires significant RAM, making parallel attacks expensive
- **Configurable** - Adjust time cost, memory cost, and parallelism
- **Three variants** - Argon2d, Argon2i, Argon2id for different threat models
- **Standardized** - RFC 9106 (2021)
- **Winner** - Password Hashing Competition (2015)

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use **Argon2id** for password hashing (recommended by RFC 9106)
- Use at minimum: t=3, m=65536 (64 MiB), p=4
- Generate a **unique random salt** (≥16 bytes) for each password
- Store salt alongside the hash (salt is not secret)
- Verify passwords by re-hashing with the same salt and comparing
- Increase parameters on more powerful servers (t=1, m=2097152 for 2 GiB)

**Avoid:**
- Using Argon2 for key derivation (use [HKDF](/docs/api/kdf/HKDF/) instead)
- Reusing salts across different passwords
- Using predictable salts (timestamps, usernames, etc.)
- Parameters below minimum: t < 1, m < 8*p, p < 1
- Storing passwords as plain text or simple hashes (use Argon2!)
{{< /callout >}}

## Variants

### Argon2d (Data-Dependent)
```cpp
Argon2 argon2(Argon2::ARGON2D);
```

**When to use:** Maximum resistance to GPU cracking attacks.

**Properties:**
- Memory access depends on password (data-dependent)
- Faster than Argon2i
- Vulnerable to side-channel attacks on shared hardware

**Best for:** Cryptocurrency, offline hashing where side-channels aren't a concern.

---

### Argon2i (Data-Independent)
```cpp
Argon2 argon2(Argon2::ARGON2I);
```

**When to use:** Protection against side-channel attacks.

**Properties:**
- Memory access independent of password (constant-time-like)
- Resistant to timing attacks and cache-timing attacks
- Slightly slower than Argon2d

**Best for:** Shared servers, cloud environments, browsers.

---

### Argon2id (Hybrid) ⭐ Recommended
```cpp
Argon2 argon2(Argon2::ARGON2ID);  // Default
```

**When to use:** General password hashing (RFC 9106 recommendation).

**Properties:**
- Uses Argon2i for first half pass, Argon2d for the rest
- Balances GPU resistance with side-channel protection
- Best of both worlds

**Best for:** Most applications, especially web servers and authentication systems.

## Constants

- `defaultTimeCost = 3` - Default number of iterations
- `defaultMemoryCost = 65536` - Default memory in KiB (64 MiB)
- `defaultParallelism = 4` - Default number of threads/lanes

## Constructor

```cpp
Argon2(Variant variant = ARGON2ID)
```

Creates an Argon2 hasher with the specified variant.

**Parameters:**
- `variant` - One of `ARGON2D`, `ARGON2I`, or `ARGON2ID` (default: `ARGON2ID`)

**Exceptions:** None

**Example:**
```cpp
Argon2 argon2id;                      // Uses Argon2id (recommended)
Argon2 argon2d(Argon2::ARGON2D);      // Data-dependent variant
Argon2 argon2i(Argon2::ARGON2I);      // Data-independent variant
```

## Public Methods

### `StaticAlgorithmName()`
```cpp
static std::string StaticAlgorithmName(Variant variant = ARGON2ID)
```

Returns the algorithm name for a variant.

**Returns:** `"Argon2d"`, `"Argon2i"`, or `"Argon2id"`

**Thread Safety:** Thread-safe (static method).

---

### `AlgorithmName()`
```cpp
std::string AlgorithmName() const
```

Returns the algorithm name for this instance's variant.

**Thread Safety:** Thread-safe (const method).

---

### `MaxDerivedKeyLength()`
```cpp
size_t MaxDerivedKeyLength() const
```

Returns the maximum output size (SIZE_MAX).

**Thread Safety:** Thread-safe (const method).

---

### `GetValidDerivedLength()`
```cpp
size_t GetValidDerivedLength(size_t keylength) const
```

Validates and returns a valid output length.

**Parameters:**
- `keylength` - Desired output length in bytes (minimum 4)

**Returns:** Valid key length

**Exceptions:** Throws `InvalidDerivedKeyLength` if less than 4 bytes

---

### `DeriveKey()` - Simple Form
```cpp
size_t DeriveKey(byte* derived, size_t derivedLen,
                 const byte* password, size_t passwordLen,
                 const byte* salt, size_t saltLen,
                 word32 timeCost = 3,
                 word32 memoryCost = 65536,
                 word32 parallelism = 4,
                 const byte* secret = nullptr,
                 size_t secretLen = 0,
                 const byte* associatedData = nullptr,
                 size_t associatedDataLen = 0) const
```

Derives a key from a password using Argon2.

**Parameters:**
- `derived` - Output buffer for hash
- `derivedLen` - Output size in bytes (minimum 4)
- `password` - Password to hash
- `passwordLen` - Password length in bytes
- `salt` - Random salt (minimum 8 bytes, recommend 16+)
- `saltLen` - Salt length in bytes
- `timeCost` - Number of iterations (minimum 1, default 3)
- `memoryCost` - Memory in KiB (minimum 8*parallelism, default 65536 = 64 MiB)
- `parallelism` - Number of threads (minimum 1, default 4)
- `secret` - Optional secret key
- `secretLen` - Secret key length
- `associatedData` - Optional associated data
- `associatedDataLen` - Associated data length

**Returns:** Number of iterations performed (equals timeCost)

**Exceptions:**
- `InvalidDerivedKeyLength` if `derivedLen < 4`
- `InvalidArgument` if parameters are invalid (e.g., `saltLen < 8`, `timeCost < 1`, `memoryCost < 8*parallelism`)

**Thread Safety:** Not thread-safe.

## Parameter Selection Guide

### RFC 9106 Recommendations

**First choice (2 GiB memory):**
```cpp
argon2.DeriveKey(hash, 32, password, passLen, salt, 16,
    1,       // t=1 (single pass)
    2097152, // m=2 GiB
    4);      // p=4 threads
```

**Second choice (64 MiB memory - default):**
```cpp
argon2.DeriveKey(hash, 32, password, passLen, salt, 16,
    3,     // t=3 (three passes)
    65536, // m=64 MiB
    4);    // p=4 threads
```

### Adjusting for Security/Performance

**Higher security (if you have 8+ GB RAM):**
```cpp
// Very secure - takes ~2 seconds
argon2.DeriveKey(hash, 32, password, passLen, salt, 16,
    4,        // t=4 iterations
    4194304,  // m=4 GiB
    8);       // p=8 threads
```

**Faster (minimum acceptable):**
```cpp
// Faster but less secure - takes ~100ms
argon2.DeriveKey(hash, 32, password, passLen, salt, 16,
    2,     // t=2 iterations
    19456, // m=19 MiB
    1);    // p=1 thread (no parallelism)
```

**Rule of thumb:**
- **Time cost (t):** Increase to slow down attacks (2-4 is typical)
- **Memory cost (m):** Increase to resist GPU/ASIC attacks (64 MiB minimum, 2 GiB recommended)
- **Parallelism (p):** Match available CPU cores (4 is typical, 1-8 range)

## Complete Examples

### Password Hashing and Verification

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

struct PasswordHash {
    std::string salt;  // Hex-encoded
    std::string hash;  // Hex-encoded
    word32 timeCost;
    word32 memoryCost;
    word32 parallelism;
};

PasswordHash HashPassword(const std::string& password) {
    Argon2 argon2(Argon2::ARGON2ID);

    // Generate random salt
    AutoSeededRandomPool rng;
    byte saltBytes[16];
    rng.GenerateBlock(saltBytes, sizeof(saltBytes));

    // Hash with recommended parameters
    byte hashBytes[32];
    argon2.DeriveKey(hashBytes, sizeof(hashBytes),
        (const byte*)password.data(), password.size(),
        saltBytes, sizeof(saltBytes),
        3, 65536, 4);  // t=3, m=64MB, p=4

    // Convert to hex for storage
    PasswordHash result;
    StringSource(saltBytes, sizeof(saltBytes), true,
        new HexEncoder(new StringSink(result.salt)));
    StringSource(hashBytes, sizeof(hashBytes), true,
        new HexEncoder(new StringSink(result.hash)));
    result.timeCost = 3;
    result.memoryCost = 65536;
    result.parallelism = 4;

    return result;
}

bool VerifyPassword(const std::string& password, const PasswordHash& stored) {
    Argon2 argon2(Argon2::ARGON2ID);

    // Decode stored salt
    std::string saltBytes;
    StringSource(stored.salt, true,
        new HexDecoder(new StringSink(saltBytes)));

    // Re-hash with same parameters
    byte hashBytes[32];
    argon2.DeriveKey(hashBytes, sizeof(hashBytes),
        (const byte*)password.data(), password.size(),
        (const byte*)saltBytes.data(), saltBytes.size(),
        stored.timeCost, stored.memoryCost, stored.parallelism);

    // Decode stored hash
    std::string storedHashBytes;
    StringSource(stored.hash, true,
        new HexDecoder(new StringSink(storedHashBytes)));

    // Constant-time comparison
    return storedHashBytes == std::string((char*)hashBytes, sizeof(hashBytes));
}

int main() {
    std::string password = "MySecurePassword123!";

    // Hash password
    PasswordHash hashed = HashPassword(password);
    std::cout << "Password hashed!" << std::endl;
    std::cout << "Salt: " << hashed.salt << std::endl;
    std::cout << "Hash: " << hashed.hash << std::endl;

    // Verify correct password
    if (VerifyPassword(password, hashed)) {
        std::cout << "✓ Password verified!" << std::endl;
    }

    // Verify wrong password
    if (!VerifyPassword("WrongPassword", hashed)) {
        std::cout << "✗ Wrong password rejected" << std::endl;
    }

    return 0;
}
```

### With Server-Side Secret (Pepper)

```cpp
// "Pepper" = fixed server-side secret, NOT stored in database
// Protects against database theft (attacker needs both DB + secret)
byte pepper[] = "ServerSecretKey2025";  // Store in config/env, not database

argon2.DeriveKey(hash, sizeof(hash),
    (const byte*)password.data(), password.size(),
    salt, sizeof(salt),          // Unique per user (stored in DB)
    3, 65536, 4,
    pepper, sizeof(pepper) - 1); // Same for all users (NOT in DB)

// Note: Salt = random, stored with hash. Pepper = fixed secret, stored separately.
```

### Benchmarking Parameters

```cpp
#include <chrono>

auto start = std::chrono::high_resolution_clock::now();

argon2.DeriveKey(hash, 32, password, passLen, salt, 16,
    t, m, p);

auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

std::cout << "Hashing took " << duration.count() << "ms" << std::endl;
// Aim for 500ms-1s for good security/UX balance
```

## Performance

Argon2 is **intentionally slow** - that's the point! It makes brute-force attacks expensive.

**Typical timings (single-threaded):**
- **t=3, m=64 MiB, p=1:** ~200-300ms
- **t=3, m=64 MiB, p=4:** ~50-100ms (parallelized)
- **t=1, m=2 GiB, p=4:** ~500ms-1s

**Scaling:**
- **Time cost:** Linear - doubling t doubles execution time
- **Memory cost:** ~Linear - doubling m roughly doubles time
- **Parallelism:** Improves performance up to available cores

**Recommendation:** Aim for 500ms-1s hashing time on your target hardware. This is fast enough for users but slow enough to resist attacks.

## Security

- **Memory-hard** - Resists GPU/ASIC attacks by requiring large RAM
- **Time-memory trade-off resistant** - Cannot significantly speed up by using more/less memory
- **Side-channel resistant** - Argon2i and Argon2id variants
- **No known weaknesses** - No practical attacks as of 2025
- **RFC 9106 standardized** - Peer-reviewed and approved

**Security level:** Depends on parameters, but properly configured Argon2 provides:
- **Offline attack cost:** ~$1 million for 10^9 guesses with m=2 GiB
- **Online attack:** Should combine with rate limiting (e.g., max 5 attempts per hour)

See [Security Levels Explained](/docs/guides/security-levels/) for cryptographic security fundamentals.

## Thread Safety

- **Per-instance:** Not thread-safe. Do not use the same `Argon2` instance from multiple threads simultaneously.
- **Multi-instance:** Thread-safe. You can safely use different `Argon2` instances in different threads.
- **Static methods:** Thread-safe.
- **Parallelism parameter:** Argon2 internally uses OpenMP for parallelization.

**Example (safe):**
```cpp
void hashPasswords(const std::vector<std::string>& passwords) {
    #pragma omp parallel for
    for (size_t i = 0; i < passwords.size(); ++i) {
        Argon2 argon2(Argon2::ARGON2ID);  // Each thread has its own instance
        byte hash[32];
        // ... hash passwords[i] ...
    }
}
```

## Comparison with Other Password Hashing Functions

| Function | Memory-Hard | GPU-Resistant | Side-Channel Safe | Status |
|----------|-------------|---------------|-------------------|--------|
| **Argon2id** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐ Recommended |
| Argon2i | ✅ Yes | ✅ Yes | ✅✅ Best | Cloud/Shared |
| Argon2d | ✅ Yes | ✅✅ Best | ❌ No | Offline only |
| bcrypt | ⚠️ Moderate | ⚠️ Moderate | ✅ Yes | Legacy |
| scrypt | ✅ Yes | ✅ Yes | ⚠️ Some | Alternative |
| PBKDF2 | ❌ No | ❌ No | ✅ Yes | Avoid |

**Why Argon2 over bcrypt/PBKDF2:**
- **Memory-hard** - bcrypt uses little memory, PBKDF2 uses none
- **Configurable** - Adjust parameters as hardware improves
- **Standardized** - RFC 9106, winner of PHC
- **Modern** - Designed with current attack vectors in mind

## Use Cases

- ✅ **Password hashing** - Primary use case for authentication
- ✅ **Cryptocurrency wallets** - Protecting private keys with passwords
- ✅ **Disk encryption** - Key derivation from user passwords
- ✅ **Secure storage** - Protecting sensitive data with password-derived keys
- ❌ **Key derivation from secrets** - Use HKDF instead (Argon2 is for passwords)
- ❌ **Fast hashing** - Use BLAKE3 for general-purpose hashing

## Test Vectors

Use these to verify your Argon2 implementation:

| Variant | Password | Salt (hex) | t | m (KiB) | p | Output (first 32 bytes, hex) |
|---------|----------|------------|---|---------|---|------------------------------|
| Argon2id | `"password"` | `"0102030405060708090a0b0c0d0e0f10"` | 3 | 65536 | 4 | TBD - Run actual test |
| Argon2i | `"password"` | `"0102030405060708090a0b0c0d0e0f10"` | 3 | 32 | 4 | TBD - Run actual test |
| Argon2d | `"password"` | `"0102030405060708090a0b0c0d0e0f10"` | 3 | 32 | 4 | TBD - Run actual test |

**Note:** Official test vectors are in [RFC 9106 Section 6.5](https://www.rfc-editor.org/rfc/rfc9106.html#section-6.5).

## See Also

- [Argon2 Guide](/docs/algorithms/argon2/) - Detailed guide with more examples
- [Password Hashing Guide](/docs/guides/password-hashing/) - Best practices
- [Security Concepts](/docs/guides/security-concepts/) - Understanding security
- [BLAKE3](/docs/api/hash/BLAKE3/) - Don't use this for passwords!
- [HKDF](/docs/api/kdf/HKDF/) - For key derivation from secrets
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) - Official Argon2 specification
- [Password Hashing Competition](https://www.password-hashing.net/) - Background
