---
title: Argon2
weight: 50
description: "Argon2 password hashing guide (RFC 9106). Learn Argon2id, Argon2i, and Argon2d for secure password storage with resistance to GPU/ASIC attacks and proper parameter tuning."
---

Argon2 is the winner of the Password Hashing Competition (2015) and is specified in RFC 9106. It's designed specifically for secure password hashing and key derivation, with built-in resistance to GPU and ASIC attacks.

## Overview

Argon2 provides strong protection against:

- **Brute-force attacks**: Configurable memory and time costs
- **GPU/ASIC attacks**: Memory-hard algorithm makes specialized hardware less effective
- **Side-channel attacks**: Argon2id variant provides resistance to timing attacks
- **Rainbow tables**: Built-in salt support

Key features:
- **RFC 9106 compliant**: Standardized password hashing
- **Three variants**: Argon2d, Argon2i, Argon2id
- **Tunable parameters**: Adjust memory, iterations, and parallelism
- **Future-proof**: Can increase difficulty as hardware improves

## Variants

### Argon2d
- **Optimized for**: Maximum resistance to GPU/ASIC attacks
- **Use when**: You need maximum security and side-channel attacks are not a concern
- **Memory access**: Data-dependent (faster but potentially vulnerable to side-channels)

### Argon2i
- **Optimized for**: Resistance to side-channel attacks
- **Use when**: Running in environments where timing attacks are possible
- **Memory access**: Data-independent (slower but resistant to timing attacks)

### Argon2id (Recommended)
- **Optimized for**: Balance of both protections
- **Use when**: General password hashing (most common use case)
- **Memory access**: Hybrid approach (first half Argon2i, second half Argon2d)
- **Best choice**: Recommended by RFC 9106 for password hashing

## Basic Usage

### Password Hashing (Argon2id)

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

int main() {
    // Password to hash
    std::string password = "MySecurePassword123!";

    // Generate random salt
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock salt(16);
    prng.GenerateBlock(salt, salt.size());

    // Output hash
    CryptoPP::SecByteBlock hash(32);

    // Argon2id parameters
    CryptoPP::Argon2id argon2;
    argon2.DeriveKey(
        hash, hash.size(),                    // Output
        (const CryptoPP::byte*)password.data(), password.size(),  // Password
        salt, salt.size(),                    // Salt
        nullptr, 0,                           // Secret (optional)
        nullptr, 0,                           // Additional data (optional)
        2,                                    // Time cost (iterations)
        65536                                 // Memory cost (64 MB)
    );

    // Convert to hex for storage
    std::string hashHex, saltHex;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(hashHex));
    encoder.Put(hash, hash.size());
    encoder.MessageEnd();

    encoder.Attach(new CryptoPP::StringSink(saltHex));
    encoder.Put(salt, salt.size());
    encoder.MessageEnd();

    std::cout << "Salt: " << saltHex << std::endl;
    std::cout << "Hash: " << hashHex << std::endl;

    return 0;
}
```

### Password Verification

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

bool verifyPassword(const std::string& password,
                   const std::string& saltHex,
                   const std::string& expectedHashHex) {
    // Decode salt and expected hash from hex
    CryptoPP::SecByteBlock salt(16);
    CryptoPP::SecByteBlock expectedHash(32);

    CryptoPP::HexDecoder decoder;
    decoder.Attach(new CryptoPP::ArraySink(salt, salt.size()));
    decoder.Put((const CryptoPP::byte*)saltHex.data(), saltHex.size());
    decoder.MessageEnd();

    decoder.Attach(new CryptoPP::ArraySink(expectedHash, expectedHash.size()));
    decoder.Put((const CryptoPP::byte*)expectedHashHex.data(), expectedHashHex.size());
    decoder.MessageEnd();

    // Compute hash with same parameters
    CryptoPP::SecByteBlock computedHash(32);
    CryptoPP::Argon2id argon2;

    argon2.DeriveKey(
        computedHash, computedHash.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0,
        nullptr, 0,
        2,      // Same time cost
        65536   // Same memory cost
    );

    // Constant-time comparison
    return CryptoPP::VerifyBufsEqual(
        computedHash, expectedHash, 32
    );
}

int main() {
    std::string password = "MySecurePassword123!";
    std::string salt = "A1B2C3D4E5F6...";  // From storage
    std::string hash = "9F8E7D6C5B4A...";  // From storage

    if (verifyPassword(password, salt, hash)) {
        std::cout << "Password verified!" << std::endl;
    } else {
        std::cout << "Invalid password" << std::endl;
    }

    return 0;
}
```

### Using Argon2d

```cpp
#include <cryptopp/argon2.h>

int main() {
    CryptoPP::Argon2d argon2;  // Maximum GPU resistance

    // Same usage as Argon2id
    argon2.DeriveKey(/* parameters */);

    return 0;
}
```

### Using Argon2i

```cpp
#include <cryptopp/argon2.h>

int main() {
    CryptoPP::Argon2i argon2;  // Side-channel resistant

    // Same usage as Argon2id
    argon2.DeriveKey(/* parameters */);

    return 0;
}
```

## Parameter Selection

### Memory Cost (m_cost)

Controls memory usage in KB:
- **Minimum**: 8 KB (not recommended)
- **Low security**: 32 MB (32768 KB)
- **Moderate security**: 64 MB (65536 KB) - recommended minimum
- **High security**: 256 MB (262144 KB)
- **Very high security**: 1 GB (1048576 KB) or more

```cpp
argon2.DeriveKey(
    hash, hash.size(),
    password, password.size(),
    salt, salt.size(),
    nullptr, 0, nullptr, 0,
    2,          // Time cost
    65536       // Memory cost: 64 MB
);
```

### Time Cost (t_cost)

Number of iterations:
- **Minimum**: 1 (not recommended)
- **Low security**: 2 iterations - recommended minimum
- **Moderate security**: 3-4 iterations
- **High security**: 5+ iterations

More iterations = slower hashing = better security

### Parallelism (lanes)

Number of parallel threads (advanced usage):
- **Default**: 1 thread
- **Multi-core**: 4-8 threads
- **Must divide memory cost evenly**

```cpp
// Advanced: using parallelism parameter
argon2.DeriveKey(
    hash, hash.size(),
    password, password.size(),
    salt, salt.size(),
    nullptr, 0, nullptr, 0,
    3,          // Time cost
    262144,     // Memory cost: 256 MB
    4           // Parallelism: 4 threads
);
```

## Recommended Configurations

### Web Applications (Moderate Security)
```cpp
// Balance between security and user experience
// Target: ~500ms on server hardware
CryptoPP::Argon2id argon2;
argon2.DeriveKey(hash, 32, password, pwd_len, salt, 16,
                 nullptr, 0, nullptr, 0,
                 2,      // 2 iterations
                 65536,  // 64 MB memory
                 1       // 1 thread
);
```

### High Security Applications
```cpp
// Stronger protection for sensitive data
// Target: 1-2 seconds
CryptoPP::Argon2id argon2;
argon2.DeriveKey(hash, 32, password, pwd_len, salt, 16,
                 nullptr, 0, nullptr, 0,
                 4,       // 4 iterations
                 262144,  // 256 MB memory
                 1        // 1 thread
);
```

### Maximum Security (Offline Storage)
```cpp
// For protecting highly sensitive offline data
// Target: 5+ seconds
CryptoPP::Argon2id argon2;
argon2.DeriveKey(hash, 32, password, pwd_len, salt, 16,
                 nullptr, 0, nullptr, 0,
                 8,        // 8 iterations
                 1048576,  // 1 GB memory
                 4         // 4 threads
);
```

## Security Best Practices

### Always Use Salt
```cpp
// GOOD: Random salt per password
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock salt(16);  // 16 bytes minimum
prng.GenerateBlock(salt, salt.size());

// BAD: Never use fixed or empty salt
// CryptoPP::SecByteBlock salt;  // NO!
```

### Store Salt with Hash
```cpp
// Store both salt and hash together
struct PasswordEntry {
    std::string saltHex;
    std::string hashHex;
    int timeCost;
    int memoryCost;
};
```

### Use Constant-Time Comparison
```cpp
// GOOD: Prevents timing attacks
bool valid = CryptoPP::VerifyBufsEqual(hash1, hash2, 32);

// BAD: Vulnerable to timing attacks
// bool valid = (memcmp(hash1, hash2, 32) == 0);  // NO!
```

### Choose Appropriate Parameters
- Benchmark on your target hardware
- Aim for at least 500ms hashing time
- Prefer higher memory cost over more iterations
- Use Argon2id unless you have specific requirements

## Comparison with Other KDFs

| Feature | Argon2id | PBKDF2 | bcrypt | scrypt |
|---------|----------|--------|--------|--------|
| RFC Standard | ✅ RFC 9106 | ✅ RFC 2898 | ❌ | ✅ RFC 7914 |
| Memory Hard | ✅ | ❌ | ❌ | ✅ |
| GPU Resistant | ✅ | ❌ | ⚠️ | ✅ |
| Side-channel Resistant | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Tunable Memory | ✅ | ❌ | ❌ | ✅ |
| Modern Design | ✅ 2015 | ❌ 2000 | ❌ 1999 | ⚠️ 2009 |

## When to Use Argon2

**Use Argon2id for:**
- User password hashing (primary use case)
- API key derivation
- Encryption key derivation from passwords
- Any new password-based system

**Use Argon2d when:**
- Maximum GPU resistance is critical
- Running in a controlled environment (no side-channel risks)
- Protecting offline data

**Use Argon2i when:**
- Side-channel attacks are a serious concern
- Running in untrusted environments
- Processing untrusted input

**Don't use Argon2 for:**
- Fast hashing needs (use BLAKE3 or SHA-3)
- HMAC (use HMAC-SHA256)
- General key derivation where passwords aren't involved (use HKDF)

## API Reference

```cpp
class Argon2id {
public:
    void DeriveKey(
        byte* derived, size_t derivedLen,        // Output hash
        const byte* password, size_t passwordLen, // Password
        const byte* salt, size_t saltLen,         // Salt (16+ bytes)
        const byte* secret, size_t secretLen,     // Optional secret
        const byte* data, size_t dataLen,         // Optional additional data
        unsigned int timeCost,                    // Iterations (2+ recommended)
        unsigned int memoryCost,                  // Memory in KB (65536+ recommended)
        unsigned int parallelism = 1              // Threads (default 1)
    ) const;
};

// Also available:
class Argon2d { /* same interface */ };
class Argon2i { /* same interface */ };
```

## Building with Argon2

Argon2 is included by default in cryptopp-modern 2025.11.0 and later.

### Compiling Your Application

Include the header:
```cpp
#include <cryptopp/argon2.h>
```

Compile and link:
```bash
# Linux/macOS
g++ -std=c++11 myapp.cpp -o myapp -lcryptopp

# Windows (MinGW)
g++ -std=c++11 myapp.cpp -o myapp.exe -lcryptopp
```

## Further Reading

- [RFC 9106: Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
- [Password Hashing Competition](https://www.password-hashing.net/)
