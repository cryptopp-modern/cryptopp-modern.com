---
title: BLAKE3
weight: 60
---

BLAKE3 is a modern cryptographic hash function that offers exceptional performance while maintaining strong security properties. It's one of the newest additions to cryptopp-modern.

## Overview

BLAKE3 is based on the BLAKE2 hash function and Bao tree hashing mode. Key features include:

- **Fast**: Significantly faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2
- **Secure**: Based on proven cryptographic primitives
- **Parallelizable**: Takes advantage of multi-core processors
- **General-purpose**: One algorithm for hashing, MACs, KDFs, and PRNGs
- **Simple**: Fewer parameters and modes than BLAKE2

## Use Cases

BLAKE3 is ideal for:

- General-purpose hashing
- File integrity verification
- Content-addressed storage systems
- Password hashing (though Argon2 is recommended for passwords)
- Key derivation
- Message authentication codes (MACs)

## Basic Usage

### Simple Hashing

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string message = "The quick brown fox jumps over the lazy dog";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "Message: " << message << std::endl;
    std::cout << "BLAKE3 hash: " << digest << std::endl;

    return 0;
}
```

### Hashing a File

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string digest;

    try {
        CryptoPP::FileSource("myfile.txt", true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest))));

        std::cout << "BLAKE3 hash: " << digest << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### Incremental Hashing

For large data or streaming scenarios:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string digest;

    // Update hash incrementally
    hash.Update((const CryptoPP::byte*)"First part ", 11);
    hash.Update((const CryptoPP::byte*)"Second part ", 12);
    hash.Update((const CryptoPP::byte*)"Third part", 10);

    // Finalize and get result
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);

    // Convert to hex
    std::string hexDigest;
    CryptoPP::StringSource(digest, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(hexDigest)));

    std::cout << "BLAKE3 hash: " << hexDigest << std::endl;

    return 0;
}
```

## Keyed Hashing (MAC)

BLAKE3 can be used as a message authentication code:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    // 32-byte key for BLAKE3
    CryptoPP::SecByteBlock key(32);
    // In practice, use a proper random key
    memset(key, 0x42, key.size());

    CryptoPP::BLAKE3 hash;
    hash.SetKey(key, key.size());

    std::string message = "Authenticated message";
    std::string mac;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(mac))));

    std::cout << "BLAKE3 MAC: " << mac << std::endl;

    return 0;
}
```

## Performance Characteristics

BLAKE3 performance advantages:

- **Multi-threading**: Automatically uses SIMD instructions (SSE2, SSE4.1, AVX2, AVX-512)
- **Parallelism**: Tree structure allows parallel computation
- **Small inputs**: Still fast even for small messages
- **Large files**: Excellent performance on large data

Typical performance (varies by platform):
- **Single-threaded**: 1-3 GB/s
- **Multi-threaded**: Up to 10+ GB/s on modern CPUs

## Comparison with Other Hash Functions

| Feature | BLAKE3 | SHA-256 | SHA3-256 | BLAKE2b |
|---------|--------|---------|----------|---------|
| Speed | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |
| Security | 128-bit | 128-bit | 128-bit | 128-bit |
| Parallelizable | Yes | No | No | Limited |
| Simplicity | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Standardized | No | Yes (FIPS) | Yes (FIPS) | Yes (RFC) |

## When to Use BLAKE3

**Choose BLAKE3 when:**
- Performance is critical
- You need a modern, fast hash function
- Parallel processing is available
- You want one algorithm for multiple purposes

**Consider alternatives when:**
- FIPS 140-2 compliance is required (use SHA-2 or SHA-3)
- Regulatory requirements mandate specific algorithms
- Maximum compatibility with legacy systems is needed

## Security Considerations

- **Collision resistance**: 128-bit security level
- **Preimage resistance**: 256-bit security level
- **Second preimage resistance**: 256-bit security level
- **No known vulnerabilities** as of 2025

BLAKE3 is designed to be secure even against quantum computers for collision resistance (though preimage resistance would be reduced to 128-bit in a post-quantum world).

## API Reference

```cpp
class BLAKE3 : public HashTransformation {
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = 32)

    BLAKE3();

    // For keyed hashing (MAC)
    void SetKey(const byte *key, size_t keyLength);

    void Update(const byte *input, size_t length);
    void Final(byte *digest);
    void Restart();

    unsigned int DigestSize() const { return DIGESTSIZE; }
    unsigned int BlockSize() const { return 64; }
};
```

## Building with BLAKE3

BLAKE3 is included by default in cryptopp-modern 2025.11.0 and later. No special build flags needed.

### Compiling Your Application

Include the header:
```cpp
#include <cryptopp/blake3.h>
```

Compile and link:
```bash
# Linux/macOS
g++ -std=c++11 myapp.cpp -o myapp -lcryptopp

# Windows (MinGW)
g++ -std=c++11 myapp.cpp -o myapp.exe -lcryptopp
```

## Further Reading

- [BLAKE3 Official Website](https://blake3.io/)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [BLAKE3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
