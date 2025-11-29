---
title: BLAKE3
weight: 60
description: "BLAKE3 cryptographic hash function guide. Fast, secure, and parallelisable hashing for file integrity, content addressing, and key derivation with cryptopp-modern."
---

BLAKE3 is a modern cryptographic hash function that offers exceptional performance while maintaining strong security properties. It's one of the newest additions to cryptopp-modern.

## Overview

BLAKE3 is based on the BLAKE2 hash function and Bao tree hashing mode. Key features include:

- **Fast**: Significantly faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2
- **Secure**: Based on proven cryptographic primitives
- **Parallelisable**: Takes advantage of SIMD instructions
- **General-purpose**: One algorithm for hashing, MACs, KDFs, and PRNGs
- **Simple**: Fewer parameters and modes than BLAKE2
- **SIMD Acceleration**: Runtime CPU detection with AVX2, SSE4.1, and C++ fallback

## Use Cases

BLAKE3 is ideal for:

- General-purpose hashing
- File integrity verification
- Content-addressed storage systems
- Key derivation (from high-entropy secrets, not passwords)
- Message authentication codes (MACs)

{{< callout type="warning" >}}
**Never use BLAKE3 for password hashing.** Fast hash functions allow attackers to try billions of guesses per second. Use [Argon2id](/docs/algorithms/argon2/) instead - it's deliberately slow and memory-hard.
{{< /callout >}}

## SIMD Acceleration

cryptopp-modern's BLAKE3 implementation includes SIMD-accelerated code paths with automatic runtime CPU detection:

| SIMD Level | Parallel Chunks | Minimum Buffer | Approx. Speed |
|------------|-----------------|----------------|---------------|
| AVX2 | 8 at a time | 8KB | ~2600 MiB/s |
| SSE4.1 | 4 at a time | 4KB | ~1800 MiB/s |
| C++ | 1 at a time | Any | ~800 MiB/s |

*Benchmarks on Intel Core Ultra 7 155H, Windows 11, MinGW-w64 GCC*

### Checking the Active Provider

You can verify which SIMD implementation is being used at runtime:

```cpp
#include <cryptopp/blake3.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::cout << "BLAKE3 provider: " << hash.AlgorithmProvider() << std::endl;
    // Output: "AVX2", "SSE4.1", "NEON", or "C++"
    return 0;
}
```

### Optimising for SIMD Performance

BLAKE3's speed advantage comes from its ability to process multiple 1KB chunks in parallel. To achieve maximum throughput, pass data in large buffers:

```cpp
#include <cryptopp/blake3.h>
#include <fstream>
#include <vector>

int main() {
    CryptoPP::BLAKE3 hash;
    CryptoPP::byte digest[CryptoPP::BLAKE3::DIGESTSIZE];

    // Use 64KB buffer for optimal AVX2 performance
    const size_t BUFFER_SIZE = 65536;
    std::vector<CryptoPP::byte> buffer(BUFFER_SIZE);

    std::ifstream file("largefile.bin", std::ios::binary);
    while (file.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE)) {
        hash.Update(buffer.data(), file.gcount());
    }
    if (file.gcount() > 0) {
        hash.Update(buffer.data(), file.gcount());
    }

    hash.Final(digest);
    return 0;
}
```

{{< callout type="info" >}}
**Buffer size matters for large data.** With AVX2, 8KB+ buffers enable 8-way parallel chunk processing (~2600 MiB/s). Smaller buffers still work correctly but won't achieve maximum throughput.
{{< /callout >}}

### Graceful Degradation

BLAKE3 automatically adapts to available data - no special handling required:

| Data Size | Parallelism | Typical Use Case |
|-----------|-------------|------------------|
| < 1KB | None (single chunk) | Passwords, tokens, small strings |
| 1-4KB | Limited | Small files, config data |
| 4-8KB | SSE4.1 (4-way) | Medium files |
| 8KB+ | AVX2 (8-way) | Large files, disk images |

Small data hashing works correctly and efficiently - the parallel processing is a bonus for large data, not a requirement.

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
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    // Generate a random 32-byte key
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Create keyed BLAKE3 (MAC mode) via constructor
    CryptoPP::BLAKE3 mac(key, key.size());

    std::string message = "Authenticated message";
    std::string macHex;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(mac,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(macHex))));

    std::cout << "BLAKE3 MAC: " << macHex << std::endl;

    return 0;
}
```

## Key Derivation

BLAKE3 includes a dedicated key derivation mode with context strings for domain separation:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    // Input keying material (e.g., from Argon2 output or key exchange)
    CryptoPP::SecByteBlock ikm(32);
    // In practice, this comes from your key exchange or master secret
    memset(ikm, 0x55, ikm.size());

    // Context string should be unique to your application
    std::string context = "MyApp 2025-01-01 encryption key";

    // KDF mode via context constructor
    CryptoPP::BLAKE3 kdf(context.c_str());

    // Derive a 32-byte key
    CryptoPP::SecByteBlock derivedKey(32);
    kdf.Update(ikm, ikm.size());
    kdf.TruncatedFinal(derivedKey, derivedKey.size());

    std::cout << "Derived key successfully" << std::endl;
    return 0;
}
```

{{< callout type="info" >}}
**Context strings provide domain separation.** Using different context strings ensures that keys derived for different purposes are cryptographically independent, even from the same input keying material.
{{< /callout >}}

## Extendable Output (XOF)

BLAKE3 supports extendable output, allowing you to generate any amount of output bytes:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    hash.Update((const CryptoPP::byte*)"input data", 10);

    // Get 64 bytes of output instead of the default 32
    CryptoPP::byte output[64];
    hash.TruncatedFinal(output, sizeof(output));

    std::string hexOutput;
    CryptoPP::StringSource(output, sizeof(output), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(hexOutput)));

    std::cout << "64-byte XOF output: " << hexOutput << std::endl;
    return 0;
}
```

## Performance Characteristics

BLAKE3 performance advantages:

- **SIMD Acceleration**: Automatic runtime detection of AVX2, SSE4.1, or C++ fallback
- **Parallelism**: Merkle tree structure enables parallel chunk processing
- **Small inputs**: Still fast even for small messages
- **Large files**: Excellent performance on large data with proper buffer sizes

### Benchmarks

| Algorithm | Provider | Speed (MiB/s) | vs BLAKE2b |
|-----------|----------|---------------|------------|
| BLAKE3 | AVX2 | 2599 | **3.15x faster** |
| BLAKE3 | SSE4.1 | ~1800 | 2.2x faster |
| BLAKE3 | C++ | ~800 | Similar |
| BLAKE2b | SSE4.1 | 822 | baseline |

*Benchmarks on Intel Core Ultra 7 155H, Windows 11, MinGW-w64 GCC*

## Comparison with Other Hash Functions

| Feature | BLAKE3 | SHA-256 | SHA3-256 | BLAKE2b |
|---------|--------|---------|----------|---------|
| Speed | Fastest | Medium | Slower | Fast |
| Security | 128-bit | 128-bit | 128-bit | 128-bit |
| Parallelisable | Yes (SIMD) | No | No | Limited |
| Simplicity | Excellent | Good | Good | Good |
| Standardised | No | Yes (FIPS) | Yes (FIPS) | Yes (RFC) |

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

- **Collision resistance**: ~128-bit
- **Preimage resistance**: ~128-bit
- **Second preimage resistance**: ~128-bit
- **No known practical attacks** as of 2025

BLAKE3 uses a 256-bit output, but its design targets ~128-bit security for all standard security goals, which is appropriate for most modern applications.

BLAKE3 isn't post-quantum-special; like other 256-bit hashes, generic quantum attacks (Grover's algorithm) would roughly halve its effective security. Plan for ~128-bit classical / ~64-bit quantum security.

## API Reference

```cpp
class BLAKE3 : public HashTransformation {
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = 32)

    // Standard hash mode
    BLAKE3(unsigned int digestSize = DIGESTSIZE);

    // Keyed hash mode (MAC)
    BLAKE3(const byte* key, size_t keyLength, unsigned int digestSize = DIGESTSIZE);

    // KDF mode with context string
    BLAKE3(const char* context, unsigned int digestSize = DIGESTSIZE);

    void Update(const byte *input, size_t length);
    void Final(byte *digest);
    void TruncatedFinal(byte *digest, size_t digestSize);  // XOF mode
    void Restart();

    unsigned int DigestSize() const { return DIGESTSIZE; }
    unsigned int BlockSize() const { return 64; }

    // Returns "AVX2", "SSE4.1", "NEON", or "C++"
    std::string AlgorithmProvider() const;
};
```

BLAKE3 also supports `SetKey()` and `SetKeyWithContext()` methods for MAC and KDF modes; these are equivalent to the keyed and context constructors above.

## Building with BLAKE3

BLAKE3 is included by default in cryptopp-modern 2025.11.0 and later.

### SIMD Build Options

The SIMD implementations are automatically enabled based on compiler and platform support:

| Compiler | AVX2 Flag | SSE4.1 Flag |
|----------|-----------|-------------|
| GCC/Clang | `-mavx2` | `-msse4.1` |
| MSVC | `/arch:AVX2` | Enabled by default on x64 |

For CMake builds:
```bash
cmake -DCRYPTOPP_AVX2=ON -DCRYPTOPP_SSE41=ON ..
```

For GNUmakefile builds, SIMD is auto-detected based on CPU capabilities.

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

## Test Vectors

BLAKE3 test vectors from the official specification:

| Input | Length | BLAKE3 Hash (hex) |
|-------|--------|-------------------|
| "" (empty) | 0 | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` |
| "abc" | 3 | `6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85` |

## Implementation Notes

### Parallel Processing Architecture

BLAKE3 uses a Merkle tree structure that enables parallel processing of 1KB chunks:

```
Input Data (16KB example)
├── Chunk 0 (1KB) ─┬─> Hash4_SSE41 ─┬─> CV 0
├── Chunk 1 (1KB) ─┤  (4 parallel)  ├─> CV 1
├── Chunk 2 (1KB) ─┤                ├─> CV 2
├── Chunk 3 (1KB) ─┘                └─> CV 3
├── Chunk 4 (1KB) ─┬─> Hash4_SSE41 ─┬─> CV 4
├── ...            │                │
└── Chunk 15 (1KB) ─┘               └─> CV 15
                                         │
                                         v
                                   Parent hashing
                                         │
                                         v
                                   Final digest
```

With AVX2, 8 chunks are processed simultaneously, doubling throughput compared to SSE4.1.

### Thread Safety

Each `BLAKE3` object maintains independent state. Multiple threads can safely use separate instances. A single instance should not be shared across threads without synchronisation.

### Memory Alignment

For optimal SIMD performance, input buffers aligned to 32 bytes (AVX2) or 16 bytes (SSE4.1) may provide marginal improvements, though unaligned access is fully supported.

## Further Reading

- [BLAKE3 Official Website](https://blake3.io/)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [BLAKE3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
