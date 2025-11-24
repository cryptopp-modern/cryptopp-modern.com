---
title: Hash Functions
weight: 70
---

Cryptographic hash functions are fundamental building blocks in cryptography. They produce fixed-size digests from arbitrary-length input and are designed to be one-way and collision-resistant.

## Supported Hash Functions

cryptopp-modern provides comprehensive support for both legacy and modern hash functions:

### Modern (Recommended)
- **BLAKE3** - Fastest, modern design (see [dedicated page](../blake3))
- **SHA-3** family - NIST standard (Keccak)
- **SHA-2** family - Widely deployed, FIPS approved
- **BLAKE2** - Fast, secure predecessor to BLAKE3

### Legacy (Compatibility Only)
- **SHA-1** - Deprecated, use only for compatibility
- **MD5** - Broken, use only for non-cryptographic purposes

## Quick Comparison

| Algorithm | Digest Size | Speed | Security | Use Case |
|-----------|-------------|-------|----------|----------|
| BLAKE3 | 256-bit | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | New projects (fastest) |
| SHA-256 | 256-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | General purpose, FIPS |
| SHA-512 | 512-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High security, 64-bit systems |
| SHA3-256 | 256-bit | ⭐⭐ | ⭐⭐⭐⭐⭐ | NIST standard |
| BLAKE2b | 512-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High performance |
| SHA-1 | 160-bit | ⭐⭐⭐⭐ | ⭐ | Legacy only |

## SHA-256

SHA-256 is part of the SHA-2 family and is the most widely used cryptographic hash function today.

### Basic SHA-256 Hashing

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

int main() {
    CryptoPP::SHA256 hash;
    std::string message = "Hello, World!";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "SHA-256: " << digest << std::endl;
    return 0;
}
```

### Incremental SHA-256 Hashing

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::SHA256 hash;

    // Update hash incrementally
    hash.Update((const CryptoPP::byte*)"Part 1 ", 7);
    hash.Update((const CryptoPP::byte*)"Part 2 ", 7);
    hash.Update((const CryptoPP::byte*)"Part 3", 6);

    // Finalize
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.Final(digest);

    // Convert to hex
    std::string output;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    std::cout << "SHA-256: " << output << std::endl;
    return 0;
}
```

### File Hashing with SHA-256

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::SHA256 hash;
    std::string digest;

    try {
        CryptoPP::FileSource("document.pdf", true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest))));

        std::cout << "File SHA-256: " << digest << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## SHA-512

SHA-512 produces a 512-bit digest and is particularly efficient on 64-bit systems.

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::SHA512 hash;
    std::string message = "SHA-512 example";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "SHA-512: " << digest << std::endl;
    return 0;
}
```

## SHA-3 (Keccak)

SHA-3 is the latest NIST hash standard, based on the Keccak algorithm. It uses a different construction than SHA-2.

### SHA3-256

```cpp
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::SHA3_256 hash;
    std::string message = "SHA-3 example";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "SHA3-256: " << digest << std::endl;
    return 0;
}
```

### SHA3-512

```cpp
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::SHA3_512 hash;
    std::string message = "SHA3-512 provides 512-bit output";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "SHA3-512: " << digest << std::endl;
    return 0;
}
```

### Available SHA-3 Variants

```cpp
CryptoPP::SHA3_224 hash224;  // 224-bit output
CryptoPP::SHA3_256 hash256;  // 256-bit output
CryptoPP::SHA3_384 hash384;  // 384-bit output
CryptoPP::SHA3_512 hash512;  // 512-bit output
```

## BLAKE2

BLAKE2 comes in two variants: BLAKE2b (optimized for 64-bit) and BLAKE2s (optimized for 32-bit).

### BLAKE2b

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE2b hash;
    std::string message = "BLAKE2b is fast and secure";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "BLAKE2b: " << digest << std::endl;
    return 0;
}
```

### BLAKE2s

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE2s hash;
    std::string message = "BLAKE2s is optimized for 32-bit";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "BLAKE2s: " << digest << std::endl;
    return 0;
}
```

### BLAKE2 with Custom Digest Size

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    // BLAKE2b with 256-bit output (instead of default 512-bit)
    CryptoPP::BLAKE2b hash(false, 32);  // 32 bytes = 256 bits
    std::string message = "Custom digest size";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "BLAKE2b-256: " << digest << std::endl;
    return 0;
}
```

## Comparing Hash Outputs

### Constant-Time Comparison

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

bool verifyHash(const CryptoPP::byte* hash1,
                const CryptoPP::byte* hash2,
                size_t size) {
    // Constant-time comparison prevents timing attacks
    return CryptoPP::VerifyBufsEqual(hash1, hash2, size);
}

int main() {
    CryptoPP::byte hash1[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::byte hash2[CryptoPP::SHA256::DIGESTSIZE];

    // ... compute hashes

    if (verifyHash(hash1, hash2, CryptoPP::SHA256::DIGESTSIZE)) {
        std::cout << "Hashes match" << std::endl;
    }

    return 0;
}
```

## HMAC (Hash-based Message Authentication)

HMAC uses a hash function to create authenticated messages.

### HMAC-SHA256

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    // Secret key
    CryptoPP::SecByteBlock key(32);
    memset(key, 0x42, key.size());  // In practice, use proper random key

    std::string message = "Message to authenticate";
    std::string mac, calculated;

    // Create HMAC
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(mac))));

    std::cout << "HMAC-SHA256: " << mac << std::endl;

    // Verify HMAC
    CryptoPP::HMAC<CryptoPP::SHA256> verifier(key, key.size());

    try {
        CryptoPP::StringSource(message + mac, true,
            new CryptoPP::HashVerificationFilter(verifier,
                nullptr,
                CryptoPP::HashVerificationFilter::THROW_EXCEPTION));

        std::cout << "HMAC verified successfully" << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "HMAC verification failed" << std::endl;
    }

    return 0;
}
```

### HMAC with Other Hashes

```cpp
// HMAC-SHA512
CryptoPP::HMAC<CryptoPP::SHA512> hmacSHA512(key, key.size());

// HMAC-SHA3-256
CryptoPP::HMAC<CryptoPP::SHA3_256> hmacSHA3(key, key.size());

// HMAC-BLAKE2b
CryptoPP::HMAC<CryptoPP::BLAKE2b> hmacBLAKE2(key, key.size());
```

## Hash Function Selection Guide

### Choose BLAKE3 when:
- Maximum performance is needed
- Building new systems
- See [dedicated BLAKE3 page](../blake3)

### Choose SHA-256 when:
- FIPS 140-2 compliance required
- Wide compatibility needed
- Industry standard expected
- Digital signatures

### Choose SHA-512 when:
- Working on 64-bit systems
- Need larger digest size
- High security requirements

### Choose SHA-3 when:
- Want alternative to SHA-2
- NIST standard required
- Post-quantum preparations (different construction)

### Choose BLAKE2 when:
- Need faster hashing than SHA-2
- Don't need FIPS compliance
- Building new systems (or use BLAKE3)

### Avoid SHA-1:
- Known collision attacks
- Use only for legacy compatibility

### Never use MD5 for security:
- Completely broken for cryptographic use
- OK only for checksums (non-adversarial)

## Common Use Cases

### File Integrity Verification

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>

std::string hashFile(const std::string& filename) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::FileSource(filename.c_str(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    std::string hash1 = hashFile("original.dat");
    std::string hash2 = hashFile("downloaded.dat");

    if (hash1 == hash2) {
        std::cout << "Files are identical" << std::endl;
    } else {
        std::cout << "Files differ!" << std::endl;
    }

    return 0;
}
```

### Digital Signatures (Hash and Sign)

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>

// Hash message, then sign the hash
CryptoPP::SHA256 hash;
CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];

hash.CalculateDigest(digest,
    (const CryptoPP::byte*)message.data(),
    message.size());

// Sign the digest (not shown: RSA signing code)
```

### Content-Addressed Storage

```cpp
std::string storeContent(const std::string& data) {
    // Hash content to get unique identifier
    CryptoPP::SHA256 hash;
    std::string id;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(id))));

    // Store with hash as key
    // storage[id] = data;
    return id;
}
```

## Performance Characteristics

Approximate throughput on modern x86_64 CPU (single-threaded):

| Hash Function | Speed (MB/s) | Notes |
|---------------|--------------|-------|
| BLAKE3 | 2000-3000 | Multi-core: 10+ GB/s |
| BLAKE2b | 800-1000 | 64-bit optimized |
| SHA-256 (AES-NI) | 400-600 | With hardware support |
| SHA-512 | 600-800 | Faster on 64-bit |
| SHA3-256 | 200-300 | Different construction |
| SHA-1 | 600-800 | Fast but insecure |

## Security Properties

All modern hash functions provide:

- **Pre-image resistance**: Can't find input from hash
- **Second pre-image resistance**: Can't find different input with same hash
- **Collision resistance**: Can't find two inputs with same hash

Security levels (bits):

| Algorithm | Collision | Pre-image |
|-----------|-----------|-----------|
| SHA-256 | 128-bit | 256-bit |
| SHA-512 | 256-bit | 512-bit |
| SHA3-256 | 128-bit | 256-bit |
| BLAKE3 | 128-bit | 256-bit |
| SHA-1 | ⚠️ Broken | 160-bit |

## Building

All hash functions are included by default in cryptopp-modern.

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/blake2.h>
#include <cryptopp/blake3.h>
```

Compile:
```bash
g++ -std=c++11 myapp.cpp -o myapp -lcryptopp
```

## Further Reading

- [NIST FIPS 180-4: SHA-2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [NIST FIPS 202: SHA-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [BLAKE2 Website](https://www.blake2.net/)
- [BLAKE3 Documentation](../blake3)
