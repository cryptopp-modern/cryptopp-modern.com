---
title: BLAKE2b / BLAKE2s
description: High-speed cryptographic hash functions API reference
weight: 5
---

**Header:** `#include <cryptopp/blake2.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.6.4
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

BLAKE2 is a cryptographic hash function faster than MD5, SHA-1, SHA-2, and SHA-3, yet at least as secure as SHA-3. It comes in two variants: BLAKE2b (optimized for 64-bit platforms) and BLAKE2s (optimized for 8-32 bit platforms).

## Quick Example

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string message = "Hello, World!";
std::string hash;

// BLAKE2b (64-byte output by default)
BLAKE2b blake2b;
StringSource(message, true,
    new HashFilter(blake2b,
        new HexEncoder(new StringSink(hash))
    )
);
// hash = "A2764D133A16...EC0E5" (128 hex chars)
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use BLAKE2b on 64-bit systems for best performance
- Use BLAKE2s on 32-bit or embedded systems
- Use keyed mode for MAC functionality (replaces HMAC)
- Specify output length if you need less than default
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use for password hashing (use Argon2)
- Don't use BLAKE2s on 64-bit when speed matters (use BLAKE2b)
- Don't use variable output for security-critical length extension resistance
{{< /callout >}}

## BLAKE2b vs BLAKE2s

| Feature | BLAKE2b | BLAKE2s |
|---------|---------|---------|
| **Optimized for** | 64-bit CPUs | 8-32 bit CPUs |
| **Output size** | 1-64 bytes (default 64) | 1-32 bytes (default 32) |
| **Block size** | 128 bytes | 64 bytes |
| **Speed (64-bit)** | ~1 GB/s | ~500 MB/s |
| **Speed (32-bit)** | ~300 MB/s | ~400 MB/s |
| **Security level** | Up to 256 bits | Up to 128 bits |

## Constants

```cpp
// BLAKE2b
BLAKE2b::DIGESTSIZE      // 64 bytes (default output)
BLAKE2b::BLOCKSIZE       // 128 bytes
BLAKE2b::MIN_KEYLENGTH   // 0 bytes (unkeyed)
BLAKE2b::MAX_KEYLENGTH   // 64 bytes

// BLAKE2s
BLAKE2s::DIGESTSIZE      // 32 bytes (default output)
BLAKE2s::BLOCKSIZE       // 64 bytes
BLAKE2s::MIN_KEYLENGTH   // 0 bytes (unkeyed)
BLAKE2s::MAX_KEYLENGTH   // 32 bytes
```

## Constructors

```cpp
// Default (full output length, unkeyed)
BLAKE2b(bool treeMode = false, unsigned int digestSize = DIGESTSIZE);
BLAKE2s(bool treeMode = false, unsigned int digestSize = DIGESTSIZE);

// Keyed mode (MAC)
BLAKE2b(const byte* key, size_t keyLength, const byte* salt = nullptr,
        size_t saltLength = 0, const byte* personalization = nullptr,
        size_t personalizationLength = 0, bool treeMode = false,
        unsigned int digestSize = DIGESTSIZE);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `treeMode` | `bool` | Enable tree hashing mode |
| `digestSize` | `unsigned int` | Output length in bytes |
| `key` | `const byte*` | Key for keyed mode (MAC) |
| `keyLength` | `size_t` | Key length (0-64 for BLAKE2b, 0-32 for BLAKE2s) |
| `salt` | `const byte*` | Optional salt (16 bytes for BLAKE2b, 8 for BLAKE2s) |
| `personalization` | `const byte*` | Optional personalization string |

## Methods

### Update

```cpp
void Update(const byte* input, size_t length);
```

Adds data to the hash computation.

### Final

```cpp
void Final(byte* digest);
```

Computes the final hash value.

### TruncatedFinal

```cpp
void TruncatedFinal(byte* digest, size_t digestSize);
```

Computes a truncated hash.

### Restart

```cpp
void Restart();
```

Resets for new computation (keeps key if set).

### DigestSize

```cpp
unsigned int DigestSize() const;
```

Returns the configured output size.

## Complete Examples

### Example 1: Basic BLAKE2b Hashing

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string message = "The quick brown fox jumps over the lazy dog";

    // Method 1: Pipeline
    std::string hash1;
    BLAKE2b blake2b;
    StringSource(message, true,
        new HashFilter(blake2b,
            new HexEncoder(new StringSink(hash1))
        )
    );

    // Method 2: Direct API
    BLAKE2b hasher;
    hasher.Update((const byte*)message.data(), message.size());
    byte digest[BLAKE2b::DIGESTSIZE];
    hasher.Final(digest);

    std::cout << "BLAKE2b: " << hash1 << std::endl;

    return 0;
}
```

### Example 2: BLAKE2s for Embedded/32-bit

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string message = "Data for 32-bit system";

    std::string hash;
    BLAKE2s blake2s;
    StringSource(message, true,
        new HashFilter(blake2s,
            new HexEncoder(new StringSink(hash))
        )
    );

    std::cout << "BLAKE2s (32 bytes): " << hash << std::endl;

    return 0;
}
```

### Example 3: Custom Output Length

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string message = "Hello";

    // 32-byte output (256-bit) instead of default 64
    BLAKE2b blake2b_256(false, 32);

    std::string hash;
    StringSource(message, true,
        new HashFilter(blake2b_256,
            new HexEncoder(new StringSink(hash))
        )
    );

    std::cout << "BLAKE2b-256: " << hash << std::endl;
    // Output: 64 hex characters (32 bytes)

    return 0;
}
```

### Example 4: Keyed BLAKE2 (MAC Mode)

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate 32-byte key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    std::string message = "Message to authenticate";

    // Keyed BLAKE2b (acts as MAC)
    BLAKE2b mac(key, key.size());

    std::string tag;
    StringSource(message, true,
        new HashFilter(mac,
            new HexEncoder(new StringSink(tag))
        )
    );

    std::cout << "BLAKE2b-MAC: " << tag << std::endl;

    // Verify
    BLAKE2b verifier(key, key.size());
    verifier.Update((const byte*)message.data(), message.size());

    byte computed[BLAKE2b::DIGESTSIZE];
    verifier.Final(computed);

    // Decode expected tag
    std::string decoded;
    StringSource(tag, true,
        new HexDecoder(new StringSink(decoded))
    );

    if (memcmp(computed, decoded.data(), BLAKE2b::DIGESTSIZE) == 0) {
        std::cout << "MAC verified!" << std::endl;
    }

    return 0;
}
```

### Example 5: File Hashing

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

std::string hashFile(const std::string& filename) {
    using namespace CryptoPP;

    std::string hash;
    BLAKE2b blake2b;

    FileSource(filename, true,
        new HashFilter(blake2b,
            new HexEncoder(new StringSink(hash))
        )
    );

    return hash;
}

int main() {
    try {
        std::string hash = hashFile("document.pdf");
        std::cout << "BLAKE2b: " << hash << std::endl;
    } catch (const FileStore::OpenErr& e) {
        std::cerr << "Cannot open file: " << e.what() << std::endl;
    }
    return 0;
}
```

### Example 6: BLAKE2 with Salt and Personalization

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <cstring>

int main() {
    using namespace CryptoPP;

    // Key (optional, can be nullptr for unkeyed)
    SecByteBlock key(32);
    memset(key, 0x42, key.size());

    // Salt (16 bytes for BLAKE2b)
    byte salt[16];
    memset(salt, 0x01, sizeof(salt));

    // Personalization (16 bytes for BLAKE2b)
    byte personalization[16] = "MyApp_v1________";  // Exactly 16 bytes

    // Create BLAKE2b with all parameters
    BLAKE2b hasher(key, key.size(), salt, sizeof(salt),
                   personalization, sizeof(personalization));

    std::string message = "Application-specific hash";
    std::string hash;

    hasher.Update((const byte*)message.data(), message.size());
    byte digest[BLAKE2b::DIGESTSIZE];
    hasher.Final(digest);

    StringSource(digest, sizeof(digest), true,
        new HexEncoder(new StringSink(hash))
    );

    std::cout << "Personalized BLAKE2b: " << hash << std::endl;

    return 0;
}
```

### Example 7: Incremental Hashing

```cpp
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    BLAKE2b hasher;

    // Hash data in chunks (streaming)
    std::string chunk1 = "First part of ";
    std::string chunk2 = "the message to ";
    std::string chunk3 = "be hashed";

    hasher.Update((const byte*)chunk1.data(), chunk1.size());
    hasher.Update((const byte*)chunk2.data(), chunk2.size());
    hasher.Update((const byte*)chunk3.data(), chunk3.size());

    byte digest[BLAKE2b::DIGESTSIZE];
    hasher.Final(digest);

    std::string hash;
    StringSource(digest, sizeof(digest), true,
        new HexEncoder(new StringSink(hash))
    );

    std::cout << "BLAKE2b: " << hash << std::endl;

    // Hash again without recreating object
    hasher.Restart();
    std::string newMessage = "Different message";
    hasher.Update((const byte*)newMessage.data(), newMessage.size());
    hasher.Final(digest);

    return 0;
}
```

## BLAKE2 vs Other Hash Functions

| Feature | BLAKE2b | BLAKE3 | SHA-256 | SHA-3 |
|---------|---------|--------|---------|-------|
| **Speed** | ⚡⚡⚡⚡ | ⚡⚡⚡⚡⚡ | ⚡⚡⚡ | ⚡⚡ |
| **Output size** | 1-64 bytes | 1-∞ bytes | 32 bytes | Variable |
| **Keyed mode** | Built-in | Built-in | Via HMAC | Via KMAC |
| **Parallelism** | No | Yes | No | No |
| **Standard** | RFC 7693 | N/A | FIPS 180-4 | FIPS 202 |

## When to Use BLAKE2

### ✅ Use BLAKE2b for:

1. **General-purpose hashing on 64-bit systems**
2. **MAC without HMAC overhead** (keyed mode)
3. **File integrity verification**
4. **Content-addressable storage**
5. **When RFC 7693 compliance needed**

### ✅ Use BLAKE2s for:

1. **32-bit and embedded systems**
2. **Resource-constrained environments**
3. **When 256-bit security is sufficient**

### ❌ Don't use BLAKE2 for:

1. **Password hashing** (use Argon2)
2. **When BLAKE3 is available and parallelism helps**
3. **When FIPS compliance is required** (use SHA-2/SHA-3)

## Performance

### Benchmarks (64-bit system)

| Algorithm | Speed |
|-----------|-------|
| BLAKE2b | ~1 GB/s |
| BLAKE2s | ~500 MB/s |
| BLAKE3 | ~2-4 GB/s (parallel) |
| SHA-256 (with SHA-NI) | ~2 GB/s |
| SHA-256 (software) | ~300 MB/s |
| SHA-3 | ~400 MB/s |

### 32-bit System

| Algorithm | Speed |
|-----------|-------|
| BLAKE2s | ~400 MB/s |
| BLAKE2b | ~300 MB/s |
| SHA-256 | ~150 MB/s |

## Security Properties

| Property | BLAKE2b | BLAKE2s |
|----------|---------|---------|
| **Security level** | 256 bits | 128 bits |
| **Collision resistance** | 2^256 | 2^128 |
| **Preimage resistance** | 2^512 | 2^256 |
| **Length extension** | Resistant | Resistant |

## Thread Safety

BLAKE2 objects are **not thread-safe**:

```cpp
// WRONG - shared across threads
BLAKE2b sharedHasher;

// CORRECT - per-thread instances
void hashInThread(const std::string& data) {
    BLAKE2b hasher;
    hasher.Update((const byte*)data.data(), data.size());
    byte digest[BLAKE2b::DIGESTSIZE];
    hasher.Final(digest);
}
```

## Error Handling

```cpp
#include <cryptopp/blake2.h>
#include <iostream>

void safeHash(const SecByteBlock& key, const std::string& message) {
    using namespace CryptoPP;

    try {
        // Key length is validated
        BLAKE2b mac(key, key.size());

        mac.Update((const byte*)message.data(), message.size());

        byte digest[BLAKE2b::DIGESTSIZE];
        mac.Final(digest);

    } catch (const InvalidKeyLength& e) {
        // Key too long (max 64 bytes for BLAKE2b)
        std::cerr << "Invalid key length: " << e.what() << std::endl;
    } catch (const Exception& e) {
        std::cerr << "BLAKE2 error: " << e.what() << std::endl;
    }
}
```

## Migration from HMAC

BLAKE2's keyed mode can replace HMAC for new applications:

```cpp
// Before (HMAC-SHA256)
HMAC<SHA256> hmac(key, keyLen);
hmac.Update(message, messageLen);
hmac.Final(mac);

// After (BLAKE2b keyed)
BLAKE2b blake2(key, keyLen);
blake2.Update(message, messageLen);
blake2.Final(mac);

// Benefits:
// - Faster (no double hashing like HMAC)
// - Simpler (single primitive)
// - Same security guarantees
```

## See Also

- [BLAKE3](/docs/api/hash/blake3/) - Faster parallel hash function
- [SHA-256](/docs/api/hash/sha256/) - Standard hash function
- [SHA-3](/docs/api/hash/sha3/) - FIPS 202 hash function
- [HMAC](/docs/api/mac/hmac/) - Hash-based MAC (for SHA family)
- [HashFilter](/docs/api/utilities/hashfilter/) - Pipeline filter for hashing
