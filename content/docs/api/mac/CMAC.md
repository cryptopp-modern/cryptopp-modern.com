---
title: CMAC
description: Cipher-based Message Authentication Code API reference
weight: 2
---

**Header:** `#include <cryptopp/cmac.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.6.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

CMAC (Cipher-based Message Authentication Code) is a block cipher-based MAC defined in NIST SP 800-38B. It uses a symmetric block cipher (typically AES) to generate authentication tags, making it a good choice when you're already using AES and want to avoid adding a hash function dependency.

## Quick Example

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// Generate 128-bit key (AES::DEFAULT_KEYLENGTH = 16 bytes)
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
rng.GenerateBlock(key, key.size());

// Compute CMAC
std::string message = "Message to authenticate";
std::string mac;

CMAC<AES> cmac(key, key.size());
StringSource(message, true,
    new HashFilter(cmac,
        new HexEncoder(new StringSink(mac))
    )
);

// mac = "A1B2C3D4E5F6..." (32 hex chars = 16 bytes)
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use AES-CMAC for new applications (AES is widely available)
- Use same key size as underlying cipher (128, 192, or 256 bits for AES)
- Generate keys using `AutoSeededRandomPool`
- Use constant-time comparison for verification
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use CMAC for password hashing (use Argon2)
- Don't use weak ciphers (DES, 3DES)
- Don't expose timing information during verification
- Don't use the same key for encryption and CMAC
{{< /callout >}}

## Constructor

```cpp
// Default constructor (must call SetKey later)
CMAC();

// Constructor with key
CMAC(const byte* key, size_t keyLength);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `const byte*` | Pointer to key bytes |
| `keyLength` | `size_t` | Key length (16, 24, or 32 bytes for AES) |

## Methods

### SetKey

```cpp
void SetKey(const byte* key, size_t length);
```

Sets or changes the authentication key.

### Update

```cpp
void Update(const byte* input, size_t length);
```

Adds data to the MAC computation.

### Final

```cpp
void Final(byte* mac);
```

Computes the final MAC tag.

### TruncatedFinal

```cpp
void TruncatedFinal(byte* mac, size_t size);
```

Computes a truncated MAC tag.

### Verify

```cpp
bool Verify(const byte* mac);
```

Verifies a MAC tag in constant time.

### VerifyTruncated

```cpp
bool VerifyTruncatedDigest(const byte* mac, size_t size);
```

Verifies a truncated MAC tag.

### Restart

```cpp
void Restart();
```

Resets for new message (keeps key).

### DigestSize

```cpp
unsigned int DigestSize() const;
```

Returns MAC tag size (16 bytes for AES-CMAC).

## Complete Examples

### Example 1: Basic AES-CMAC

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 128-bit
    rng.GenerateBlock(key, key.size());

    std::string message = "The quick brown fox jumps over the lazy dog";

    // Method 1: Pipeline
    std::string mac1;
    CMAC<AES> cmac1(key, key.size());
    StringSource(message, true,
        new HashFilter(cmac1,
            new HexEncoder(new StringSink(mac1))
        )
    );

    // Method 2: Direct API
    CMAC<AES> cmac2(key, key.size());
    cmac2.Update((const byte*)message.data(), message.size());
    byte mac2[AES::BLOCKSIZE];
    cmac2.Final(mac2);

    std::cout << "AES-CMAC: " << mac1 << std::endl;

    return 0;
}
```

### Example 2: CMAC Verification

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <iostream>

bool verifyMessage(const std::string& message,
                   const byte* mac,
                   const SecByteBlock& key) {
    using namespace CryptoPP;

    CMAC<AES> cmac(key, key.size());
    cmac.Update((const byte*)message.data(), message.size());

    return cmac.Verify(mac);  // Constant-time comparison
}

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    std::string message = "Authentic message";

    // Compute MAC
    CMAC<AES> cmac(key, key.size());
    cmac.Update((const byte*)message.data(), message.size());
    byte mac[AES::BLOCKSIZE];
    cmac.Final(mac);

    // Verify MAC
    if (verifyMessage(message, mac, key)) {
        std::cout << "Message is authentic" << std::endl;
    } else {
        std::cout << "Message has been tampered with!" << std::endl;
    }

    // Tamper with message
    std::string tamperedMessage = "Tampered message";
    if (!verifyMessage(tamperedMessage, mac, key)) {
        std::cout << "Tampering detected!" << std::endl;
    }

    return 0;
}
```

### Example 3: File Authentication

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

std::string computeFileCMAC(const std::string& filename,
                             const SecByteBlock& key) {
    using namespace CryptoPP;

    CMAC<AES> cmac(key, key.size());
    std::string mac;

    FileSource(filename, true,
        new HashFilter(cmac,
            new HexEncoder(new StringSink(mac))
        )
    );

    return mac;
}

bool verifyFileCMAC(const std::string& filename,
                    const std::string& expectedMAC,
                    const SecByteBlock& key) {
    std::string computedMAC = computeFileCMAC(filename, key);
    return computedMAC == expectedMAC;
}
```

### Example 4: API Request Signing

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <sstream>

std::string signAPIRequest(const std::string& method,
                           const std::string& path,
                           const std::string& timestamp,
                           const std::string& body,
                           const SecByteBlock& apiKey) {
    using namespace CryptoPP;

    // Create canonical string
    std::ostringstream canonical;
    canonical << method << "\n"
              << path << "\n"
              << timestamp << "\n"
              << body;

    std::string signature;
    CMAC<AES> cmac(apiKey, apiKey.size());

    StringSource(canonical.str(), true,
        new HashFilter(cmac,
            new HexEncoder(new StringSink(signature))
        )
    );

    return signature;
}

// Usage:
// std::string sig = signAPIRequest("POST", "/api/v1/data", "2025-01-15T12:00:00Z", body, key);
// Set header: X-Signature: sig
```

### Example 5: 256-bit Key CMAC

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // 256-bit key for AES-256-CMAC
    SecByteBlock key(AES::MAX_KEYLENGTH);  // 32 bytes
    rng.GenerateBlock(key, key.size());

    CMAC<AES> cmac(key, key.size());

    std::string message = "High security message";
    cmac.Update((const byte*)message.data(), message.size());

    byte mac[AES::BLOCKSIZE];
    cmac.Final(mac);

    return 0;
}
```

### Example 6: Truncated CMAC

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

// Some protocols use truncated MACs (e.g., 8 bytes instead of 16)
void truncatedCMAC() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    std::string message = "Message";

    CMAC<AES> cmac(key, key.size());
    cmac.Update((const byte*)message.data(), message.size());

    // Get only 8 bytes (64 bits) of MAC
    byte truncatedMAC[8];
    cmac.TruncatedFinal(truncatedMAC, sizeof(truncatedMAC));

    // Verify truncated MAC
    cmac.Restart();
    cmac.Update((const byte*)message.data(), message.size());
    bool valid = cmac.VerifyTruncatedDigest(truncatedMAC, sizeof(truncatedMAC));
}
```

### Example 7: Incremental Update

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

void incrementalCMAC() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    CMAC<AES> cmac(key, key.size());

    // Process data in chunks
    std::string part1 = "First part of ";
    std::string part2 = "the message to ";
    std::string part3 = "authenticate";

    cmac.Update((const byte*)part1.data(), part1.size());
    cmac.Update((const byte*)part2.data(), part2.size());
    cmac.Update((const byte*)part3.data(), part3.size());

    byte mac[AES::BLOCKSIZE];
    cmac.Final(mac);

    // Same result as hashing the full message at once
}
```

## CMAC vs HMAC

| Feature | CMAC | HMAC |
|---------|------|------|
| **Based on** | Block cipher (AES) | Hash function (SHA) |
| **Output size** | Block size (16 bytes for AES) | Hash size (32 for SHA-256) |
| **Key size** | Cipher key size (16-32 bytes) | Any length |
| **Speed (with AES-NI)** | Very fast | Fast |
| **Speed (without AES-NI)** | Medium | Fast |
| **Standard** | NIST SP 800-38B | RFC 2104 |

**When to use CMAC:**
- Already using AES for encryption
- Hardware AES acceleration available
- Want to minimize dependencies
- NIST compliance required

**When to use HMAC:**
- General-purpose MAC
- Variable-length output needed
- No AES acceleration available

## Performance

### Benchmarks (approximate)

| Configuration | Speed |
|---------------|-------|
| AES-128-CMAC with AES-NI | ~2 GB/s |
| AES-256-CMAC with AES-NI | ~1.5 GB/s |
| AES-128-CMAC (software) | ~200 MB/s |

### Hardware Detection

```cpp
#include <cryptopp/aes.h>
#include <iostream>

void checkHardwareSupport() {
    using namespace CryptoPP;

    AES::Encryption aes;
    std::cout << "AES provider: " << aes.AlgorithmProvider() << std::endl;

    // Output:
    // "AES-NI" - Intel/AMD with hardware acceleration
    // "ARMv8" - ARM with Crypto Extensions
    // "C++" - Software implementation
}
```

## Security Properties

| Property | Value |
|----------|-------|
| **Security level** | Half of key size (64-128 bits) |
| **Tag size** | 128 bits (16 bytes) |
| **Forgery probability** | 2^(-tag_bits) |
| **Birthday bound** | 2^64 blocks per key |

### Security Notes

1. **Key separation:** Don't use same key for encryption and CMAC
2. **Message limit:** Recommended to rekey after 2^48 blocks
3. **Truncation:** Truncating to T bits gives ~2^(-T) forgery probability

## Thread Safety

CMAC objects are **not thread-safe**:

```cpp
// WRONG - shared across threads
CMAC<AES> sharedCMAC(key, keyLen);

// CORRECT - per-thread
void computeInThread(const std::string& message, const SecByteBlock& key) {
    CMAC<AES> cmac(key, key.size());
    cmac.Update((const byte*)message.data(), message.size());
    byte mac[AES::BLOCKSIZE];
    cmac.Final(mac);
}
```

## Error Handling

```cpp
#include <cryptopp/cmac.h>
#include <cryptopp/aes.h>

void safeCMAC(const SecByteBlock& key, const std::string& message) {
    using namespace CryptoPP;

    try {
        // Key size validation happens in SetKey
        CMAC<AES> cmac(key, key.size());

        cmac.Update((const byte*)message.data(), message.size());

        byte mac[AES::BLOCKSIZE];
        cmac.Final(mac);

    } catch (const InvalidKeyLength& e) {
        std::cerr << "Invalid key length: " << e.what() << std::endl;
        // AES requires 16, 24, or 32 byte keys
    } catch (const Exception& e) {
        std::cerr << "CMAC error: " << e.what() << std::endl;
    }
}
```

## Alternative Ciphers

While AES is most common, CMAC works with any block cipher:

```cpp
// 3DES-CMAC (legacy, not recommended for new applications)
#include <cryptopp/des.h>
CMAC<DES_EDE3> cmac3des(key, DES_EDE3::DEFAULT_KEYLENGTH);

// Camellia-CMAC
#include <cryptopp/camellia.h>
CMAC<Camellia> cmacCamellia(key, Camellia::DEFAULT_KEYLENGTH);
```

## See Also

- [HMAC](/docs/api/mac/hmac/) - Hash-based MAC (more common)
- [Poly1305](/docs/api/mac/poly1305/) - High-speed MAC
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption with built-in MAC
- [HashFilter](/docs/api/utilities/hashfilter/) - Pipeline filter for MACs
- [Security Concepts](/docs/guides/security-concepts/) - MAC best practices
