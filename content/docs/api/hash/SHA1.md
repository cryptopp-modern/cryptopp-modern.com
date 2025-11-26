---
title: SHA-1
description: SHA-1 cryptographic hash function API reference (legacy/deprecated)
weight: 6
---

**Header:** `#include <cryptopp/sha.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

{{< callout type="warning" >}}
**SHA-1 is cryptographically broken and should not be used for security purposes.**

SHA-1 has known collision attacks (SHAttered, 2017) and should only be used for:
- Legacy system compatibility
- Non-security checksums
- Git commit hashes (being phased out)

**For new applications, use SHA-256, SHA-3, or BLAKE3.**
{{< /callout >}}

SHA-1 (Secure Hash Algorithm 1) is a 160-bit cryptographic hash function designed by the NSA. While once widely used, it is now considered broken for security applications due to practical collision attacks.

## Quick Example

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // WARNING: SHA-1 is deprecated for security use
    SHA1 hash;
    std::string message = "Hello, World!";
    std::string digest, hexOutput;

    StringSource(message, true,
        new HashFilter(hash,
            new StringSink(digest)
        )
    );

    StringSource(digest, true,
        new HexEncoder(new StringSink(hexOutput))
    );

    std::cout << "SHA-1: " << hexOutput << std::endl;
    // Output: 0A0A9F2A6772942557AB5355D76AF442F8F65E01

    return 0;
}
```

## When SHA-1 Is Still Used

Despite being broken, SHA-1 remains in use for:

| Use Case | Status | Recommendation |
|----------|--------|----------------|
| Git commits | ⚠️ Legacy | Git moving to SHA-256 |
| HMAC-SHA1 | ⚠️ Still secure* | Prefer HMAC-SHA256 |
| Legacy TLS | ⚠️ Deprecated | Upgrade to TLS 1.3 |
| Code signing | ❌ Insecure | Use SHA-256 |
| Certificates | ❌ Rejected | Use SHA-256+ |
| Checksums (non-security) | ⚠️ OK | Consider faster alternatives |

*HMAC construction doesn't require collision resistance, but migration is recommended.

## Class: SHA1

### Constants

```cpp
static const int DIGESTSIZE = 20;   // 160 bits (20 bytes)
static const int BLOCKSIZE = 64;    // 512 bits (64 bytes)
```

### Methods

#### Update()

```cpp
void Update(const byte* input, size_t length);
```

Add data to hash computation.

#### Final()

```cpp
void Final(byte* digest);
```

Finalize and get 20-byte digest.

#### Restart()

```cpp
void Restart();
```

Reset to initial state.

#### CalculateDigest() - Static

```cpp
static void CalculateDigest(byte* digest,
                            const byte* input,
                            size_t length);
```

One-shot hashing.

#### VerifyDigest() - Static

```cpp
static bool VerifyDigest(const byte* digest,
                         const byte* input,
                         size_t length);
```

Verify hash (constant-time comparison).

## Complete Example: Legacy Compatibility

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

// Only use for legacy system compatibility!
std::string sha1Hash(const std::string& input) {
    SHA1 hash;
    std::string digest, hexDigest;

    StringSource(input, true,
        new HashFilter(hash,
            new StringSink(digest)
        )
    );

    StringSource(digest, true,
        new HexEncoder(new StringSink(hexDigest))
    );

    return hexDigest;
}

int main() {
    // Legacy compatibility example
    std::string hash = sha1Hash("test data");
    std::cout << "SHA-1 (legacy): " << hash << std::endl;

    // WARNING: Do not use for:
    // - Digital signatures
    // - Certificate fingerprints
    // - Password hashing
    // - Any security-critical application

    return 0;
}
```

## Security

### Known Attacks

| Attack | Year | Complexity | Impact |
|--------|------|------------|--------|
| Theoretical collision | 2005 | 2^69 | Academic |
| SHAttered collision | 2017 | 2^63 | **Practical** |
| Chosen-prefix collision | 2020 | 2^63 | **Practical** |

### SHAttered Attack (2017)

Google and CWI Amsterdam demonstrated a practical collision attack, creating two different PDF files with the same SHA-1 hash:

```
PDF 1: SHA-1 = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
PDF 2: SHA-1 = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a (same!)
```

This attack cost approximately 110 GPU-years and is feasible for well-resourced attackers.

### What's Still Safe

- **HMAC-SHA1:** The HMAC construction doesn't require collision resistance. HMAC-SHA1 remains secure, though migration to HMAC-SHA256 is recommended.
- **Non-security checksums:** If collision resistance isn't needed (e.g., cache keys), SHA-1 works but faster alternatives exist.

### What's Broken

- **Digital signatures:** An attacker can create two documents with the same hash
- **Certificate fingerprints:** Collision attacks enable certificate forgery
- **Git commits:** Potential for malicious commit collision (being addressed)
- **File integrity:** Attacker can substitute files with same hash

## Migration Guide

### Replace SHA-1 with SHA-256

```cpp
// OLD (insecure)
#include <cryptopp/sha.h>
SHA1 hash;

// NEW (secure)
#include <cryptopp/sha.h>
SHA256 hash;

// The API is identical - just change the class name
```

### Replace HMAC-SHA1 with HMAC-SHA256

```cpp
// OLD
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
HMAC<SHA1> hmac(key, keyLen);

// NEW
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
HMAC<SHA256> hmac(key, keyLen);
```

## Performance

### Benchmarks (Approximate)

| Algorithm | Speed (MB/s) | Digest Size | Security |
|-----------|--------------|-------------|----------|
| SHA-1 | 400-800 | 20 bytes | ❌ Broken |
| SHA-256 | 200-400 | 32 bytes | ✅ Secure |
| SHA-256 (SHA-NI) | 1000-2000 | 32 bytes | ✅ Secure |
| BLAKE3 | 3000-6000 | 32 bytes | ✅ Secure |

**Note:** SHA-1's speed advantage is not worth the security risk. Modern CPUs with SHA-NI make SHA-256 faster than SHA-1 anyway.

## SHA-1 vs Modern Alternatives

| Property | SHA-1 | SHA-256 | BLAKE3 |
|----------|-------|---------|--------|
| Security | ❌ Broken | ✅ ~128-bit | ✅ ~128-bit |
| Collision resistance | ❌ ~63-bit | ✅ ~128-bit | ✅ ~128-bit |
| Speed | Medium | Medium | Fast |
| Hardware accel | ❌ Rare | ✅ SHA-NI | ❌ No |
| Recommendation | Legacy only | General use | Performance |

## When to Use SHA-1

### ⚠️ Only use SHA-1 for:

1. **Legacy Compatibility** - Interfacing with old systems
2. **HMAC-SHA1** - When required by protocol (but prefer HMAC-SHA256)
3. **Git Compatibility** - Until SHA-256 migration complete
4. **Non-Security Checksums** - Where collisions don't matter

### ❌ Never use SHA-1 for:

1. **Digital Signatures** - Use SHA-256 or stronger
2. **Certificates** - Major browsers/CAs reject SHA-1
3. **Password Hashing** - Use Argon2 or bcrypt
4. **New Protocols** - Always use SHA-256+
5. **File Integrity** - Where security matters

## Test Vector

```cpp
// SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
std::string message = "abc";
SHA1 hash;
byte digest[SHA1::DIGESTSIZE];

hash.Update((const byte*)message.data(), message.size());
hash.Final(digest);

byte expected[] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d
};

assert(std::memcmp(digest, expected, 20) == 0);
```

## Exceptions

None thrown under normal operation.

## See Also

- [SHA-256](/docs/api/hash/sha256/) - Recommended replacement
- [SHA-512](/docs/api/hash/sha512/) - Higher security margin
- [BLAKE3](/docs/api/hash/blake3/) - Fastest secure hash
- [HMAC](/docs/api/mac/hmac/) - Message authentication
