---
title: MD5
description: MD5 message digest API reference (legacy/broken)
weight: 7
---

**Header:** `#include <cryptopp/md5.h>` | **Namespace:** `CryptoPP::Weak`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

{{< callout type="error" >}}
**MD5 is completely broken and must not be used for any security purpose.**

MD5 has been broken since 2004, with practical collision attacks taking seconds on a laptop. It is included **only** for:
- Legacy system compatibility
- Non-cryptographic checksums (file deduplication, etc.)

**For any security application, use SHA-256, SHA-3, or BLAKE3.**
{{< /callout >}}

MD5 (Message-Digest Algorithm 5) is a 128-bit hash function designed by Ronald Rivest in 1991. It has been cryptographically broken since 2004 and should not be used for security purposes.

## Quick Example

```cpp
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // WARNING: MD5 is broken - use only for legacy compatibility!
    Weak::MD5 hash;
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

    std::cout << "MD5: " << hexOutput << std::endl;
    // Output: 65A8E27D8879283831B664BD8B7F0AD4

    return 0;
}
```

## The Weak Namespace

Crypto++ places MD5 in the `Weak` namespace to discourage its use:

```cpp
// Method 1: Enable weak algorithms explicitly
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
CryptoPP::Weak::MD5 hash;

// Method 2: Without the define, you get a compiler warning
#include <cryptopp/md5.h>
CryptoPP::MD5 hash;  // Warning: using weak algorithm
```

The `CRYPTOPP_ENABLE_NAMESPACE_WEAK` define suppresses the warning, acknowledging you understand the risks.

## Class: Weak::MD5

### Constants

```cpp
static const int DIGESTSIZE = 16;   // 128 bits (16 bytes)
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

Finalize and get 16-byte digest.

#### Restart()

```cpp
void Restart();
```

Reset to initial state.

## Complete Example: Legacy System Compatibility

```cpp
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

// Only for legacy compatibility - NOT for security!
std::string md5Hash(const std::string& input) {
    Weak::MD5 hash;
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
    // Example: Verify against legacy system's MD5 hash
    std::string data = "test";
    std::string hash = md5Hash(data);

    std::cout << "MD5 (legacy check): " << hash << std::endl;
    // Output: 098F6BCD4621D373CADE4E832627B4F6

    // Compare with expected legacy hash
    if (hash == "098F6BCD4621D373CADE4E832627B4F6") {
        std::cout << "Legacy hash matches!" << std::endl;
    }

    return 0;
}
```

## Security

### MD5 Is Completely Broken

| Attack | Year | Complexity | Impact |
|--------|------|------------|--------|
| Theoretical collision | 1996 | 2^64 → 2^41 | Academic |
| First practical collision | 2004 | Minutes | **Critical** |
| Chosen-prefix collision | 2007 | Hours | **Critical** |
| Fast collision | 2009 | Seconds | **Critical** |
| Flame malware | 2012 | Real-world | **In the wild** |

### Real-World Attacks

**Flame Malware (2012):** Used an MD5 collision to forge a Microsoft code-signing certificate, allowing malware to appear legitimately signed.

**Rogue CA Certificate (2008):** Researchers created a rogue Certificate Authority certificate by exploiting MD5 collisions.

### Collision Generation

MD5 collisions can be generated in **seconds** on modern hardware:

```
# Using fastcoll (public tool):
$ fastcoll -p prefix.txt -o collision1.bin collision2.bin
Generating collision... done (2.3 seconds)

# Both files have identical MD5 but different content!
```

### What MD5 Cannot Do

- ❌ **Digital signatures** - Forgery is trivial
- ❌ **Certificate fingerprints** - Collision attacks enable forgery
- ❌ **Password hashing** - Use Argon2 or bcrypt
- ❌ **File integrity (security)** - Attacker can create collisions
- ❌ **Any security application** - Completely broken

### Limited Safe Uses

- ✅ **Non-cryptographic checksums** - Cache keys, deduplication (where security doesn't matter)
- ✅ **Legacy compatibility** - When you must interface with old systems
- ⚠️ **HMAC-MD5** - Technically still secure, but migrate to HMAC-SHA256

## Migration Guide

### Replace MD5 with SHA-256

```cpp
// OLD (broken)
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
CryptoPP::Weak::MD5 hash;
byte digest[16];
hash.Final(digest);

// NEW (secure)
#include <cryptopp/sha.h>
CryptoPP::SHA256 hash;
byte digest[32];
hash.Final(digest);
```

### For Password Hashing

```cpp
// OLD (completely wrong)
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
Weak::MD5 hash;
hash.Update((byte*)password.data(), password.size());
hash.Final(passwordHash);  // NEVER DO THIS

// NEW (correct)
#include <cryptopp/argon2.h>
Argon2id argon2;
argon2.DeriveKey(derivedKey, derivedLen,
    (byte*)password.data(), password.size(),
    salt, saltLen,
    3, 65536, 4);  // Proper password hashing
```

## Performance

| Algorithm | Speed (MB/s) | Digest | Security |
|-----------|--------------|--------|----------|
| MD5 | 500-1000 | 16 bytes | ❌ Broken |
| SHA-1 | 400-800 | 20 bytes | ❌ Broken |
| SHA-256 | 200-400 | 32 bytes | ✅ Secure |
| BLAKE3 | 3000-6000 | 32 bytes | ✅ Secure |

**Note:** MD5's speed is irrelevant given it provides no security. BLAKE3 is both faster and secure.

## MD5 vs Modern Alternatives

| Property | MD5 | SHA-256 | BLAKE3 |
|----------|-----|---------|--------|
| Security | ❌ Broken (0 bits) | ✅ ~128-bit | ✅ ~128-bit |
| Collision resistance | ❌ Seconds | ✅ ~128-bit | ✅ ~128-bit |
| Preimage resistance | ⚠️ Weakened | ✅ ~256-bit | ✅ ~128-bit |
| Speed | Fast | Medium | Faster |
| Digest size | 16 bytes | 32 bytes | 32 bytes |
| Recommendation | ❌ Never | ✅ Default | ✅ Performance |

## Test Vector

```cpp
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

// MD5("") = d41d8cd98f00b204e9800998ecf8427e
Weak::MD5 hash;
byte digest[Weak::MD5::DIGESTSIZE];
hash.Final(digest);

byte expected[] = {
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
};

assert(std::memcmp(digest, expected, 16) == 0);
```

## When to Use MD5

### ⚠️ Only use MD5 for:

1. **Legacy Compatibility** - Interfacing with systems that require MD5
2. **Non-Security Checksums** - Cache keys, file deduplication where collision attacks are irrelevant
3. **Academic/Historical** - Studying hash function cryptanalysis

### ❌ Never use MD5 for:

1. **Any Security Purpose** - It is completely broken
2. **Password Hashing** - Use Argon2
3. **Digital Signatures** - Use SHA-256+
4. **File Integrity** - Use SHA-256 or BLAKE3
5. **New Code** - Always use modern alternatives

## Exceptions

None thrown under normal operation.

## See Also

- [SHA-256](/docs/api/hash/sha256/) - Recommended replacement
- [BLAKE3](/docs/api/hash/blake3/) - Fast modern hash
- [SHA-1](/docs/api/hash/sha1/) - Also broken (but less so)
- [Argon2](/docs/api/kdf/argon2/) - For password hashing
