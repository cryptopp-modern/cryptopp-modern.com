---
title: HKDF
description: HMAC-based Key Derivation Function API reference
weight: 2
---

**Header:** `#include <cryptopp/hkdf.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.6.3  
**Thread Safety:** Not thread-safe per instance; use separate instances per thread
**Inherits from:** `KeyDerivationFunction`

HKDF (HMAC-based Key Derivation Function) is a simple and well-analyzed key derivation function defined in RFC 5869. It uses HMAC to extract entropy from key material and expand it into multiple cryptographic keys. HKDF is the recommended KDF for most applications.

## Quick Example

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Input key material (e.g., ECDH shared secret)
    SecByteBlock ikm(32);
    AutoSeededRandomPool rng;
    rng.GenerateBlock(ikm, ikm.size());

    // Salt (optional but recommended)
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // Context information
    std::string info = "application-specific-context";

    // Derive 48 bytes of key material
    SecByteBlock derivedKey(48);

    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(
        derivedKey, derivedKey.size(),  // output
        ikm, ikm.size(),                // input key material
        salt, sizeof(salt),             // salt
        (const byte*)info.data(), info.size()  // info
    );

    // Split into separate keys
    SecByteBlock encKey(derivedKey, 32);      // First 32 bytes
    SecByteBlock macKey(derivedKey + 32, 16); // Next 16 bytes

    std::cout << "Derived 48 bytes of key material" << std::endl;
    std::cout << "Encryption key: 32 bytes" << std::endl;
    std::cout << "MAC key: 16 bytes" << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use HKDF<SHA256> for most applications (recommended)
- Use HKDF<SHA512> for high-security requirements
- Provide salt when available (use random salt if no natural salt exists)
- Use distinct info strings for different derived keys
- Derive multiple keys from single shared secret (key separation)

**Avoid:**
- Using HKDF for password hashing (use Argon2 instead)
- Reusing the same info string for different purposes
- Deriving more than 255 × HashLen bytes (very large limit)
{{< /callout >}}

## Template Class: HKDF<T>

Key derivation function parameterized by hash function.

### Template Parameter

```cpp
template <class T>  // T = hash function (SHA256, SHA512, etc.)
class HKDF : public KeyDerivationFunction;
```

**Common instantiations:**

```cpp
HKDF<SHA256> hkdf256;  // Recommended
HKDF<SHA512> hkdf512;  // High security
HKDF<SHA1>   hkdf1;    // Legacy only
```

### Methods

#### DeriveKey() - Full Form

```cpp
size_t DeriveKey(byte* derived, size_t derivedLen,
                 const byte* secret, size_t secretLen,
                 const byte* salt, size_t saltLen,
                 const byte* info, size_t infoLen) const;
```

Derive key from input key material.

**Parameters:**
- `derived` - Output buffer for derived key
- `derivedLen` - Length of derived key (max: 255 × HashLen)
- `secret` - Input key material (IKM)
- `secretLen` - IKM length
- `salt` - Salt value (can be NULL)
- `saltLen` - Salt length (0 if NULL)
- `info` - Application-specific context
- `infoLen` - Info length (can be 0)

**Returns:** 1 (always, unlike PBKDF which returns iteration count)

**Example:**

```cpp
HKDF<SHA256> hkdf;

SecByteBlock ikm(32);      // Input key material
byte salt[16];             // Salt
std::string info = "app-context";
SecByteBlock output(64);   // Derive 64 bytes

hkdf.DeriveKey(
    output, output.size(),
    ikm, ikm.size(),
    salt, sizeof(salt),
    (const byte*)info.data(), info.size()
);
```

#### MaxDerivedKeyLength()

```cpp
size_t MaxDerivedKeyLength() const;
```

Get maximum output length.

**Returns:** 255 × HashLen (e.g., 8160 bytes for SHA256)

**Example:**

```cpp
HKDF<SHA256> hkdf;
size_t maxLen = hkdf.MaxDerivedKeyLength();
// Returns: 255 × 32 = 8160 bytes
```

## Complete Example: Key Separation

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

class DerivedKeys {
public:
    SecByteBlock aesKey;
    SecByteBlock hmacKey;
    SecByteBlock ivKey;

    static DerivedKeys fromSharedSecret(const SecByteBlock& sharedSecret,
                                        const std::string& context) {
        DerivedKeys keys;

        // Derive separate keys using different info strings
        HKDF<SHA256> hkdf;

        // AES key (32 bytes)
        keys.aesKey.New(32);
        std::string aesInfo = context + ":aes";
        hkdf.DeriveKey(
            keys.aesKey, keys.aesKey.size(),
            sharedSecret, sharedSecret.size(),
            nullptr, 0,  // no salt
            (const byte*)aesInfo.data(), aesInfo.size()
        );

        // HMAC key (32 bytes)
        keys.hmacKey.New(32);
        std::string hmacInfo = context + ":hmac";
        hkdf.DeriveKey(
            keys.hmacKey, keys.hmacKey.size(),
            sharedSecret, sharedSecret.size(),
            nullptr, 0,
            (const byte*)hmacInfo.data(), hmacInfo.size()
        );

        // IV generation key (16 bytes)
        keys.ivKey.New(16);
        std::string ivInfo = context + ":iv";
        hkdf.DeriveKey(
            keys.ivKey, keys.ivKey.size(),
            sharedSecret, sharedSecret.size(),
            nullptr, 0,
            (const byte*)ivInfo.data(), ivInfo.size()
        );

        return keys;
    }
};

int main() {
    AutoSeededRandomPool rng;

    // Simulate ECDH shared secret
    SecByteBlock sharedSecret(32);
    rng.GenerateBlock(sharedSecret, sharedSecret.size());

    // Derive separate keys for encryption, MAC, IV
    DerivedKeys keys = DerivedKeys::fromSharedSecret(
        sharedSecret,
        "secure-channel-v1"
    );

    std::cout << "Derived keys from shared secret:" << std::endl;
    std::cout << "AES key: " << keys.aesKey.size() << " bytes" << std::endl;
    std::cout << "HMAC key: " << keys.hmacKey.size() << " bytes" << std::endl;
    std::cout << "IV key: " << keys.ivKey.size() << " bytes" << std::endl;

    // Keys are cryptographically independent
    // Safe to use for different purposes

    return 0;
}
```

## Complete Example: ECDH + HKDF

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <iostream>

using namespace CryptoPP;

class SecureChannel {
public:
    SecByteBlock encryptionKey;
    SecByteBlock macKey;

    static SecureChannel establish(
        const ECDH<ECP>::Domain& domain,
        const SecByteBlock& privateKey,
        const SecByteBlock& publicKey,
        const std::string& context) {

        // Perform ECDH key agreement
        SecByteBlock sharedSecret(domain.AgreedValueLength());

        if (!domain.Agree(sharedSecret, privateKey, publicKey)) {
            throw std::runtime_error("ECDH agreement failed");
        }

        std::cout << "ECDH shared secret: " << sharedSecret.size()
                  << " bytes" << std::endl;

        // Derive keys using HKDF
        SecByteBlock derivedKeys(64);  // 32 + 32
        HKDF<SHA256> hkdf;

        hkdf.DeriveKey(
            derivedKeys, derivedKeys.size(),
            sharedSecret, sharedSecret.size(),
            nullptr, 0,  // no salt (shared secret is already random)
            (const byte*)context.data(), context.size()
        );

        // Split derived keys
        SecureChannel channel;
        channel.encryptionKey.Assign(derivedKeys, 32);
        channel.macKey.Assign(derivedKeys + 32, 32);

        std::cout << "Derived encryption key: "
                  << channel.encryptionKey.size() << " bytes" << std::endl;
        std::cout << "Derived MAC key: "
                  << channel.macKey.size() << " bytes" << std::endl;

        return channel;
    }
};

int main() {
    AutoSeededRandomPool rng;

    // Create ECDH domain (P-256)
    ECDH<ECP>::Domain domain(ASN1::secp256r1());

    // Alice's key pair
    SecByteBlock alicePrivate(domain.PrivateKeyLength());
    SecByteBlock alicePublic(domain.PublicKeyLength());
    domain.GenerateKeyPair(rng, alicePrivate, alicePublic);

    // Bob's key pair
    SecByteBlock bobPrivate(domain.PrivateKeyLength());
    SecByteBlock bobPublic(domain.PublicKeyLength());
    domain.GenerateKeyPair(rng, bobPrivate, bobPublic);

    // Alice establishes channel with Bob's public key
    SecureChannel aliceChannel = SecureChannel::establish(
        domain, alicePrivate, bobPublic, "chat-session-2024"
    );

    // Bob establishes channel with Alice's public key
    SecureChannel bobChannel = SecureChannel::establish(
        domain, bobPrivate, alicePublic, "chat-session-2024"
    );

    // Verify both sides derived same keys
    bool encMatch = std::memcmp(
        aliceChannel.encryptionKey.data(),
        bobChannel.encryptionKey.data(),
        32
    ) == 0;

    bool macMatch = std::memcmp(
        aliceChannel.macKey.data(),
        bobChannel.macKey.data(),
        32
    ) == 0;

    std::cout << "\nKey agreement successful: "
              << (encMatch && macMatch ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Complete Example: Password-Based Key with Salt

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

// Proper password-based key derivation combines Argon2 + HKDF
class PasswordDerivedKeys {
public:
    static SecByteBlock deriveFromPassword(
        const std::string& password,
        const byte* salt, size_t saltLen,
        size_t outputLen) {

        // Step 1: Hash password with Argon2id (slow, memory-hard)
        Argon2id argon2(2, 1 << 16, 4);  // t=2, m=64MB, p=4
        SecByteBlock passwordHash(32);

        argon2.DeriveKey(
            passwordHash, passwordHash.size(),
            (const byte*)password.data(), password.size(),
            salt, saltLen
        );

        std::cout << "Argon2 password hash: " << passwordHash.size()
                  << " bytes" << std::endl;

        // Step 2: Expand with HKDF (fast, generate multiple keys)
        HKDF<SHA256> hkdf;
        SecByteBlock output(outputLen);

        std::string info = "application-keys-v1";
        hkdf.DeriveKey(
            output, output.size(),
            passwordHash, passwordHash.size(),
            salt, saltLen,
            (const byte*)info.data(), info.size()
        );

        return output;
    }
};

int main() {
    AutoSeededRandomPool rng;

    std::string password = "correct horse battery staple";

    // Generate random salt
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // Derive 64 bytes for encryption + MAC keys
    SecByteBlock keys = PasswordDerivedKeys::deriveFromPassword(
        password, salt, sizeof(salt), 64
    );

    std::cout << "Derived " << keys.size() << " bytes from password" << std::endl;

    // Split into separate keys
    SecByteBlock encKey(keys, 32);
    SecByteBlock macKey(keys + 32, 32);

    std::cout << "Encryption key: " << encKey.size() << " bytes" << std::endl;
    std::cout << "MAC key: " << macKey.size() << " bytes" << std::endl;

    return 0;
}
```

## Salt Behavior

HKDF has special handling for NULL vs empty salt:

```cpp
HKDF<SHA256> hkdf;

// NULL salt: HKDF uses string of zeros with length = hash output size
hkdf.DeriveKey(output, outLen, ikm, ikmLen,
               nullptr, 0,  // NULL salt → zeros used internally
               info, infoLen);

// Empty salt (non-NULL pointer): different from NULL
byte dummy = 0;
byte* emptySalt = &dummy;

hkdf.DeriveKey(output, outLen, ikm, ikmLen,
               emptySalt, 0,  // Empty but non-NULL
               info, infoLen);

// Explicit salt (recommended)
byte salt[16] = { /* ... */ };
hkdf.DeriveKey(output, outLen, ikm, ikmLen,
               salt, sizeof(salt),  // Explicit salt
               info, infoLen);
```

**Recommendation:** Always provide explicit salt when possible.

## Info String Usage

The `info` parameter binds derived keys to specific contexts:

```cpp
HKDF<SHA256> hkdf;
SecByteBlock ikm(32), output(32);

// Different info strings produce independent keys
std::string info1 = "encryption";
hkdf.DeriveKey(output, 32, ikm, 32, nullptr, 0,
               (const byte*)info1.data(), info1.size());
SecByteBlock encKey = output;

std::string info2 = "authentication";
hkdf.DeriveKey(output, 32, ikm, 32, nullptr, 0,
               (const byte*)info2.data(), info2.size());
SecByteBlock macKey = output;

// encKey and macKey are cryptographically independent
```

**Best practices:**
- Include version: `"myapp-v1:encryption"`
- Include purpose: `"client-to-server-key"`
- Include protocol: `"TLS-1.3-handshake-key"`

## Performance

### Speed (Approximate)

| Variant | Speed (MB/s)* | Typical Security Level |
|---------|---------------|------------------------|
| HKDF-SHA256 | 400–800 | ~128-bit |
| HKDF-SHA512 | 600–1200 | ~256-bit |
| HKDF-SHA1 (legacy) | 500–1000 | Legacy only |

*Very rough ballpark figures on modern CPUs. Actual performance depends on hardware and compiler, and is dominated by the cost of the underlying HMAC.

HKDF adds minimal overhead on top of HMAC: one HMAC for the "extract" step, plus one HMAC per `HashLen` bytes of output during "expand".

### Comparison with Other KDFs

| KDF | Speed | Use Case |
|-----|-------|----------|
| **HKDF** | Very fast | Key derivation from high-entropy secrets |
| Argon2 | Slow (intentional) | Password hashing |
| PBKDF2 | Moderate | Legacy password hashing |
| scrypt | Slow | Legacy password hashing |

**Use HKDF for key derivation, Argon2 for password hashing.**

## Security

### Security Properties

- **Extractability:** Extracts entropy from non-uniform secrets (when salt is non-trivial)
- **Expansion:** Generates multiple keys from a single secret (extract-then-expand)
- **Security:** Reduces to the PRF / random-oracle security of HMAC with the chosen hash
- **Standard:** RFC 5869, also aligned with NIST SP 800-56C (extract-then-expand KDFs)
- **Proof:** Security proven in the PRF / random-oracle model (see RFC 5869 and HKDF paper)

### Hash Function Selection

```cpp
// Recommended: SHA-256 (128-bit security)
HKDF<SHA256> hkdf256;

// High security: SHA-512 (256-bit security)
HKDF<SHA512> hkdf512;

// Legacy only: SHA-1 (avoid for new applications)
HKDF<SHA1> hkdf1;  // Acceptable for HKDF but not signing
```

### Security Best Practices

1. **Use Different Info for Different Keys:**
   ```cpp
   // CORRECT - different info strings
   hkdf.DeriveKey(..., info: "encryption");
   hkdf.DeriveKey(..., info: "authentication");

   // WRONG - same info string
   hkdf.DeriveKey(..., info: "keys");  // Both keys!
   hkdf.DeriveKey(..., info: "keys");  // IDENTICAL
   ```

2. **Provide Salt When Available:**
   ```cpp
   // GOOD - with salt
   hkdf.DeriveKey(..., salt, saltLen, ...);

   // ACCEPTABLE - no salt (if secret already high-entropy)
   hkdf.DeriveKey(..., nullptr, 0, ...);
   ```

3. **Don't Use for Password Hashing:**
   ```cpp
   // WRONG - HKDF for passwords
   HKDF<SHA256> hkdf;
   hkdf.DeriveKey(key, keyLen, (byte*)password, passLen, ...);

   // CORRECT - Argon2 then HKDF
   Argon2id argon2(...);
   argon2.DeriveKey(hash, hashLen, (byte*)password, passLen, ...);
   hkdf.DeriveKey(key, keyLen, hash, hashLen, ...);
   ```

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## When to Use HKDF

### ✅ Use HKDF for:

1. **Key Derivation from Shared Secrets** - After ECDH/X25519 key agreement
2. **Key Separation** - Derive encryption, MAC, IV keys from one secret
3. **Key Expansion** - Generate multiple keys from single master key
4. **Protocol Key Derivation** - TLS, Signal Protocol, etc.
5. **After Argon2** - Expand password hash into multiple keys

### ❌ Don't use HKDF for:

1. **Password Hashing** - Use Argon2id instead
2. **Low-Entropy Secrets** - Use Argon2/PBKDF2 first
3. **Random Number Generation** - Use AutoSeededRandomPool

## HKDF vs Argon2 vs PBKDF2

| KDF | Speed | Memory | Use Case |
|-----|-------|--------|----------|
| **HKDF** | Fast | Low | High-entropy secrets (ECDH, etc.) |
| **Argon2** | Slow | High | Password hashing |
| **PBKDF2** | Moderate | Low | Legacy password hashing |

**Decision tree:**
- High-entropy secret (ECDH, random key) → **HKDF**
- Password → **Argon2id**
- Legacy password system → **PBKDF2**

## Exceptions

None thrown under normal operation.

## See Also

- [Argon2](/docs/api/kdf/argon2/) - For password hashing
- [HMAC](/docs/api/mac/hmac/) - Underlying primitive
- [X25519](/docs/api/pubkey/x25519/) - Key exchange (use with HKDF)
- [SHA-256](/docs/api/hash/sha256/) - Recommended hash function
