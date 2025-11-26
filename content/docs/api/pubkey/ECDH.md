---
title: ECDH
description: Elliptic Curve Diffie-Hellman key exchange API reference
weight: 5
---

**Header:** `#include <cryptopp/eccrypto.h>` and `#include <cryptopp/oids.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 3.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

ECDH (Elliptic Curve Diffie-Hellman) is a key agreement protocol that allows two parties to establish a shared secret over an insecure channel using elliptic curve cryptography. It provides the same security as traditional DH with much smaller key sizes.

## Quick Example

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Create ECDH domain with P-256 curve
    ECDH<ECP>::Domain dh(ASN1::secp256r1());

    // Alice generates her key pair
    SecByteBlock alicePrivate(dh.PrivateKeyLength());
    SecByteBlock alicePublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, alicePrivate, alicePublic);

    // Bob generates his key pair
    SecByteBlock bobPrivate(dh.PrivateKeyLength());
    SecByteBlock bobPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, bobPrivate, bobPublic);

    // Alice computes shared secret
    SecByteBlock aliceShared(dh.AgreedValueLength());
    if (!dh.Agree(aliceShared, alicePrivate, bobPublic)) {
        std::cerr << "Alice: Key agreement failed!" << std::endl;
        return 1;
    }

    // Bob computes shared secret
    SecByteBlock bobShared(dh.AgreedValueLength());
    if (!dh.Agree(bobShared, bobPrivate, alicePublic)) {
        std::cerr << "Bob: Key agreement failed!" << std::endl;
        return 1;
    }

    // Verify both have same shared secret
    if (aliceShared == bobShared) {
        std::cout << "Key agreement successful!" << std::endl;
        std::cout << "Shared secret size: " << aliceShared.size() << " bytes" << std::endl;
    }

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use P-256 (secp256r1) for general purpose, P-384 for higher security
- Always derive encryption keys from shared secret using HKDF
- Use ephemeral keys for forward secrecy
- Validate public keys before use (Agree() does this by default)

**Avoid:**
- Using shared secret directly as encryption key (use HKDF)
- Reusing ephemeral keys across sessions (defeats forward secrecy)
- Using ECDH when X25519 is available (X25519 is simpler and faster)
- Skipping public key validation
{{< /callout >}}

## Supported Curves

| Curve | OID | Security | Key Size | Shared Secret |
|-------|-----|----------|----------|---------------|
| **P-256** (secp256r1) | `ASN1::secp256r1()` | ~128-bit | 64 bytes | 32 bytes |
| **P-384** (secp384r1) | `ASN1::secp384r1()` | ~192-bit | 96 bytes | 48 bytes |
| **P-521** (secp521r1) | `ASN1::secp521r1()` | ~256-bit | 132 bytes | 66 bytes |

## Class: ECDH<EC>::Domain

ECDH key agreement domain for elliptic curves.

```cpp
template <class EC, class COFACTOR_OPTION = ...>
struct ECDH {
    typedef DH_Domain<DL_GroupParameters_EC<EC>, COFACTOR_OPTION> Domain;
};
```

### Constructor

```cpp
ECDH<ECP>::Domain(const OID& oid);
ECDH<ECP>::Domain(const DL_GroupParameters_EC<ECP>& params);
```

**Parameters:**
- `oid` - Curve OID (e.g., `ASN1::secp256r1()`)
- `params` - Explicit curve parameters

**Example:**

```cpp
// Using curve OID (recommended)
ECDH<ECP>::Domain dh(ASN1::secp256r1());

// Using P-384
ECDH<ECP>::Domain dh384(ASN1::secp384r1());
```

### Methods

#### GenerateKeyPair()

```cpp
void GenerateKeyPair(RandomNumberGenerator& rng,
                     byte* privateKey,
                     byte* publicKey) const;
```

Generate an ephemeral key pair.

**Parameters:**
- `rng` - Random number generator
- `privateKey` - Output buffer for private key
- `publicKey` - Output buffer for public key

**Example:**

```cpp
ECDH<ECP>::Domain dh(ASN1::secp256r1());

SecByteBlock privateKey(dh.PrivateKeyLength());
SecByteBlock publicKey(dh.PublicKeyLength());

dh.GenerateKeyPair(rng, privateKey, publicKey);
```

#### Agree()

```cpp
bool Agree(byte* agreedValue,
           const byte* privateKey,
           const byte* otherPublicKey,
           bool validateOtherPublicKey = true) const;
```

Compute shared secret from private key and other party's public key.

**Parameters:**
- `agreedValue` - Output buffer for shared secret
- `privateKey` - Your private key
- `otherPublicKey` - Other party's public key
- `validateOtherPublicKey` - Validate public key (default: true)

**Returns:** `true` if successful, `false` if validation fails

**Example:**

```cpp
SecByteBlock sharedSecret(dh.AgreedValueLength());

if (!dh.Agree(sharedSecret, myPrivate, theirPublic)) {
    // Key agreement failed - invalid public key
    return false;
}
```

#### PrivateKeyLength()

```cpp
unsigned int PrivateKeyLength() const;
```

**Returns:** Size of private key in bytes

#### PublicKeyLength()

```cpp
unsigned int PublicKeyLength() const;
```

**Returns:** Size of public key in bytes

#### AgreedValueLength()

```cpp
unsigned int AgreedValueLength() const;
```

**Returns:** Size of shared secret in bytes

## Complete Example: Secure Channel Setup

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

struct DerivedKeys {
    SecByteBlock encryptionKey;
    SecByteBlock macKey;
};

// Derive encryption keys from ECDH shared secret
DerivedKeys deriveKeys(const SecByteBlock& sharedSecret,
                       const SecByteBlock& alicePublic,
                       const SecByteBlock& bobPublic) {
    HKDF<SHA256> hkdf;

    // Create context binding (both public keys)
    SecByteBlock info(alicePublic.size() + bobPublic.size());
    std::memcpy(info, alicePublic, alicePublic.size());
    std::memcpy(info + alicePublic.size(), bobPublic, bobPublic.size());

    DerivedKeys keys;
    keys.encryptionKey.resize(32);  // AES-256 key
    keys.macKey.resize(32);         // HMAC key

    // Derive encryption key
    byte encInfo[] = "encryption";
    hkdf.DeriveKey(keys.encryptionKey, keys.encryptionKey.size(),
                   sharedSecret, sharedSecret.size(),
                   info, info.size(),
                   encInfo, sizeof(encInfo) - 1);

    // Derive MAC key
    byte macInfo[] = "authentication";
    hkdf.DeriveKey(keys.macKey, keys.macKey.size(),
                   sharedSecret, sharedSecret.size(),
                   info, info.size(),
                   macInfo, sizeof(macInfo) - 1);

    return keys;
}

int main() {
    AutoSeededRandomPool rng;

    // Create ECDH domain with P-256
    ECDH<ECP>::Domain dh(ASN1::secp256r1());

    // Alice generates ephemeral keys
    SecByteBlock alicePrivate(dh.PrivateKeyLength());
    SecByteBlock alicePublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, alicePrivate, alicePublic);

    // Bob generates ephemeral keys
    SecByteBlock bobPrivate(dh.PrivateKeyLength());
    SecByteBlock bobPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, bobPrivate, bobPublic);

    // Exchange public keys (simulated - in reality over network)

    // Alice computes shared secret
    SecByteBlock aliceShared(dh.AgreedValueLength());
    if (!dh.Agree(aliceShared, alicePrivate, bobPublic)) {
        std::cerr << "Alice: Key agreement failed!" << std::endl;
        return 1;
    }

    // Bob computes shared secret
    SecByteBlock bobShared(dh.AgreedValueLength());
    if (!dh.Agree(bobShared, bobPrivate, alicePublic)) {
        std::cerr << "Bob: Key agreement failed!" << std::endl;
        return 1;
    }

    // Derive session keys (both parties get same keys)
    DerivedKeys aliceKeys = deriveKeys(aliceShared, alicePublic, bobPublic);
    DerivedKeys bobKeys = deriveKeys(bobShared, alicePublic, bobPublic);

    // Verify keys match
    if (aliceKeys.encryptionKey == bobKeys.encryptionKey &&
        aliceKeys.macKey == bobKeys.macKey) {
        std::cout << "Secure channel established!" << std::endl;
    }

    // Alice encrypts message to Bob
    std::string message = "Secret message from Alice";
    std::string ciphertext;

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(aliceKeys.encryptionKey, aliceKeys.encryptionKey.size(),
                     iv, sizeof(iv));

    StringSource(message, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    std::cout << "Message encrypted: " << ciphertext.size() << " bytes" << std::endl;

    return 0;
}
```

## Complete Example: Static-Ephemeral ECDH

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/secblock.h>
#include <iostream>

using namespace CryptoPP;

// Server has static key pair (long-term identity)
// Client generates ephemeral key pair per session

int main() {
    AutoSeededRandomPool rng;
    ECDH<ECP>::Domain dh(ASN1::secp256r1());

    // === Server Setup (one-time) ===
    SecByteBlock serverPrivate(dh.PrivateKeyLength());
    SecByteBlock serverPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, serverPrivate, serverPublic);
    std::cout << "Server public key generated (publish this)" << std::endl;

    // === Client Session ===
    // Client generates ephemeral key pair
    SecByteBlock clientPrivate(dh.PrivateKeyLength());
    SecByteBlock clientPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, clientPrivate, clientPublic);

    // Client computes shared secret using server's static public key
    SecByteBlock clientShared(dh.AgreedValueLength());
    if (!dh.Agree(clientShared, clientPrivate, serverPublic)) {
        std::cerr << "Client: Key agreement failed!" << std::endl;
        return 1;
    }

    // Client sends ephemeral public key to server

    // === Server Session ===
    // Server computes shared secret using client's ephemeral public key
    SecByteBlock serverShared(dh.AgreedValueLength());
    if (!dh.Agree(serverShared, serverPrivate, clientPublic)) {
        std::cerr << "Server: Key agreement failed!" << std::endl;
        return 1;
    }

    // Verify
    if (clientShared == serverShared) {
        std::cout << "Static-ephemeral ECDH successful!" << std::endl;
        std::cout << "  Server uses static key (identity)" << std::endl;
        std::cout << "  Client uses ephemeral key (forward secrecy)" << std::endl;
    }

    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Curve | Key Gen | Agreement |
|-------|---------|-----------|
| P-256 | 0.5-1 ms | 1-2 ms |
| P-384 | 1-2 ms | 2-4 ms |
| P-521 | 2-4 ms | 4-8 ms |

**Platform:** Modern x86-64 CPU

### ECDH vs X25519

| Feature | ECDH P-256 | X25519 |
|---------|------------|--------|
| Key gen | ~1 ms | ~0.05 ms |
| Agreement | ~2 ms | ~0.05 ms |
| Public key | 64 bytes | 32 bytes |
| Private key | 32 bytes | 32 bytes |
| Shared secret | 32 bytes | 32 bytes |
| Security | ~128-bit | ~128-bit |
| Complexity | Higher | Lower |

**Recommendation:** Use X25519 for new applications. Use ECDH when NIST curves are required.

## Security

### Security Properties

- **Security level:** Curve-dependent (P-256 ≈ 128-bit)
- **Forward secrecy:** Achieved with ephemeral keys
- **Key validation:** Public keys are validated by default in `Agree()`
- **Standards:** NIST SP 800-56A, ANSI X9.63

### Security Notes

- **Always use HKDF:** Never use the raw shared secret directly as an encryption key. Use HKDF to derive keys.
- **Ephemeral keys:** Use new keys for each session to achieve forward secrecy.
- **Public key validation:** Always validate received public keys (done automatically by `Agree()` with default parameters).
- **Context binding:** Include both public keys in HKDF info parameter to bind derived keys to the specific exchange.

### Key Derivation Best Practice

```cpp
// WRONG - using raw shared secret
GCM<AES>::Encryption enc;
enc.SetKeyWithIV(sharedSecret, sharedSecret.size(), iv, sizeof(iv));

// CORRECT - derive key with HKDF
HKDF<SHA256> hkdf;
SecByteBlock derivedKey(32);
hkdf.DeriveKey(derivedKey, derivedKey.size(),
               sharedSecret, sharedSecret.size(),
               salt, saltLen,
               info, infoLen);

GCM<AES>::Encryption enc;
enc.SetKeyWithIV(derivedKey, derivedKey.size(), iv, sizeof(iv));
```

## ECDH vs X25519

| Aspect | ECDH (NIST curves) | X25519 |
|--------|-------------------|--------|
| Standardization | NIST, widely adopted | Modern, growing |
| Performance | Good | Better (10-40x faster) |
| Implementation | Complex, many pitfalls | Simple, hard to misuse |
| Key size | P-256: 64 bytes public | 32 bytes public |
| Compatibility | Universal (TLS 1.2, etc.) | TLS 1.3, modern protocols |
| Recommendation | Compliance/interop | New applications |

## When to Use ECDH

### ✅ Use ECDH for:

1. **TLS 1.2** - Standard key exchange
2. **NIST Compliance** - Government/regulated environments
3. **Interoperability** - Systems requiring NIST curves
4. **X.509/PKI** - Standard certificate infrastructure

### ❌ Don't use ECDH for:

1. **New Applications** - Prefer X25519
2. **Performance Critical** - X25519 is much faster
3. **Simple Protocols** - X25519 is easier to use correctly

## Exceptions

- `InvalidMaterial` - Invalid key parameters
- Key agreement returns `false` if public key validation fails

## See Also

- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange (recommended)
- [ECDSA](/docs/api/pubkey/ecdsa/) - Signatures with same curves
- [HKDF](/docs/api/kdf/hkdf/) - Key derivation for shared secrets
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption
