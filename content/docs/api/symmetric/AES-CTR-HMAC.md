---
title: AES-CTR-HMAC
description: AES-CTR mode with HMAC authentication (Encrypt-then-MAC) using automatic key derivation
weight: 4
---

**Header:** `#include <cryptopp/aes_ctr_hmac.h>`
**Namespace:** `CryptoPP`
**Since:** cryptopp-modern 2025.12
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

AES-CTR-HMAC is an Encrypt-then-MAC authenticated encryption scheme combining AES in Counter mode with HMAC for authentication. Unlike manual CBC+HMAC constructions, this implementation automatically derives separate encryption and MAC keys from a single master key using HKDF.

## Quick Example

```cpp
#include <cryptopp/aes_ctr_hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate a 32-byte master key (AES-256)
    SecByteBlock masterKey(32);
    rng.GenerateBlock(masterKey, masterKey.size());

    // Generate a unique 12-byte IV
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Secret message";
    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];

    // Encrypt
    AES_CTR_HMAC_SHA256::Encryption enc;
    enc.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        iv, sizeof(iv),
        nullptr, 0,  // No AAD
        (const byte*)plaintext.data(), plaintext.size()
    );

    std::cout << "Encrypted " << plaintext.size() << " bytes" << std::endl;

    // Decrypt and verify
    std::string recovered(ciphertext.size(), '\0');
    AES_CTR_HMAC_SHA256::Decryption dec;
    dec.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));

    bool valid = dec.DecryptAndVerify(
        (byte*)recovered.data(), tag, sizeof(tag),
        iv, sizeof(iv),
        nullptr, 0,  // No AAD
        (const byte*)ciphertext.data(), ciphertext.size()
    );

    if (valid) {
        std::cout << "Decrypted: " << recovered << std::endl;
    } else {
        std::cerr << "Authentication failed!" << std::endl;
    }

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use a random 12-byte IV for each encryption (unique per message under the same key)
- Use 32-byte master keys for AES-256 (recommended), or 16/24 bytes for AES-128/192
- Always check the return value of `DecryptAndVerify()`
- Use AAD (additional authenticated data) for data that needs authentication but not encryption

**Avoid:**
- Reusing IVs with the same key (catastrophic for CTR mode)
- Ignoring authentication failures during decryption
- Using this for password-based encryption directly (use Argon2 first to derive the master key)
{{< /callout >}}

## Why AES-CTR-HMAC?

AES-CTR-HMAC provides a compelling alternative to both AES-GCM and manual CBC+HMAC:

| Feature | AES-CTR-HMAC | AES-GCM | AES-CBC+HMAC |
|---------|--------------|---------|--------------|
| Key management | Single master key | Single key | Two separate keys |
| Key derivation | Automatic (HKDF) | None | Manual |
| Parallelisable | Yes (CTR) | Yes | No (CBC) |
| Padding required | No | No | Yes |
| Primitives | AES + HMAC + HKDF | AES + GHASH | AES + HMAC |
| Domain separation | Built-in | None | Manual |

**Choose AES-CTR-HMAC when:**
- You want simpler key management (one master key instead of two)
- You need automatic, secure key derivation with domain separation
- You want CTR mode's parallelism without GCM's nonce-reuse fragility
- You're building a protocol that benefits from HMAC's conservative security margins

**Choose AES-GCM when:**
- Maximum performance is critical (GCM is faster due to GHASH)
- You need strict standards compliance (TLS 1.3, etc.)

## Key Derivation

AES-CTR-HMAC automatically derives separate encryption and MAC keys from your master key using HKDF:

```
Master Key (16/24/32 bytes)
         │
         ▼
    ┌─────────┐
    │  HKDF   │  info = "AES-CTR-HMAC-" + HashName
    └────┬────┘     (e.g. "AES-CTR-HMAC-SHA-256")
         │
    ┌────┴────┐
    ▼         ▼
Encryption   MAC Key
   Key       (hash digest size:
(same size    32 bytes for SHA-256,
as master)    64 bytes for SHA-512)
```

The master key length determines the AES variant:
- 16 bytes → AES-128
- 24 bytes → AES-192
- 32 bytes → AES-256 (recommended)

## IV/Nonce Requirements

- **Fixed 12-byte IV** - Must be unique per message under the same key
- **Counter format:** IV || 0x00000001 (16 bytes total, big-endian)
- Counter starts at 1, reserving block 0

```cpp
// Generate a random IV for each message
AutoSeededRandomPool rng;
byte iv[12];
rng.GenerateBlock(iv, sizeof(iv));

enc.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));
```

{{< callout type="warning" >}}
**Never reuse an IV with the same key.** CTR mode XORs the keystream with plaintext - reusing an IV reveals the XOR of two plaintexts and completely breaks confidentiality.
{{< /callout >}}

## MAC Construction

The HMAC is computed over a structured input for robust security:

```text
HMAC Input:
┌─────────────────────────────────────┐
│ Domain: "AES-CTR-HMAC-" + HashName  │  (ASCII string)
│         e.g. "AES-CTR-HMAC-SHA-256" │
├─────────────────────────────────────┤
│ Separator: 0x00                     │  (1 byte)
├─────────────────────────────────────┤
│ IV                                  │  (12 bytes)
├─────────────────────────────────────┤
│ AAD                                 │  (variable)
├─────────────────────────────────────┤
│ Ciphertext                          │  (variable)
├─────────────────────────────────────┤
│ len(AAD) || len(Ciphertext)         │  (16 bytes, big-endian)
└─────────────────────────────────────┘
```

This construction:
- Prevents cross-protocol attacks via domain separation
- Authenticates the IV to prevent IV manipulation
- Uses length encoding to avoid ambiguity and concatenation attacks on `(AAD, ciphertext)`

## Complete Example: With Additional Authenticated Data

```cpp
#include <cryptopp/aes_ctr_hmac.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate master key and IV
    SecByteBlock masterKey(32);  // AES-256
    byte iv[12];
    rng.GenerateBlock(masterKey, masterKey.size());
    rng.GenerateBlock(iv, sizeof(iv));

    // Message and AAD
    std::string plaintext = "Confidential payload";
    std::string aad = "packet-header:12345";  // Authenticated but not encrypted

    // Encrypt with AAD
    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];

    AES_CTR_HMAC_SHA256::Encryption enc;
    enc.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        iv, sizeof(iv),
        (const byte*)aad.data(), aad.size(),
        (const byte*)plaintext.data(), plaintext.size()
    );

    // Decrypt with AAD verification
    std::string recovered(ciphertext.size(), '\0');

    AES_CTR_HMAC_SHA256::Decryption dec;
    dec.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));

    bool valid = dec.DecryptAndVerify(
        (byte*)recovered.data(), tag, sizeof(tag),
        iv, sizeof(iv),
        (const byte*)aad.data(), aad.size(),  // Must match!
        (const byte*)ciphertext.data(), ciphertext.size()
    );

    if (valid) {
        std::cout << "AAD: " << aad << std::endl;
        std::cout << "Decrypted: " << recovered << std::endl;
    } else {
        std::cerr << "Authentication failed - AAD or ciphertext tampered!" << std::endl;
    }

    return 0;
}
```

## Complete Example: Using Pipeline Filters

```cpp
#include <cryptopp/aes_ctr_hmac.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock masterKey(32);
    byte iv[12];
    rng.GenerateBlock(masterKey, masterKey.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Hello, authenticated encryption!";
    std::string ciphertext;

    // Encrypt using pipeline
    AES_CTR_HMAC_SHA256::Encryption enc;
    enc.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    std::cout << "Ciphertext + tag: " << ciphertext.size() << " bytes" << std::endl;

    // Decrypt using pipeline
    std::string recovered;
    AES_CTR_HMAC_SHA256::Decryption dec;
    dec.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));

    try {
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(recovered)
            )
        );
        std::cout << "Decrypted: " << recovered << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        std::cerr << "Authentication failed: " << e.what() << std::endl;
    }

    return 0;
}
```

## Using SHA-512 for Higher Security Margin

```cpp
#include <cryptopp/aes_ctr_hmac.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    SecByteBlock masterKey(32);
    byte iv[12];
    rng.GenerateBlock(masterKey, masterKey.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "High security message";
    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];  // Still 16-byte tag (truncated from 64-byte HMAC-SHA512)

    // Use SHA-512 variant
    AES_CTR_HMAC_SHA512::Encryption enc;
    enc.SetKeyWithIV(masterKey, masterKey.size(), iv, sizeof(iv));
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        iv, sizeof(iv),
        nullptr, 0,
        (const byte*)plaintext.data(), plaintext.size()
    );

    return 0;
}
```

## Class Reference

### Type Aliases

```cpp
// SHA-256 variant (recommended)
typedef AES_CTR_HMAC<AES, SHA256> AES_CTR_HMAC_SHA256;

// SHA-512 variant (higher security margin)
typedef AES_CTR_HMAC<AES, SHA512> AES_CTR_HMAC_SHA512;
```

### AES_CTR_HMAC<>::Encryption

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set the master key and IV. The master key is expanded via HKDF into separate encryption and MAC keys.

**Parameters:**
- `key` - Master key (16, 24, or 32 bytes)
- `keyLength` - Length of master key
- `iv` - Initialization vector (must be 12 bytes)
- `ivLength` - Length of IV (must be 12)

#### EncryptAndAuthenticate()

```cpp
void EncryptAndAuthenticate(byte* ciphertext, byte* mac, size_t macSize,
                            const byte* iv, int ivLength,
                            const byte* aad, size_t aadLength,
                            const byte* message, size_t messageLength);
```

One-shot encryption with authentication.

**Parameters:**
- `ciphertext` - Output buffer (same size as message)
- `mac` - Output authentication tag
- `macSize` - Size of MAC output. The default (and `TagSize()`) is 16 bytes. Values must be between 1 and the hash digest size (32 for SHA-256, 64 for SHA-512); larger values throw `InvalidArgument`
- `iv` - Initialization vector (12 bytes)
- `ivLength` - IV length
- `aad` - Additional authenticated data (can be NULL)
- `aadLength` - AAD length
- `message` - Plaintext to encrypt
- `messageLength` - Plaintext length

### AES_CTR_HMAC<>::Decryption

#### DecryptAndVerify()

```cpp
bool DecryptAndVerify(byte* message, const byte* mac, size_t macSize,
                      const byte* iv, int ivLength,
                      const byte* aad, size_t aadLength,
                      const byte* ciphertext, size_t ciphertextLength);
```

One-shot decryption with authentication verification.

**Returns:** `true` if authentication succeeded, `false` if verification failed.

**Important:** Always check the return value. If `false`, the message has been tampered with and the output should be discarded.

## Size Accessors

The following methods return size information:

**Key sizes (determined by master key length):**
- `MinKeyLength()` returns 16 (AES-128)
- `MaxKeyLength()` returns 32 (AES-256)
- `DefaultKeyLength()` returns 16

**IV size (fixed):**
- `IVSize()` returns 12

**Tag size:**
- `TagSize()` returns 16 by default
- You can request a different size (up to the hash digest size) via `EncryptAndAuthenticate` / `DecryptAndVerify` / the filters

## Performance

| Configuration | Approx. Speed | Notes |
|---------------|---------------|-------|
| AES-256-CTR-HMAC-SHA256 (AES-NI) | ~800 MB/s | Combined encryption + MAC |
| AES-128-CTR-HMAC-SHA256 (AES-NI) | ~900 MB/s | Faster key schedule |
| AES-256-CTR-HMAC-SHA512 | ~600 MB/s | Larger MAC computation |

*Measured on a modern x86-64 CPU with AES-NI; actual performance will vary by CPU and compiler.*

**Note:** AES-GCM is faster (~2000+ MB/s) because GHASH is more efficient than HMAC. Choose AES-CTR-HMAC for its security margins and key derivation features, not raw speed.

## Security

### Quick Summary

| Aspect | Value |
|--------|-------|
| Key derivation | HKDF with domain separation |
| Encryption | AES-CTR (128/192/256-bit) |
| Authentication | HMAC-SHA256 or HMAC-SHA512 |
| IV size | 96 bits (12 bytes) |
| Tag size | 128 bits default (configurable up to hash digest size) |
| Construction | Encrypt-then-MAC |

### Security Properties

- **Confidentiality:** Provided by AES-CTR with derived encryption key
- **Authenticity:** Provided by HMAC over domain string, IV, AAD, ciphertext, and lengths
- **Key separation:** HKDF ensures encryption and MAC keys are cryptographically independent
- **Domain separation:** Hash algorithm name included in HKDF info and MAC input
- **Length encoding:** Avoids ambiguity and concatenation attacks on `(AAD, ciphertext)`

### Comparison with AES-GCM

| Property | AES-CTR-HMAC | AES-GCM |
|----------|--------------|---------|
| Nonce reuse impact | Confidentiality loss | Confidentiality + authenticity loss |
| Security margin | Conservative (HMAC) | Tighter (GHASH) |
| Key separation | Built-in (HKDF splits enc + MAC keys) | Requires external KDF if deriving from master key |
| Speed | Slower | Faster |

AES-CTR-HMAC is more robust to implementation errors and has larger security margins, at the cost of performance.

## Thread Safety

**Not thread-safe.** Create separate `Encryption` and `Decryption` objects for each thread.

```cpp
// WRONG - sharing between threads
AES_CTR_HMAC_SHA256::Encryption shared_enc;

// CORRECT - one per thread
void threadFunc() {
    AES_CTR_HMAC_SHA256::Encryption enc;  // Thread-local
    // ... use enc ...
}
```

## Exceptions

- `InvalidKeyLength` - Master key size is not 16, 24, or 32 bytes
- `InvalidArgument` - IV length is not 12 bytes, or `macSize` exceeds the hash digest size
- `HashVerificationFilter::HashVerificationFailed` - Authentication tag verification failed (when using filters)

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Faster AEAD (recommended for most uses)
- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Legacy Encrypt-then-MAC
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative AEAD
- [HKDF](/docs/api/kdf/hkdf/) - Key derivation function used internally
- [HMAC](/docs/api/mac/hmac/) - Message authentication code used internally
