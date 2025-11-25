---
title: Symmetric Encryption
description: API reference for symmetric encryption algorithms
weight: 3
---

Symmetric encryption algorithms for encrypting data with authenticated encryption (AEAD) modes.

## Authenticated Encryption (AEAD)

Provides both confidentiality AND authenticity. **Always use these for encryption.**

### [AES-GCM](/docs/api/symmetric/aes-gcm/) ⭐ Recommended
Advanced Encryption Standard with Galois/Counter Mode
- Industry standard authenticated encryption
- Hardware accelerated (AES-NI, ARM Crypto)
- Fast parallel encryption/decryption
- 128, 192, or 256-bit keys

**Use AES-GCM for:**
- File encryption
- Network protocol encryption (TLS, IPsec)
- Database encryption
- Any scenario requiring both encryption and authentication

### ChaCha20-Poly1305 (coming soon)
Modern authenticated encryption alternative
- Excellent for systems without AES hardware acceleration
- Constant-time (resistant to timing attacks)
- 256-bit keys only
- Used in TLS 1.3, WireGuard, Signal

## Block Ciphers (Low-Level)

**Warning:** These are building blocks. Use AEAD modes above instead.

### AES (coming soon)
Advanced Encryption Standard
- FIPS 197 approved
- Block size: 128 bits
- Key sizes: 128, 192, 256 bits
- Hardware acceleration available

### ChaCha20 (coming soon)
Stream cipher
- 256-bit keys
- Fast in software
- No timing side channels

## Block Cipher Modes

**Warning:** Most modes don't provide authentication. Use GCM or CCM instead.

### GCM (Galois/Counter Mode) - See AES-GCM above ⭐
Authenticated encryption mode
- Provides encryption + authentication
- Parallelizable
- Industry standard

### CBC (Cipher Block Chaining) (coming soon)
Legacy encryption mode
- **Requires separate MAC (use HMAC)**
- Padding oracle vulnerabilities possible
- Not parallelizable
- Avoid for new systems

### CTR (Counter Mode) (coming soon)
Stream cipher mode
- **Requires separate MAC (use HMAC)**
- Parallelizable
- Random access to encrypted data

### CCM (Counter with CBC-MAC) (coming soon)
Authenticated encryption mode
- Provides encryption + authentication
- Alternative to GCM
- Not parallelizable (slower)

### ECB (Electronic Codebook) ⚠️ NEVER USE
**Insecure:** Identical plaintexts produce identical ciphertexts
- Not provided by library (intentionally)
- Reveals patterns in data
- No IV/nonce

## Quick Comparison

| Mode/Cipher | Authentication | Parallel | Hardware Accel | Recommended |
|-------------|---------------|----------|----------------|-------------|
| **AES-GCM** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐ Primary choice |
| ChaCha20-Poly1305 | ✅ Yes | ✅ Yes | ❌ No | Software systems |
| AES-CCM | ✅ Yes | ❌ No | ✅ Yes | Constrained devices |
| AES-CBC | ❌ No | ❌ No | ✅ Yes | Legacy only |
| AES-CTR | ❌ No | ✅ Yes | ✅ Yes | With HMAC only |

## Choosing an Algorithm

### For New Systems
1. **AES-GCM** (primary recommendation)
   - Hardware acceleration available on target platform
   - Need maximum performance
   - Industry standard compliance required

2. **ChaCha20-Poly1305** (alternative)
   - No AES hardware acceleration
   - Mobile/embedded platforms
   - Constant-time implementation preferred

### For Legacy Systems
- **Upgrading from AES-CBC:** Migrate to AES-GCM
- **Upgrading from AES-CTR+HMAC:** Migrate to AES-GCM
- **Cannot change:** Add HMAC authentication if not present

## Common Interface

All authenticated encryption modes implement the `AuthenticatedSymmetricCipher` interface:

```cpp
class AuthenticatedSymmetricCipher {
public:
    // Set key and IV
    void SetKeyWithIV(const byte* key, size_t keyLength,
                      const byte* iv, size_t ivLength);

    // One-shot encryption
    void EncryptAndAuthenticate(
        byte* ciphertext, byte* mac, size_t macSize,
        const byte* iv, int ivLength,
        const byte* aad, size_t aadLength,
        const byte* message, size_t messageLength);

    // One-shot decryption
    bool DecryptAndVerify(
        byte* message,
        const byte* mac, size_t macSize,
        const byte* iv, int ivLength,
        const byte* aad, size_t aadLength,
        const byte* ciphertext, size_t ciphertextLength);

    // Query methods
    unsigned int DigestSize() const;  // MAC tag size
    unsigned int IVSize() const;       // IV size
    size_t MinKeyLength() const;
    size_t MaxKeyLength() const;
};
```

## Security Best Practices

1. **Always use authenticated encryption** (GCM, CCM, ChaCha20-Poly1305)
2. **Never reuse IVs** with the same key
3. **Generate random IVs** using `AutoSeededRandomPool`
4. **Use 256-bit keys** for new systems (future-proof)
5. **Verify authentication tags** - failed verification = tampered data
6. **Store IVs with ciphertext** (IVs don't need to be secret)
7. **Use `SecByteBlock`** for keys (auto-zeroing memory)

## Performance Notes

### Hardware Acceleration Detection

```cpp
#include <cryptopp/aes.h>
#include <iostream>

void checkHardwareSupport() {
    using namespace CryptoPP;

    std::cout << "AES Provider: "
              << AES::Encryption().AlgorithmProvider()
              << std::endl;

    // Output examples:
    // "AES-NI"     - Intel/AMD x86-64 with AES-NI
    // "ARMv8"      - ARM with Crypto Extensions
    // "POWER8"     - IBM POWER8+ with AES
    // "C++"        - Software implementation
}
```

### Typical Performance (with AES-NI)

| Operation | Speed (GB/s) | Notes |
|-----------|--------------|-------|
| AES-128-GCM | 2-4 | Encryption + authentication |
| AES-256-GCM | 1.5-3 | Slightly slower than AES-128 |
| ChaCha20-Poly1305 | 1-2 | Software implementation |

## See Also

- [Symmetric Encryption Guide](/docs/guides/symmetric-encryption/) - Conceptual overview
- [Security Concepts](/docs/guides/security-concepts/) - Understanding cryptography
- [Algorithm Reference](/docs/algorithms/reference/) - All supported algorithms
- [Message Authentication](/docs/api/mac/) - MAC algorithms (HMAC, etc.)
