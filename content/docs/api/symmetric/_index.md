---
title: Symmetric Encryption
description: API reference for symmetric encryption algorithms
weight: 3
---

Symmetric encryption algorithms, focusing on authenticated encryption (AEAD) modes.

## Authenticated Encryption (AEAD)

Provides both confidentiality AND authenticity. **Always use these for encryption.**

### [AES-GCM](/docs/api/symmetric/aes-gcm/) ⭐ Recommended
Advanced Encryption Standard with Galois/Counter Mode
- Industry standard authenticated encryption
- Hardware accelerated (AES-NI, ARM Crypto)
- Fast parallel encryption/decryption
- 128, 192, or 256-bit keys

**Use AES-GCM for:**
- File encryption (with careful nonce management)
- Network protocol encryption (TLS, IPsec)
- Database encryption
- Any scenario requiring both encryption and authentication

### [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/)
Modern authenticated encryption alternative
- Excellent for systems without AES hardware acceleration
- Constant-time (resistant to timing attacks)
- 256-bit keys only
- Used in TLS 1.3, WireGuard, Signal

### [XChaCha20-Poly1305](/docs/api/symmetric/xchacha20-poly1305/)
Extended nonce variant of ChaCha20-Poly1305
- 24-byte nonce with negligible collision risk
- Safe to use random nonces
- Ideal for file encryption and at-rest data
- No counter tracking required

### [AES-CCM](/docs/api/symmetric/aes-ccm/)
Counter with CBC-MAC mode
- Used in Wi-Fi (WPA2/WPA3 CCMP-128), Bluetooth, Zigbee, and TLS
- Two-pass mode (slower than GCM)
- Requires pre-specified data lengths
- Variable nonce size (7-13 bytes)

### [AES-EAX](/docs/api/symmetric/aes-eax/)
EAX authenticated encryption mode
- Simple, well-analyzed construction
- Built from CTR mode + CMAC
- Flexible nonce length (any size)
- Good choice when GCM hardware unavailable

## Low-Level Primitives

**Warning:** These are building blocks. Use AEAD modes above instead.

AES, ChaCha20, Twofish, and other block/stream ciphers are available as raw primitives, but you should almost always use the AEAD modes above.

- [Twofish](/docs/api/symmetric/twofish/) - AES finalist block cipher (128-bit block, 128/192/256-bit keys)

## Legacy Modes (Require Separate MAC)

**Warning:** These modes don't provide authentication. Prefer AEAD modes like GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, EAX, or CCM instead.

- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Legacy Encrypt-then-MAC
- [AES-CTR](/docs/api/symmetric/aes-ctr/) - Counter mode
- [AES-CBC](/docs/api/symmetric/aes-cbc/) - Cipher Block Chaining

Don't use ECB mode; it's insecure and not recommended.

## Quick Comparison

| Mode/Cipher | Authentication | Parallel | Hardware Accel | Recommended |
|-------------|---------------|----------|----------------|-------------|
| **AES-GCM** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐ Primary choice |
| ChaCha20-Poly1305 | ✅ Yes | ✅ Yes | ❌ No | Software systems |
| XChaCha20-Poly1305 | ✅ Yes | ✅ Yes | ❌ No | Random nonces |
| AES-CCM | ✅ Yes | Limited | ✅ Yes | Wi-Fi, Bluetooth, TLS |
| AES-EAX | ✅ Yes | Partial | ✅ Yes | Simple AEAD |
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

## Security Best Practices

1. **Always use authenticated encryption** (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, EAX, CCM)
2. **Never reuse IVs** with the same key
3. **Generate random IVs** using `AutoSeededRandomPool`
4. **Use 256-bit keys** for new systems (future-proof)
5. **Verify authentication tags** - failed verification = tampered data
6. **Store IVs with ciphertext** (IVs don't need to be secret)
7. **Use `SecByteBlock`** for keys (auto-zeroing memory)

## Performance Notes

On modern x86 with AES-NI, AES-GCM is typically about 2× faster than CCM/EAX, and ChaCha20-Poly1305 is competitive when AES-NI isn't available.

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
    // "AESNI"      - Intel/AMD x86-64 with AES-NI
    // "ARMv8"      - ARM with Crypto Extensions
    // "POWER8"     - IBM POWER8+ with AES
    // "C++"        - Software implementation
}
```

## See Also

- [Symmetric Encryption Guide](/docs/guides/symmetric-encryption/) - Conceptual overview
- [Security Concepts](/docs/guides/security-concepts/) - Understanding cryptography
- [Algorithm Reference](/docs/algorithms/reference/) - All supported algorithms
- [Message Authentication](/docs/api/mac/) - MAC algorithms (HMAC, etc.)
