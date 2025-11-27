---
title: Algorithm Reference
weight: 10
description: "Complete reference of all cryptographic algorithms supported by cryptopp-modern including hash functions, symmetric encryption, public-key cryptography, MACs, and KDFs."
---

This page provides a comprehensive reference of all cryptographic algorithms available in cryptopp-modern.

## Hash Functions

### Modern (Recommended)

| Algorithm | Output Size | Speed | Security | Use Case |
|-----------|-------------|-------|----------|----------|
| **BLAKE3** | 256-bit (variable) | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | General purpose, file integrity, content addressing |
| **SHA-256** | 256-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | FIPS compliance, general purpose |
| **SHA-512** | 512-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High security, 64-bit systems |
| **SHA3-256** | 256-bit | ⭐⭐ | ⭐⭐⭐⭐⭐ | NIST standard, alternative to SHA-2 |
| **SHA3-512** | 512-bit | ⭐⭐ | ⭐⭐⭐⭐⭐ | High security NIST standard |
| **BLAKE2b** | 512-bit (variable) | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High performance alternative to SHA-2 |
| **BLAKE2s** | 256-bit (variable) | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Optimized for 32-bit systems |

### Legacy (Compatibility Only)

| Algorithm | Output Size | Status | Notes |
|-----------|-------------|--------|-------|
| **SHA-1** | 160-bit | ⚠️ Deprecated | Use only for legacy compatibility |
| **MD5** | 128-bit | ❌ Broken | Non-cryptographic purposes only |
| **RIPEMD-160** | 160-bit | ⚠️ Legacy | Bitcoin compatibility |
| **Tiger** | 192-bit | ⚠️ Legacy | Rare use cases |
| **Whirlpool** | 512-bit | ⚠️ Legacy | Superseded by SHA-3 |

**Header files:** `blake3.h`, `sha.h`, `sha3.h`, `blake2.h`, `md5.h`, `ripemd.h`, `tiger.h`, `whirlpool.h`

---

## Password Hashing & Key Derivation

### Password Hashing

| Algorithm | Memory-Hard | Time Cost | Use Case |
|-----------|-------------|-----------|----------|
| **Argon2id** | ✅ Yes | Tunable | Password hashing (recommended) |
| **Argon2i** | ✅ Yes | Tunable | Side-channel resistance |
| **Argon2d** | ✅ Yes | Tunable | Maximum GPU resistance |
| **Scrypt** | ✅ Yes | Fixed | Legacy password hashing |
| **PBKDF2** | ❌ No | Tunable | Legacy systems, NIST compliance |

### Key Derivation Functions (KDF)

| Algorithm | Type | Use Case |
|-----------|------|----------|
| **HKDF** | Extract-and-expand | Key derivation from shared secrets |
| **PBKDF2** | Iterative | Legacy key derivation, PKCS #5 |
| **Scrypt** | Memory-hard | Alternative to Argon2 |

**Header files:** `argon2.h`, `scrypt.h`, `pwdbased.h`, `hkdf.h`

---

## Symmetric Encryption

### Block Ciphers

| Cipher | Key Sizes | Block Size | Speed | Security | Use Case |
|--------|-----------|------------|-------|----------|----------|
| **AES** | 128, 192, 256-bit | 128-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Industry standard, FIPS approved |
| **ChaCha20** | 256-bit | Stream | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Modern stream cipher, mobile-optimized |
| **Serpent** | 128, 192, 256-bit | 128-bit | ⭐⭐ | ⭐⭐⭐⭐⭐ | High security margin |
| **Twofish** | 128, 192, 256-bit | 128-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | AES finalist |
| **Camellia** | 128, 192, 256-bit | 128-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ISO/IEC 18033-3 standard |
| **ARIA** | 128, 192, 256-bit | 128-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Korean standard (RFC 5794) |

### Authenticated Encryption Modes (Recommended)

| Mode | Authentication | Use Case |
|------|----------------|----------|
| **GCM** | Built-in | Fast authenticated encryption (AES-GCM, recommended) |
| **CCM** | Built-in | Constrained environments |
| **EAX** | Built-in | Simple authenticated encryption |
| **ChaCha20-Poly1305** | Built-in | Modern AEAD, mobile-optimized |

### Classical Modes (Require Separate MAC)

| Mode | Type | Use Case |
|------|------|----------|
| **CBC** | Block | Traditional encryption (use with HMAC) |
| **CTR** | Stream | Parallelizable encryption |
| **CFB** | Stream | Self-synchronizing stream cipher |
| **OFB** | Stream | Stream cipher mode |
| **ECB** | Block | ⚠️ Insecure - do not use |

**Header files:** `aes.h`, `chacha.h`, `serpent.h`, `twofish.h`, `camellia.h`, `aria.h`, `modes.h`, `gcm.h`, `ccm.h`, `eax.h`, `chachapoly.h`

---

## Public-Key Cryptography

### Digital Signatures

| Algorithm | Key Size | Speed | Security | Use Case |
|-----------|----------|-------|----------|----------|
| **Ed25519** | 256-bit | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Modern signatures (recommended) |
| **ECDSA (P-256)** | 256-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | NIST standard, wide compatibility |
| **ECDSA (P-384)** | 384-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High security NIST standard |
| **ECDSA (P-521)** | 521-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Maximum security NIST curve |
| **RSA (2048-bit)** | 2048-bit | ⭐⭐ | ⭐⭐⭐⭐ | Legacy compatibility |
| **RSA (3072-bit)** | 3072-bit | ⭐ | ⭐⭐⭐⭐⭐ | Long-term security |
| **RSA (4096-bit)** | 4096-bit | ⭐ | ⭐⭐⭐⭐⭐ | Maximum RSA security |
| **DSA** | 1024-3072-bit | ⭐⭐ | ⭐⭐⭐ | Legacy FIPS 186 |

### Key Exchange

| Algorithm | Key Size | Speed | Security | Use Case |
|-----------|----------|-------|----------|----------|
| **X25519** | 256-bit | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Modern key exchange (recommended) |
| **ECDH (P-256)** | 256-bit | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | NIST standard key exchange |
| **ECDH (P-384)** | 384-bit | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | High security key exchange |
| **DH (2048-bit)** | 2048-bit | ⭐⭐ | ⭐⭐⭐⭐ | Traditional Diffie-Hellman |

### Public-Key Encryption

| Algorithm | Key Size | Use Case |
|-----------|----------|----------|
| **RSA-OAEP** | 2048-4096-bit | Legacy public-key encryption |
| **ECIES** | Variable | Elliptic curve integrated encryption |

**Header files:** `xed25519.h`, `eccrypto.h`, `rsa.h`, `dsa.h`

---

## Message Authentication Codes (MAC)

| Algorithm | Output Size | Speed | Use Case |
|-----------|-------------|-------|----------|
| **HMAC-SHA256** | 256-bit | ⭐⭐⭐⭐ | General purpose MAC |
| **HMAC-SHA512** | 512-bit | ⭐⭐⭐⭐ | High security MAC |
| **HMAC-BLAKE3** | 256-bit | ⭐⭐⭐⭐⭐ | Fastest MAC |
| **CMAC-AES** | 128-bit | ⭐⭐⭐⭐ | Block cipher-based MAC |
| **Poly1305** | 128-bit | ⭐⭐⭐⭐⭐ | Fast one-time MAC (use with ChaCha20) |
| **GMAC** | 128-bit | ⭐⭐⭐⭐ | GCM authentication only |
| **SipHash** | 64-bit | ⭐⭐⭐⭐⭐ | Cryptographic MAC for hash-table keys / short messages |

**Header files:** `hmac.h`, `cmac.h`, `poly1305.h`, `siphash.h`

---

## Elliptic Curves

### Modern Curves (Recommended)

| Curve | Type | Security Level | Use Case |
|-------|------|----------------|----------|
| **Curve25519** | Montgomery | 128-bit | X25519 key exchange |
| **Ed25519** | Edwards | 128-bit | Ed25519 signatures |

### NIST Curves

| Curve | Type | Security Level | Use Case |
|-------|------|----------------|----------|
| **P-256 (secp256r1)** | Weierstrass | 128-bit | NIST standard, wide support |
| **P-384 (secp384r1)** | Weierstrass | 192-bit | High security applications |
| **P-521 (secp521r1)** | Weierstrass | 256-bit | Maximum NIST security |

### Other Curves

| Curve | Type | Notes |
|-------|------|-------|
| **secp256k1** | Weierstrass | Bitcoin, Ethereum |
| **brainpoolP256r1** | Weierstrass | European standard |
| **brainpoolP384r1** | Weierstrass | European high security |
| **brainpoolP512r1** | Weierstrass | European maximum security |

**Header files:** `xed25519.h`, `eccrypto.h`, `asn.h` (for curve OIDs)

---

## Random Number Generators

| Generator | Type | Use Case |
|-----------|------|----------|
| **AutoSeededRandomPool** | CSPRNG | General purpose (recommended) |
| **OS_GenerateRandomBlock** | OS entropy | Direct OS random source |
| **RDRAND** | Hardware | Intel/AMD RDRAND instruction |
| **RDSEED** | Hardware | Intel/AMD RDSEED instruction |
| **RandomPool** | CSPRNG | Manual seeding |
| **LC_RNG** | Deterministic | Testing only (not cryptographically secure) |

**Header files:** `osrng.h`, `randpool.h`

---

## Encoding & Utilities

### Encoders

| Encoder | Use Case |
|---------|----------|
| **HexEncoder** | Hexadecimal encoding |
| **Base64Encoder** | Base64 encoding |
| **Base32Encoder** | Base32 encoding |

### Compression

| Algorithm | Type |
|-----------|------|
| **Gzip** | Deflate compression |
| **Zlib** | Zlib compression |

**Header files:** `hex.h`, `base64.h`, `base32.h`, `gzip.h`, `zlib.h`

---

## Algorithm Selection Guide

### By Use Case

**I need to hash data (file integrity, checksums):**
- Modern projects: **BLAKE3**
- FIPS compliance: **SHA-256** or **SHA-512**
- Legacy compatibility: **SHA-1** (deprecated)

**I need to hash passwords:**
- Modern projects: **Argon2id**
- Legacy systems: **PBKDF2** or **Scrypt**

**I need to encrypt data:**
- Modern projects: **AES-GCM** or **ChaCha20-Poly1305**
- Mobile/embedded: **ChaCha20-Poly1305**
- FIPS compliance: **AES-GCM**

**I need digital signatures:**
- Modern projects: **Ed25519**
- NIST compliance: **ECDSA (P-256)**
- Legacy systems: **RSA (2048-bit minimum)**

**I need key exchange:**
- Modern projects: **X25519**
- NIST compliance: **ECDH (P-256)**
- Legacy systems: **DH (2048-bit minimum)**

**I need message authentication:**
- General purpose: **HMAC-SHA256**
- Maximum speed: **HMAC-BLAKE3**
- Block cipher-based: **CMAC-AES**

---

## Security Levels

### Key Size Equivalents

| Symmetric | Hash | RSA | ECC | Security Level |
|-----------|------|-----|-----|----------------|
| 128-bit | 256-bit | 3072-bit | 256-bit | Standard |
| 192-bit | 384-bit | 7680-bit | 384-bit | High |
| 256-bit | 512-bit | 15360-bit | 521-bit | Maximum |

### Recommended Minimum Sizes (2025)

- **Symmetric encryption:** 128-bit (AES-128)
- **Hash functions:** 256-bit (SHA-256, BLAKE3)
- **RSA:** 2048-bit (3072-bit for long-term)
- **Elliptic curves:** 256-bit (P-256, Curve25519)
- **Diffie-Hellman:** 2048-bit

---

## Standards Compliance

### FIPS 140-2/140-3

Approved algorithms:
- AES (all key sizes)
- SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512)
- SHA-3 family
- RSA (2048-bit minimum)
- ECDSA (P-256, P-384, P-521)
- HMAC (with approved hash functions)

**Note:** cryptopp-modern implements these algorithms, but cryptopp-modern itself is **not** a FIPS 140-validated module.

### NIST Recommendations

- **Hash:** SHA-256, SHA-384, SHA-512, SHA-3
- **Symmetric:** AES-128, AES-256
- **Signatures:** ECDSA (P-256+), RSA (2048-bit+)
- **Key Exchange:** ECDH (P-256+)

### RFC Standards

- **Argon2:** RFC 9106
- **ChaCha20-Poly1305:** RFC 7539
- **Ed25519:** RFC 8032
- **X25519:** RFC 7748
- **HMAC:** RFC 2104
- **HKDF:** RFC 5869
- **ARIA:** RFC 5794

---

## Deprecated Algorithms

**Do not use for new projects:**

| Algorithm | Status | Reason |
|-----------|--------|--------|
| **DES** | ❌ Broken | 56-bit key too small |
| **3DES** | ⚠️ Deprecated | Slow, small block size |
| **RC4** | ❌ Broken | Multiple vulnerabilities |
| **MD5** | ❌ Broken | Collision attacks |
| **SHA-1** | ⚠️ Deprecated | Collision attacks |
| **DSA (1024-bit)** | ❌ Insecure | Key size too small |
| **RSA (1024-bit)** | ❌ Insecure | Key size too small |

---

## Quick Reference

**Most common combinations:**

```cpp
// File hashing
BLAKE3 or SHA-256

// Password storage
Argon2id

// Symmetric encryption
AES-256-GCM or ChaCha20-Poly1305

// Digital signatures
Ed25519 or ECDSA-P256

// Key exchange
X25519 or ECDH-P256

// Message authentication
HMAC-SHA256 or HMAC-BLAKE3
```

---

## Documentation Links

- [Hash Functions](hashing) - Detailed hash function guide
- [BLAKE3](blake3) - BLAKE3 documentation
- [Argon2](argon2) - Password hashing guide
- [Symmetric Encryption](symmetric) - AES, ChaCha20 guide
- [Public-Key Cryptography](public-key) - RSA, ECDSA, Ed25519, X25519
- [Security Concepts](../guides/security-concepts) - Security best practices
- [Beginner's Guide](../guides/beginners-guide) - Complete tutorial

---

## Platform Support

All algorithms are supported on:
- **Windows:** Visual Studio 2010+, MinGW
- **Linux:** GCC 4.8+, Clang 3.4+
- **macOS:** Xcode Command Line Tools
- **Architectures:** x86, x86_64, ARM, ARM64, RISC-V

Hardware acceleration available for:
- AES (AES-NI on x86/x64)
- SHA-256 (SHA extensions)
- ChaCha20 (SSSE3, AVX2)
- Curve25519 (AVX2, AVX-512)
