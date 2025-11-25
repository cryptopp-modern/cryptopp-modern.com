---
title: Security Levels Explained
description: Understanding cryptographic security levels and what they mean
weight: 30
---

## What is a "Security Level"?

A cryptographic algorithm's **security level** (in bits) represents the computational effort needed to break it. A 128-bit security level means an attacker needs approximately 2^128 operations to break the algorithm through brute force.

## Common Security Levels

### **128-bit Security**

**Computational effort:** 2^128 ≈ 340 undecillion operations

**What this means:**
- Impossible to break with current or foreseeable technology
- Would take all computers on Earth billions of years
- Considered secure for the foreseeable future

**Examples:**
- AES-128
- SHA-256 (preimage resistance)
- BLAKE3 (preimage resistance)
- ChaCha20

### **256-bit Security**

**Computational effort:** 2^256 operations

**What this means:**
- Vastly more secure than 128-bit
- Far beyond any conceivable computing power
- Often used for collision resistance in hash functions

**Examples:**
- AES-256
- SHA-256 (collision resistance)
- BLAKE3 (collision resistance)
- Ed25519 (equivalent to ~128-bit symmetric due to curve structure)

## Hash Function Security

Hash functions provide **two types** of security:

### **Collision Resistance**

**Definition:** How hard it is to find two different inputs that hash to the same output.

**Security level:** For an n-bit hash, collision resistance is n-bit (e.g., SHA-256 provides 256-bit collision resistance).

**Why it matters:** Needed for digital signatures, certificates, and integrity checking.

### **Preimage Resistance**

**Definition:** How hard it is to find an input that hashes to a specific output.

**Security level:** For an n-bit hash, preimage resistance is typically n/2-bit due to birthday attack.

**Why it matters:** Prevents reversing hashes to recover original data.

### Example: SHA-256

- **Collision resistance:** 256-bit security
- **Preimage resistance:** 128-bit security (birthday paradox)

This is why SHA-256 is considered "128-bit secure" for most practical purposes.

## Post-Quantum Security

**Classical computers:** Security levels as described above.

**Quantum computers (Grover's algorithm):**
- **Reduces effective security by half**
- 256-bit symmetric → 128-bit quantum resistance
- 128-bit symmetric → 64-bit quantum resistance (considered weak)

**Examples:**
- AES-256 → 128-bit post-quantum security (adequate)
- AES-128 → 64-bit post-quantum security (weak, use AES-256 instead)
- SHA-256 → 128-bit post-quantum preimage resistance (adequate)
- BLAKE3 → 128-bit post-quantum preimage resistance (adequate)

**Note:** Public-key algorithms (RSA, ECDSA) are completely broken by Shor's algorithm on quantum computers. Use post-quantum algorithms like Kyber, Dilithium instead.

## Key Size vs Security Level

Symmetric encryption, hash functions, and public-key cryptography have different relationships between key size and security level:

### Symmetric Ciphers (AES, ChaCha20)

**Key size = Security level**

- 128-bit key → 128-bit security
- 256-bit key → 256-bit security

### Hash Functions (SHA-256, BLAKE3)

**Collision resistance = output size**
**Preimage resistance = output size / 2**

- SHA-256: 256-bit collision, 128-bit preimage
- BLAKE3: 256-bit collision, 128-bit preimage

### Public-Key Cryptography

**Much larger keys needed for same security:**

| Security Level | RSA Key Size | ECC Key Size | Symmetric Equivalent |
|----------------|--------------|--------------|----------------------|
| 80-bit | 1024-bit | 160-bit | DES (weak) |
| 112-bit | 2048-bit | 224-bit | 3DES |
| 128-bit | 3072-bit | 256-bit | AES-128 |
| 192-bit | 7680-bit | 384-bit | AES-192 |
| 256-bit | 15360-bit | 521-bit | AES-256 |

This is why Ed25519 (256-bit key) provides ~128-bit security, not 256-bit.

## Practical Recommendations

### For Long-Term Security (10+ years)

- **Symmetric encryption:** AES-256, ChaCha20 (256-bit keys)
- **Hashing:** SHA-256, SHA-512, BLAKE3
- **Password hashing:** Argon2id with strong parameters
- **Signatures:** Ed25519 (or post-quantum when standardized)
- **Key exchange:** X25519 (or post-quantum when standardized)

### For Current Security (5-10 years)

- **Symmetric encryption:** AES-128, ChaCha20 (128-bit keys)
- **Hashing:** SHA-256, BLAKE3
- **Password hashing:** Argon2id
- **Signatures:** Ed25519, ECDSA P-256
- **Key exchange:** X25519, ECDH P-256

### Avoid These (Broken or Weak)

- ❌ DES, 3DES (too weak)
- ❌ MD5, SHA-1 (collision attacks exist)
- ❌ RSA-1024 (too weak, broken by factoring)
- ❌ Plain hashing for passwords (use Argon2 instead)

## How We Measure

**Bits of security** is measured logarithmically:

- **80-bit:** Breakable with significant resources (nation-states)
- **112-bit:** Difficult but theoretically feasible in the future
- **128-bit:** Secure for foreseeable future with classical computers
- **256-bit:** Massive overkill for symmetric crypto, appropriate for hash collision resistance

**Quantum resistance:**
- **64-bit quantum:** Weak (avoid)
- **128-bit quantum:** Adequate for most uses
- **256-bit quantum:** Very strong

## See Also

- [Security Concepts](/docs/guides/security-concepts/) - Practical security guidance
- [Algorithm Reference](/docs/algorithms/reference/) - Security levels of all algorithms
- [BLAKE3](/docs/api/hash/BLAKE3/) - 256-bit collision, 128-bit preimage
- [Argon2](/docs/algorithms/argon2/) - Password hashing security
- [Ed25519](/docs/algorithms/public-key/#ed25519) - ~128-bit signature security
