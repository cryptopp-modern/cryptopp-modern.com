---
title: Hash Functions
description: API reference for cryptographic hash functions
weight: 1
---

Cryptographic hash functions for data integrity, digital signatures, and content addressing.

## Available Hash Functions

### [BLAKE3](/docs/api/hash/blake3/)
**Recommended** - Fastest modern hash function
- 256-bit security
- Parallel hashing support
- Extendable output
- Keyed hashing (MAC mode)
- Key derivation (KDF mode)

### SHA-256 (coming soon)
Standard hash function, widely supported
- 256-bit security
- FIPS 180-4 compliant
- Hardware acceleration (SHA-NI)

### SHA-512 (coming soon)
Large output hash function
- 512-bit output
- 256-bit security
- Faster than SHA-256 on 64-bit systems

### SHA-3 (coming soon)
NIST standard based on Keccak
- Multiple output sizes (224, 256, 384, 512)
- Different construction than SHA-2
- FIPS 202 compliant

## Common Interface

All hash functions share a common interface:

```cpp
class HashFunction {
public:
    // Get algorithm name
    std::string AlgorithmName() const;

    // Get digest size
    unsigned int DigestSize() const;

    // Update hash with data
    void Update(const byte* input, size_t length);

    // Finalize and get result
    void TruncatedFinal(byte* digest, size_t digestSize);

    // Reset to initial state
    void Restart();
};
```

## Quick Reference

| Algorithm | Output Size | Security | Speed | Status |
|-----------|-------------|----------|-------|--------|
| BLAKE3 | 32 bytes (extendable) | 256-bit | ⚡⚡⚡⚡⚡ | Recommended |
| SHA-256 | 32 bytes | 256-bit | ⚡⚡⚡⚡ | Standard |
| SHA-512 | 64 bytes | 256-bit | ⚡⚡⚡⚡ | Standard |
| SHA-3-256 | 32 bytes | 256-bit | ⚡⚡⚡ | Standard |

## See Also

- [Hash Functions Guide](/docs/algorithms/hashing/) - Conceptual overview with examples
- [BLAKE3 Guide](/docs/algorithms/blake3/) - Detailed BLAKE3 guide
- [Algorithm Reference](/docs/algorithms/reference/) - All supported algorithms
