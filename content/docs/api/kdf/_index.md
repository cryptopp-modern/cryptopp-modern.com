---
title: Key Derivation & Password Hashing
description: API reference for password hashing and key derivation functions
weight: 2
---

Functions for deriving keys from passwords and other secrets.

## Password Hashing

### [Argon2](/docs/api/kdf/argon2/) ⭐ Recommended
Memory-hard password hashing function
- Three variants: Argon2d, Argon2i, Argon2id
- Winner of Password Hashing Competition
- RFC 9106 standardized
- GPU/ASIC resistant

**Use Argon2 for:**
- User password authentication
- Cryptocurrency wallet encryption
- Disk encryption key derivation

### bcrypt (coming soon)
Legacy password hashing function
- Still acceptable for existing systems
- Consider migrating to Argon2

### scrypt (coming soon)
Memory-hard password hashing
- Alternative to Argon2
- Good but not as configurable

## Key Derivation Functions

### [HKDF](/docs/api/kdf/hkdf/)
HMAC-based key derivation
- For deriving keys from shared secrets
- Not for passwords (use Argon2)

### [PBKDF2](/docs/api/kdf/pbkdf2/)
Password-Based Key Derivation Function 2
- RFC 2898 / FIPS compliant
- For legacy systems and FIPS requirements
- **Use Argon2 for new applications**

## Quick Comparison

| Function | Password Hashing | Key Derivation | Memory-Hard | Recommended |
|----------|------------------|----------------|-------------|-------------|
| **Argon2** | ✅ Best | ❌ No | ✅ Yes | ⭐ |
| HKDF | ❌ No | ✅ Yes | ❌ No | For secrets |
| PBKDF2 | ⚠️ Legacy | ⚠️ Legacy | ❌ No | FIPS only |
| bcrypt | ✅ Acceptable | ❌ No | ⚠️ Moderate | Legacy |
| scrypt | ✅ Good | ⚠️ Maybe | ✅ Yes | Alternative |

## See Also

- [Password Hashing Guide](/docs/guides/password-hashing/) - Best practices
- [Security Concepts](/docs/guides/security-concepts/) - Understanding cryptography
- [Algorithm Reference](/docs/algorithms/reference/) - All supported algorithms
