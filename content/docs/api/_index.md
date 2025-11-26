---
title: API Reference
description: Complete API reference for cryptopp-modern C++ library
weight: 40
---

Complete API documentation for all classes, methods, and functions in the cryptopp-modern library.

## Hash Functions

High-performance cryptographic hash functions for data integrity and digital signatures.

- [BLAKE3](/docs/api/hash/blake3/) - Fastest modern hash function with parallelism support
- [SHA-256](/docs/api/hash/sha256/) - Standard hash function with hardware acceleration
- [SHA-512](/docs/api/hash/sha512/) - 64-bit optimized hash for high security
- [SHA-3](/docs/api/hash/sha3/) - FIPS 202 Keccak-based hash function

## Password Hashing & Key Derivation

Secure password hashing and key derivation functions.

- [Argon2](/docs/api/kdf/argon2/) - Memory-hard password hashing (recommended)
- [HKDF](/docs/api/kdf/hkdf/) - HMAC-based key derivation for secrets

## Symmetric Encryption

Authenticated encryption algorithms for encrypting data.

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Industry standard authenticated encryption (recommended)
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Modern AEAD without hardware acceleration needs
- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Legacy encrypt-then-MAC pattern

## Public-Key Cryptography

Asymmetric cryptography for signatures and key exchange.

- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange (recommended)
- [Ed25519](/docs/api/pubkey/ed25519/) - Modern digital signatures (recommended)
- [RSA](/docs/api/pubkey/rsa/) - Legacy public-key encryption and signatures

## Message Authentication

Message Authentication Codes (MACs) for data authenticity.

- [HMAC](/docs/api/mac/hmac/) - Hash-based MAC (recommended for most use cases)
- CMAC (coming soon)
- Poly1305 (coming soon)

## Utilities

Essential utilities for cryptographic operations.

- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Cryptographic RNG (essential)
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure memory for keys (essential)
- [HexEncoder](/docs/api/utilities/hexencoder/) - Hexadecimal encoding and decoding
- [Base64Encoder](/docs/api/utilities/base64encoder/) - Base64 and Base64URL encoding

## Quick Navigation

- **By Category** - Browse above
- **Alphabetical** - See all classes A-Z (coming soon)
- **Most Used** - Popular classes (coming soon)

## Using the API Reference

Each API page includes:
- **Overview** - What the class does and when to use it
- **Constants** - Important compile-time constants
- **Constructors** - How to create instances
- **Methods** - All public methods with parameters and return values
- **Examples** - Working code you can copy and paste
- **Performance** - Speed characteristics and hardware acceleration
- **Security** - Security properties and guarantees
- **See Also** - Related classes and guides

## Need Help?

- **New to cryptopp-modern?** Start with the [Beginner's Guide](/docs/guides/beginners-guide/)
- **Looking for examples?** Check the [Algorithm Guides](/docs/algorithms/)
- **Security questions?** Read [Security Concepts](/docs/guides/security-concepts/)
- **Migrating from Crypto++?** See the [Migration Guide](/docs/migration/from-cryptopp/)
