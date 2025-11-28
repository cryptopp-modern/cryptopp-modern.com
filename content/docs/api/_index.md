---
title: API Reference
description: Complete API reference for cryptopp-modern C++ library
weight: 40
---

Complete API documentation for all classes, methods, and functions in the cryptopp-modern library.

## Hash Functions

High-performance cryptographic hash functions for data integrity and digital signatures.

- [BLAKE3](/docs/api/hash/blake3/) - Fastest modern hash function with parallelism support
- [BLAKE2b / BLAKE2s](/docs/api/hash/blake2/) - High-speed hash functions (RFC 7693)
- [SHA-256](/docs/api/hash/sha256/) - Standard hash function with hardware acceleration
- [SHA-512](/docs/api/hash/sha512/) - 64-bit optimised hash for high security
- [SHA-3](/docs/api/hash/sha3/) - FIPS 202 Keccak-based hash function

## Password Hashing & Key Derivation

Secure password hashing and key derivation functions.

- [Argon2](/docs/api/kdf/argon2/) - Memory-hard password hashing (recommended)
- [HKDF](/docs/api/kdf/hkdf/) - HMAC-based key derivation for secrets
- [PBKDF2](/docs/api/kdf/pbkdf2/) - Password-based key derivation (legacy/FIPS)

## Symmetric Encryption

Authenticated encryption algorithms for encrypting data.

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Industry standard authenticated encryption (recommended)
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Modern AEAD without hardware acceleration needs
- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Legacy encrypt-then-MAC pattern
- [AES-CTR](/docs/api/symmetric/aes-ctr/) - Counter mode (requires separate MAC)
- [AES-CBC](/docs/api/symmetric/aes-cbc/) - Cipher Block Chaining mode (requires separate MAC)

## Public-Key Cryptography

Asymmetric cryptography for signatures and key exchange.

- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange (recommended)
- [Ed25519](/docs/api/pubkey/ed25519/) - Modern digital signatures (recommended)
- [RSA](/docs/api/pubkey/rsa/) - Legacy public-key encryption and signatures

## Message Authentication

Message Authentication Codes (MACs) for data authenticity.

- [HMAC](/docs/api/mac/hmac/) - Hash-based MAC (recommended for most use cases)
- [CMAC](/docs/api/mac/cmac/) - Cipher-based MAC using AES
- [Poly1305](/docs/api/mac/poly1305/) - High-speed one-time MAC

## Utilities

Essential utilities for cryptographic operations.

- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Cryptographic RNG (essential)
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure memory for keys (essential)
- [HexEncoder](/docs/api/utilities/hexencoder/) - Hexadecimal encoding and decoding
- [Base64Encoder](/docs/api/utilities/base64encoder/) - Base64 and Base64URL encoding

## Pipeline & Filters

Data transformation pipeline for streaming operations.

- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String-based I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File-based I/O
- [ArraySource / ArraySink](/docs/api/utilities/arraysource/) - Byte array I/O
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation filter
- [SignerFilter / VerifierFilter](/docs/api/utilities/signerfilter/) - Digital signature filters
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Encryption/decryption filter
- [AuthenticatedEncryptionFilter](/docs/api/utilities/authenticatedencryptionfilter/) - AEAD encryption filter
- [Redirector / Tee](/docs/api/utilities/redirector/) - Pipeline branching and duplication

## Advanced Utilities

- [Integer](/docs/api/utilities/integer/) - Arbitrary precision integers for big number operations

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
