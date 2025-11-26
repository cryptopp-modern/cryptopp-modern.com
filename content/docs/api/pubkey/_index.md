---
title: Public-Key Cryptography
description: API reference for asymmetric cryptography algorithms
weight: 5
---

Public-key (asymmetric) cryptography uses pairs of keys: public keys for encryption/verification and private keys for decryption/signing. Essential for secure communication without pre-shared secrets.

## Available Algorithms

### [X25519](/docs/api/pubkey/x25519/) ⭐ Recommended
Modern elliptic curve key exchange
- Diffie-Hellman key agreement on Curve25519
- 128-bit security level
- Fast (40-80 µs per operation)
- Simple API, hard to misuse
- Used in TLS 1.3, WireGuard, Signal

**Use X25519 for:**
- Establishing shared secrets over insecure channels
- Forward secrecy in communication protocols
- Key exchange for symmetric encryption
- Modern alternative to traditional DH/RSA key exchange

### [Ed25519](/docs/api/pubkey/ed25519/)
Modern elliptic curve digital signatures
- Fast signature generation and verification
- 128-bit security level
- Deterministic signatures
- Used in SSH, GPG, cryptocurrencies

### [RSA](/docs/api/pubkey/rsa/)
Traditional public-key encryption and signatures
- Widely supported (legacy systems)
- Larger keys (2048-4096 bits)
- Slower than elliptic curves
- Still acceptable but prefer Ed25519/X25519 for new systems

### [ECDSA](/docs/api/pubkey/ecdsa/)
Elliptic Curve Digital Signature Algorithm
- NIST standard curves (P-256, P-384, P-521)
- Used in TLS, Bitcoin, X.509 certificates
- Deterministic variant (RFC 6979) available
- Consider Ed25519 for new systems when NIST compliance not required

### [ECDH](/docs/api/pubkey/ecdh/)
Elliptic Curve Diffie-Hellman key exchange
- NIST standard curves (P-256, P-384, P-521)
- Used in TLS 1.2, many protocols
- Consider X25519 for new systems

## Quick Comparison

| Algorithm | Type | Speed | Key Size | Security | Recommended |
|-----------|------|-------|----------|----------|-------------|
| **X25519** | Key Exchange | ⚡⚡⚡⚡⚡ | 32 bytes | 128-bit | ⭐ Primary |
| **Ed25519** | Signature | ⚡⚡⚡⚡⚡ | 32 bytes | 128-bit | ⭐ Primary |
| ECDSA P-256 | Signature | ⚡⚡⚡⚡ | 64 bytes | 128-bit | NIST compliance |
| RSA-2048 | Both | ⚡⚡ | 256 bytes | 112-bit | Legacy |
| RSA-3072 | Both | ⚡ | 384 bytes | 128-bit | Legacy |

## Key Exchange vs Signatures

### Key Exchange (X25519, DH, RSA-OAEP)

**Purpose:** Establish shared secret between two parties

```cpp
// Alice and Bob perform key exchange
x25519 alice(rng), bob(rng);

SecByteBlock alicePrivate(32), bobPublic(32);
alice.GenerateKeyPair(rng, alicePrivate, alicePublic);

SecByteBlock sharedSecret(32);
alice.Agree(sharedSecret, alicePrivate, bobPublic);

// Both parties now have same shared secret
// Use for symmetric encryption
```

**Use for:**
- TLS/SSL handshakes
- Secure messaging (Signal, WhatsApp)
- VPN connections
- Any scenario needing shared encryption key

### Digital Signatures (Ed25519, ECDSA, RSA-PSS)

**Purpose:** Prove authenticity and integrity

```cpp
// Signer creates signature
Ed25519::Signer signer(privateKey);
std::string signature = sign(message, signer);

// Verifier checks signature
Ed25519::Verifier verifier(publicKey);
bool valid = verify(message, signature, verifier);

if (valid) {
    // Message is authentic and unmodified
}
```

**Use for:**
- Software/firmware signing
- Document signing
- Certificate authorities (TLS certificates)
- Git commit signing
- Cryptocurrency transactions

## Security Best Practices

### 1. Choose Modern Algorithms

```cpp
// RECOMMENDED - Modern Curve25519
x25519 kex(rng);           // Key exchange
Ed25519::Signer signer;    // Signatures

// ACCEPTABLE - NIST curves
ECDH<ECP>::Domain dh(ASN1::secp256r1());

// LEGACY - Only if required for compatibility
RSA::PrivateKey rsaKey;
```

### 2. Use Adequate Key Sizes

| Algorithm | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| X25519/Ed25519 | 256 bits | 256 bits | Fixed size |
| RSA | 2048 bits | 3072+ bits | Larger is slower |
| ECDSA | P-256 | P-384+ | Use Ed25519 instead |

### 3. Validate Public Keys

```cpp
// CORRECT - validate public keys
if (!kex.Agree(shared, myPrivate, theirPublic)) {
    // Validation failed - reject key
    throw std::runtime_error("Invalid public key");
}

// WRONG - skip validation (vulnerable!)
kex.Agree(shared, myPrivate, theirPublic, false);
```

### 4. Use Ephemeral Keys for Forward Secrecy

```cpp
// CORRECT - ephemeral keys per session
void newSession() {
    x25519 kex(rng);  // Fresh keys
    // ... perform key exchange ...
    // Keys destroyed at end of scope
}

// WRONG - reusing static keys
x25519 static_kex(rng);  // Used for all sessions
// Compromise of static key compromises all past sessions
```

### 5. Combine Key Exchange with Signatures

```cpp
// Authenticated key exchange (prevent MITM)
// 1. Perform ephemeral key exchange
x25519 ephemeral(rng);
SecByteBlock sharedSecret = keyExchange(ephemeral);

// 2. Sign the exchange with long-term identity key
Ed25519::Signer identityKey(myLongTermPrivateKey);
std::string signature = sign(transcript, identityKey);

// 3. Verify other party's signature
// Now protected against man-in-the-middle attacks
```

## Common Patterns

### Establish Secure Channel

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

// 1. Key exchange
x25519 alice(rng), bob(rng);
SecByteBlock sharedSecret(32);
// ... perform key exchange ...

// 2. Derive encryption keys
HKDF<SHA256> hkdf;
SecByteBlock encKey(32), macKey(32);
hkdf.DeriveKey(encKey, 32, sharedSecret, 32, ...);

// 3. Encrypt messages
GCM<AES>::Encryption enc;
enc.SetKeyWithIV(encKey, 32, iv, 12);
// ... encrypt data ...
```

### Sign and Verify Documents

```cpp
#include <cryptopp/ed25519.h>
#include <cryptopp/files.h>

// Generate signing key
AutoSeededRandomPool rng;
Ed25519::Signer signer(rng);

// Sign document
std::string document = "Important contract";
std::string signature;
StringSource(document, true,
    new SignerFilter(rng, signer,
        new StringSink(signature)
    )
);

// Verify signature
Ed25519::Verifier verifier(signer);
bool valid = verifySignature(document, signature, verifier);
```

## Performance

### Benchmarks (Approximate)

| Operation | Algorithm | Time (µs) | Notes |
|-----------|-----------|-----------|-------|
| Key generation | X25519 | 40-80 | Fast |
| Key exchange | X25519 | 40-80 | Fast |
| Sign | Ed25519 | 50-100 | Fast |
| Verify | Ed25519 | 100-150 | Fast |
| Key generation | RSA-2048 | 50000-100000 | Very slow |
| Sign | RSA-2048 | 1000-2000 | Slow |
| Verify | RSA-2048 | 50-100 | Fast |

**Platform:** Modern x86-64 CPU

## When to Use Public-Key Cryptography

### ✅ Use Public-Key Crypto for:

1. **Key Exchange** - Establish shared secret (X25519)
2. **Digital Signatures** - Prove authenticity (Ed25519)
3. **Certificate Chains** - TLS/SSL certificates (RSA, ECDSA)
4. **Identity Verification** - SSH keys, GPG keys
5. **No Pre-Shared Secret** - First contact between parties

### ❌ Don't use Public-Key Crypto for:

1. **Bulk Encryption** - Use symmetric crypto (AES-GCM)
   - Public-key is 100-1000x slower
   - Combine: X25519 for key exchange + AES-GCM for data

2. **Message Authentication** - Use HMAC
   - Signatures are slower than MACs
   - Use signatures only when non-repudiation needed

## Hybrid Encryption

Combine public-key and symmetric crypto for best of both:

```cpp
// Sender
x25519 sender(rng);
SecByteBlock ephemeralPrivate(32), ephemeralPublic(32);
sender.GenerateKeyPair(rng, ephemeralPrivate, ephemeralPublic);

// Perform key exchange with recipient's public key
SecByteBlock sharedSecret(32);
sender.Agree(sharedSecret, ephemeralPrivate, recipientPublic);

// Derive symmetric key
HKDF<SHA256> hkdf;
SecByteBlock aesKey(32);
hkdf.DeriveKey(aesKey, 32, sharedSecret, 32, ...);

// Encrypt large data with AES-GCM (fast)
GCM<AES>::Encryption enc;
enc.SetKeyWithIV(aesKey, 32, iv, 12);
std::string ciphertext = encryptLargeData(data, enc);

// Send: ephemeralPublic + ciphertext
```

## Thread Safety

Public-key objects are generally **not thread-safe**. Generate keys per-thread or use synchronization.

```cpp
// Safe - per-thread keys
void threadFunc() {
    AutoSeededRandomPool rng;
    x25519 kex(rng);  // Thread-local
    // ... use kex ...
}

// Unsafe - shared key operations
x25519 global_kex;
void thread1() { global_kex.Agree(...); }  // RACE CONDITION
void thread2() { global_kex.Agree(...); }
```

## See Also

- [X25519 API](/docs/api/pubkey/x25519/) - Key exchange API reference
- [Ed25519 API](/docs/api/pubkey/ed25519/) - Digital signatures API reference
- [Public-Key Cryptography Guide](/docs/algorithms/public-key/) - Conceptual overview
- [Security Concepts](/docs/guides/security-concepts/) - Understanding public-key cryptography
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Key generation
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure key storage
