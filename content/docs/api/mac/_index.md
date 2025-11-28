---
title: Message Authentication
description: API reference for Message Authentication Codes (MACs)
weight: 4
---

Message Authentication Codes (MACs) provide data authenticity and integrity using a shared secret key. They verify that a message came from a legitimate sender and hasn't been tampered with.

## What is a MAC?

A MAC is like a "keyed checksum" - it uses a secret key to produce an authentication tag that only someone with the key can generate or verify. Unlike digital signatures, MACs use symmetric keys (same key for generation and verification).

## Available MAC Algorithms

### [HMAC](/docs/api/mac/hmac/) ⭐ Recommended
Hash-based Message Authentication Code
- Uses any hash function (HMAC-SHA256, HMAC-SHA512, HMAC-BLAKE3)
- RFC 2104 standardised
- Fast and secure
- Most widely used MAC

**Use HMAC for:**
- API request authentication
- File integrity verification
- Message authentication
- General-purpose MAC needs

### [CMAC](/docs/api/mac/cmac/)
Cipher-based Message Authentication Code
- Uses block ciphers (AES-CMAC)
- NIST SP 800-38B standardised
- Good alternative to HMAC

### [Poly1305](/docs/api/mac/poly1305/)
Universal hash function MAC
- Very fast (designed for speed)
- Used in ChaCha20-Poly1305
- 128-bit security (one-time key)

## Quick Comparison

| Algorithm | Speed | Security | Use Case | Recommended |
|-----------|-------|----------|----------|-------------|
| **HMAC-SHA256** | Fast | 256-bit | General purpose | ⭐ Primary |
| **HMAC-BLAKE3** | Very Fast | 256-bit | High throughput | ⭐ Performance |
| **HMAC-SHA512** | Fast | 512-bit | High security | ⭐ Long-term |
| CMAC-AES | Medium | 128-bit | Block cipher preference | Alternative |
| Poly1305 | Very Fast | 128-bit | With ChaCha20 | Specialised |
| GMAC | Very Fast | 128-bit | With AES-GCM | Specialised |

## Common Interface

All MAC algorithms implement the `MessageAuthenticationCode` interface:

```cpp
class MessageAuthenticationCode {
public:
    // Set authentication key
    void SetKey(const byte* key, size_t length);

    // Add data to authenticate
    void Update(const byte* input, size_t length);

    // Get MAC tag
    void Final(byte* mac);

    // Reset for new message (keeps key)
    void Restart();

    // Query methods
    unsigned int DigestSize() const;  // MAC tag size
    unsigned int OptimalBlockSize() const;
};
```

## Choosing a MAC Algorithm

### For New Systems

**Primary Choice: HMAC-SHA256**
```cpp
HMAC<SHA256> hmac(key, keyLen);
```
- Industry standard
- Hardware acceleration on modern CPUs
- Well-studied and trusted
- Good balance of speed and security

**Performance-Critical: HMAC-BLAKE3**
```cpp
HMAC<BLAKE3> hmac(key, keyLen);
```
- 2-4x faster than HMAC-SHA256
- Same 256-bit security
- Excellent for high-throughput systems

**High Security: HMAC-SHA512**
```cpp
HMAC<SHA512> hmac(key, keyLen);
```
- 512-bit security
- Future-proof
- Faster on 64-bit systems

### For Specific Scenarios

**With AES Encryption:**
Use AES-GCM (provides encryption + MAC together)

**With ChaCha20 Encryption:**
Use ChaCha20-Poly1305 (provides encryption + MAC together)

**Block Cipher Preference:**
Use AES-CMAC

## MAC vs Digital Signature

| Feature | MAC | Digital Signature |
|---------|-----|-------------------|
| Key type | Symmetric (shared) | Asymmetric (public/private) |
| Verification | Same key | Public key |
| Non-repudiation | ❌ No | ✅ Yes |
| Speed | ⚡⚡⚡ Very fast | ⚡ Slower |
| Use case | Trusted parties | Untrusted parties |

**When to use MAC:** Both parties trust each other (API authentication, file integrity)

**When to use signatures:** Need non-repudiation (software signing, contracts)

## Security Best Practices

### 1. Key Generation

```cpp
AutoSeededRandomPool rng;
SecByteBlock key(32);  // 256-bit key for HMAC
rng.GenerateBlock(key, key.size());
```

### 2. Key Length

- **Minimum:** 128 bits (16 bytes)
- **Recommended:** 256 bits (32 bytes)
- **Never:** < 128 bits

### 3. Constant-Time Verification

```cpp
// WRONG - vulnerable to timing attacks
if (computedMAC == receivedMAC) {
    // Attacker can measure comparison time
}

// CORRECT - constant-time comparison
bool valid = VerifyMAC(computedMAC, receivedMAC);
```

### 4. Don't Use for Passwords

```cpp
// WRONG - MACs are not password hashing functions
std::string hash = hmac(password);

// CORRECT - use password hashing
Argon2 argon2;
argon2.DeriveKey(hash, ...);
```

### 5. Key Storage

```cpp
SecByteBlock key(32);  // Auto-zeroes on destruction

// NOT: std::string key;  // Leaves key in memory
// NOT: byte key[32];     // Not auto-zeroed
```

## Common Patterns

### API Request Signing

```cpp
std::string signRequest(const std::string& method,
                       const std::string& path,
                       const std::string& body,
                       const SecByteBlock& apiKey) {
    HMAC<SHA256> hmac(apiKey, apiKey.size());

    std::string message = method + "\n" + path + "\n" + body;
    std::string mac, signature;

    StringSource(message, true,
        new HashFilter(hmac, new StringSink(mac))
    );

    // Encode as hex or base64
    StringSource(mac, true,
        new HexEncoder(new StringSink(signature))
    );

    return signature;
}
```

### File Integrity

```cpp
std::string computeFileMAC(const std::string& filename,
                           const SecByteBlock& key) {
    HMAC<SHA256> hmac(key, key.size());
    std::string mac, hexMAC;

    FileSource(filename.c_str(), true,
        new HashFilter(hmac, new StringSink(mac))
    );

    StringSource(mac, true,
        new HexEncoder(new StringSink(hexMAC))
    );

    return hexMAC;
}
```

### Encrypt-then-MAC

```cpp
void authenticatedEncryption(const std::string& plaintext,
                             const SecByteBlock& encKey,
                             const SecByteBlock& macKey,
                             std::string& ciphertext,
                             std::string& mac) {
    // 1. Encrypt
    // ... encrypt plaintext to ciphertext ...

    // 2. MAC the ciphertext (Encrypt-then-MAC)
    HMAC<SHA256> hmac(macKey, macKey.size());
    StringSource(ciphertext, true,
        new HashFilter(hmac, new StringSink(mac))
    );
}

// Note: In practice, use AES-GCM which combines encryption + MAC
```

## Performance Benchmarks

Approximate speeds on modern hardware:

| Algorithm | Speed (MB/s) | Hardware Accel |
|-----------|--------------|----------------|
| HMAC-BLAKE3 | 3000-6000 | No |
| HMAC-SHA256 | 800-1500 | SHA-NI |
| HMAC-SHA512 | 600-1200 | SHA-NI |
| Poly1305 | 2000-4000 | No |
| CMAC-AES | 1000-2000 | AES-NI |

## Thread Safety

MAC objects are **not thread-safe**. Create separate instances per thread:

```cpp
// WRONG - sharing between threads
HMAC<SHA256> shared_hmac;

// CORRECT - thread-local instances
void threadFunc(const SecByteBlock& key) {
    HMAC<SHA256> hmac(key, key.size());  // Per-thread
    // ... use hmac ...
}
```

## When NOT to Use MACs

### ❌ Password Hashing
MACs are fast - that's bad for passwords. Use Argon2:
```cpp
// WRONG
HMAC<SHA256> hmac(salt, saltLen);
std::string hash = hmac(password);

// CORRECT
Argon2 argon2;
argon2.DeriveKey(hash, ...);
```

### ❌ Digital Signatures
MACs require shared secrets. For public verification, use signatures:
```cpp
// WRONG - both parties need same secret
HMAC<SHA256> hmac(sharedSecret, secretLen);

// CORRECT - public key verification
Ed25519::Signer signer(privateKey);
Ed25519::Verifier verifier(publicKey);
```

### ❌ Content Addressing
For identifying content without authentication, use hashes:
```cpp
// If you don't need authentication, just use SHA-256
SHA256 hash;
std::string digest = hash(data);
```

## Authenticated Encryption (AEAD)

Instead of separate encryption + MAC, use authenticated encryption:

| Instead of... | Use... |
|---------------|--------|
| AES-CBC + HMAC-SHA256 | AES-GCM |
| AES-CTR + HMAC-SHA256 | AES-GCM |
| ChaCha20 + HMAC | ChaCha20-Poly1305 |

**Benefits:**
- Simpler API (one operation)
- Faster (optimised together)
- Harder to misuse (correct by construction)

## See Also

- [Hash Functions Guide](/docs/algorithms/hashing/) - Hash and HMAC overview
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption
- [Security Concepts](/docs/guides/security-concepts/) - MAC vs signature vs hash
- [Argon2](/docs/api/kdf/argon2/) - Password hashing (not MAC)
