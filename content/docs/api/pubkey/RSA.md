---
title: RSA
description: RSA public-key cryptography API reference (legacy)
weight: 3
---

**Header:** `#include <cryptopp/rsa.h>` and `#include <cryptopp/oaep.h>`  
**Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0  
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

RSA is a public-key cryptosystem that can be used for both encryption and digital signatures. While still widely supported for legacy compatibility, modern applications should prefer Ed25519 for signatures and X25519/ECDH for key exchange.

## Quick Example

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate 2048-bit RSA key pair
    RSA::PrivateKey privateKey;
    privateKey.Initialize(rng, 2048);
    RSA::PublicKey publicKey(privateKey);

    // Encrypt with OAEP padding
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    std::string message = "Secret message";
    std::string ciphertext;

    StringSource(message, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string recovered;

    StringSource(ciphertext, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(recovered)
        )
    );

    std::cout << "Decrypted: " << recovered << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="warning" >}}
**RSA is an older, heavy-weight public-key scheme.** It's still widely used and secure at appropriate key sizes, but for new designs prefer Ed25519 for signatures and X25519/ECDH for key exchange.

**Use RSA for:**
- Legacy system compatibility
- Interoperability requirements
- Long-term signatures (when Ed25519 not supported)

**Modern alternatives:**
- **Signatures:** Use Ed25519 (faster, simpler, smaller keys)
- **Key exchange:** Use X25519 or ECDH
- **Encryption:** Use hybrid encryption (ECDH + AES-GCM)

**RSA Warnings:**
- NEVER use raw RSA (always use padding: OAEP for encryption, PSS for signatures)
- Key generation is slow (seconds for 4096-bit)
- Large key sizes required (minimum 2048-bit, prefer 3072-bit or 4096-bit)
- Vulnerable to side-channel attacks without proper implementation
{{< /callout >}}

## Class: RSA::PrivateKey

RSA private key for decryption and signing.

### Constructors

#### Default Constructor

```cpp
RSA::PrivateKey();
```

Create uninitialized private key.

#### Constructor from Parameters

```cpp
RSA::PrivateKey(const Integer& n, const Integer& e, const Integer& d);
```

Load existing private key.

### Methods

#### Initialize()

```cpp
void Initialize(RandomNumberGenerator& rng, unsigned int modulusBits);
void Initialize(RandomNumberGenerator& rng, unsigned int modulusBits,
                const Integer& publicExponent);
```

Generate new RSA key pair.

**Parameters:**
- `rng` - Random number generator
- `modulusBits` - Key size (2048, 3072, or 4096 recommended)
- `publicExponent` - Public exponent (default: 65537)

**Example:**

```cpp
AutoSeededRandomPool rng;
RSA::PrivateKey privateKey;

// Generate 2048-bit key (minimum recommended)
privateKey.Initialize(rng, 2048);

// Generate 4096-bit key (high security)
privateKey.Initialize(rng, 4096);
```

**Key Generation Time:**
- 2048-bit: ~100-500 ms
- 3072-bit: ~500-2000 ms
- 4096-bit: ~2-10 seconds

#### Save() / Load()

```cpp
void Save(BufferedTransformation& bt) const;
void Load(BufferedTransformation& bt);
```

Save/load the key in Crypto++'s native BER format.

For interoperable PKCS#8 `PrivateKeyInfo` encoding, use `DEREncodePrivateKey()` / `BERDecodePrivateKey()` as described in *Keys and Formats* on the Crypto++ wiki.

**Example:**

```cpp
// Save private key (native format)
FileSink file("private.key");
privateKey.Save(file);

// Load private key
FileSource file("private.key", true);
RSA::PrivateKey loadedKey;
loadedKey.Load(file);
```

## Class: RSA::PublicKey

RSA public key for encryption and verification.

### Constructors

#### Default Constructor

```cpp
RSA::PublicKey();
```

#### Constructor from Private Key

```cpp
RSA::PublicKey(const RSA::PrivateKey& privateKey);
```

Extract public key from private key.

**Example:**

```cpp
RSA::PrivateKey privateKey;
privateKey.Initialize(rng, 2048);

RSA::PublicKey publicKey(privateKey);
```

### Methods

#### Save() / Load()

```cpp
void Save(BufferedTransformation& bt) const;
void Load(BufferedTransformation& bt);
```

Save/load the key in Crypto++'s native BER format.

For interoperable X.509 `SubjectPublicKeyInfo` encoding, use `DEREncodePublicKey()` / `BERDecodePublicKey()` as described in *Keys and Formats* on the Crypto++ wiki.

## RSA-OAEP Encryption

RSA with Optimal Asymmetric Encryption Padding (recommended for encryption).

### Class: RSAES_OAEP_SHA_Encryptor

```cpp
RSAES_OAEP_SHA_Encryptor(const RSA::PublicKey& key);
```

Encrypt data using RSA-OAEP with SHA-1.

### Class: RSAES_OAEP_SHA_Decryptor

```cpp
RSAES_OAEP_SHA_Decryptor(const RSA::PrivateKey& key);
```

Decrypt data using RSA-OAEP with SHA-1.

### Recommended: OAEP with SHA-256

For new designs, prefer OAEP with SHA-256:

```cpp
RSAES_OAEP_SHA256_Encryptor enc(publicKey);
RSAES_OAEP_SHA256_Decryptor dec(privateKey);
```

`RSAES_OAEP_SHA_Encryptor` / `RSAES_OAEP_SHA_Decryptor` (SHA-1) are provided for compatibility with legacy systems.

### Complete Example: Secure File Encryption

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

void encryptFile(const std::string& filename,
                 const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;

    // Read file (small files only - RSA can't encrypt large data)
    std::string message;
    FileSource(filename.c_str(), true,
        new StringSink(message)
    );

    // Check message size
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    if (message.size() > encryptor.FixedMaxPlaintextLength()) {
        std::cerr << "Message too large for RSA encryption!" << std::endl;
        std::cerr << "Max: " << encryptor.FixedMaxPlaintextLength()
                  << " bytes" << std::endl;
        return;
    }

    // Encrypt
    std::string ciphertext;
    StringSource(message, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );

    // Save encrypted file
    FileSink(std::string(filename + ".enc").c_str())
        .Put((const byte*)ciphertext.data(), ciphertext.size());

    std::cout << "File encrypted: " << filename << std::endl;
}

void decryptFile(const std::string& filename,
                 const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;

    // Read encrypted file
    std::string ciphertext;
    FileSource(filename.c_str(), true,
        new StringSink(ciphertext)
    );

    // Decrypt
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string recovered;

    try {
        StringSource(ciphertext, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(recovered)
            )
        );
    } catch (const Exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        return;
    }

    // Save decrypted file
    std::string outFile = filename;
    if (outFile.size() > 4 && outFile.substr(outFile.size() - 4) == ".enc") {
        outFile = outFile.substr(0, outFile.size() - 4);
    }

    FileSink(outFile.c_str())
        .Put((const byte*)recovered.data(), recovered.size());

    std::cout << "File decrypted: " << outFile << std::endl;
}

int main() {
    AutoSeededRandomPool rng;

    // Generate keys
    RSA::PrivateKey privateKey;
    privateKey.Initialize(rng, 2048);
    RSA::PublicKey publicKey(privateKey);

    // Encrypt small file
    encryptFile("message.txt", publicKey);

    // Decrypt file
    decryptFile("message.txt.enc", privateKey);

    return 0;
}
```

## RSA-PSS Signatures

RSA with Probabilistic Signature Scheme (recommended for signatures).

### Class: RSASS_PSS_SHA256_Signer

```cpp
RSASS_PSS_SHA256_Signer(const RSA::PrivateKey& key);
```

Sign data using RSA-PSS with SHA-256.

### Class: RSASS_PSS_SHA256_Verifier

```cpp
RSASS_PSS_SHA256_Verifier(const RSA::PublicKey& key);
```

Verify signatures using RSA-PSS with SHA-256.

### Complete Example: Digital Signatures

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate 3072-bit key for signatures
    RSA::PrivateKey privateKey;
    privateKey.Initialize(rng, 3072);
    RSA::PublicKey publicKey(privateKey);

    // Create signer
    RSASS<PSS, SHA256>::Signer signer(privateKey);

    // Sign message
    std::string message = "Important document";
    std::string signature;

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    std::cout << "Signature size: " << signature.size()
              << " bytes" << std::endl;

    // Create verifier
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);

    // Verify signature
    bool valid = false;
    try {
        StringSource(signature + message, true,
            new SignatureVerificationFilter(verifier,
                new ArraySink((byte*)&valid, sizeof(valid))
            )
        );
    } catch (const Exception& e) {
        valid = false;
    }

    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Performance

### Key Generation Time

| Key Size | Time (approx) | Security Level |
|----------|---------------|----------------|
| 2048-bit | 100-500 ms | 112-bit (minimum) |
| 3072-bit | 500-2000 ms | 128-bit (recommended) |
| 4096-bit | 2-10 seconds | 140-bit (high security) |

**Note:** Key generation is one-time cost, usually done offline.

### Encryption/Decryption Speed

| Key Size | Encrypt (ops/sec) | Decrypt (ops/sec) |
|----------|-------------------|-------------------|
| 2048-bit | 5000-10000 | 100-200 |
| 3072-bit | 3000-5000 | 40-80 |
| 4096-bit | 1500-3000 | 20-40 |

**Decryption is 50-100x slower than encryption.**

### Signature Speed

| Key Size | Sign (ops/sec) | Verify (ops/sec) |
|----------|----------------|------------------|
| 2048-bit | 100-200 | 5000-10000 |
| 3072-bit | 40-80 | 3000-5000 |
| 4096-bit | 20-40 | 1500-3000 |

**Signing is 50-100x slower than verification.**

### Comparison with Ed25519

| Operation | RSA-2048 | Ed25519 | Winner |
|-----------|----------|---------|--------|
| Key gen | 100-500 ms | 40-80 µs | Ed25519 (1000x faster) |
| Sign | 1-10 ms | 50-100 µs | Ed25519 (10-20x faster) |
| Verify | 100-200 µs | 100-150 µs | Similar |
| Private key | 256 bytes | 32 bytes | Ed25519 (8x smaller) |
| Public key | 256 bytes | 32 bytes | Ed25519 (8x smaller) |
| Signature | 256 bytes | 64 bytes | Ed25519 (4x smaller) |

## Security

### Key Size Recommendations

| Year | Minimum | Recommended | High Security |
|------|---------|-------------|---------------|
| 2024-2030 | 2048-bit | 3072-bit | 4096-bit |
| 2030+ | 3072-bit | 4096-bit | 8192-bit |

**Approximate Security Levels (NIST SP 800-57):**
- 2048-bit ≈ 112-bit security
- 3072-bit ≈ 128-bit security (equivalent to AES-128)
- 4096-bit ≈ ~140-bit security (estimate; NIST only tabulates 2048, 3072, 7680, 15360)

### Security Best Practices

1. **Always Use Padding:**
   ```cpp
   // CORRECT - OAEP padding
   RSAES_OAEP_SHA_Encryptor enc(publicKey);

   // WRONG - Raw RSA (vulnerable to attacks)
   // NEVER DO THIS
   ```

2. **Use PSS for Signatures:**
   ```cpp
   // CORRECT - RSA-PSS
   RSASS<PSS, SHA256>::Signer signer(privateKey);

   // ACCEPTABLE - PKCS#1 v1.5 (legacy only)
   RSASS<PKCS1v15, SHA256>::Signer signer(privateKey);
   ```

3. **Minimum 2048-bit Keys:**
   ```cpp
   // CORRECT - 2048-bit minimum
   privateKey.Initialize(rng, 2048);

   // WRONG - Too weak
   privateKey.Initialize(rng, 1024);  // INSECURE
   ```

4. **Protect Private Keys:**
   ```cpp
   // Serialize private key, then encrypt before storing
   ByteQueue q;
   privateKey.DEREncodePrivateKey(q);  // or privateKey.Save(q)

   // Encrypt q's contents before writing to disk
   ```

## Maximum Message Sizes

RSA can only encrypt small messages. Maximum plaintext size:

| Key Size | OAEP-SHA1 | OAEP-SHA256 |
|----------|-----------|-------------|
| 2048-bit | 214 bytes | 190 bytes |
| 3072-bit | 342 bytes | 318 bytes |
| 4096-bit | 470 bytes | 446 bytes |

**For large data, use hybrid encryption:**
1. Generate random AES key
2. Encrypt data with AES-GCM
3. Encrypt AES key with RSA-OAEP
4. Send both encrypted AES key and encrypted data

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## When to Use RSA

### ✅ Use RSA for:

1. **Legacy Compatibility** - Systems that don't support modern algorithms
2. **Interoperability** - Standards requiring RSA (TLS 1.2, etc.)
3. **Long-Term Signatures** - When Ed25519 not supported
4. **Hybrid Encryption** - Encrypt symmetric keys

### ❌ Don't use RSA for:

1. **New Applications** - Use Ed25519 for signatures, X25519 for key exchange
2. **Large Data Encryption** - Use symmetric encryption (AES-GCM)
3. **Performance-Critical** - RSA is 10-1000x slower than alternatives
4. **IoT/Embedded** - Large keys and slow operations

## RSA vs Ed25519

**Choose Ed25519 unless:**
- Legacy system compatibility required
- Specific standard mandates RSA
- Interoperability with systems that don't support Ed25519

**Ed25519 advantages:**
- 10-20x faster signing
- 1000x faster key generation
- 8x smaller keys
- 4x smaller signatures
- Simpler implementation (fewer failure modes)
- Deterministic signatures (no RNG needed)

## Exceptions

- `InvalidMaterial` - Invalid key parameters
- `InvalidCiphertext` - Decryption failed (wrong key or corrupted data)

## See Also

- [Ed25519](/docs/api/pubkey/ed25519/) - Modern digital signatures (recommended)
- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange (recommended)
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - For encrypting large data
- [Public-Key Cryptography](/docs/api/pubkey/) - Overview
