---
title: Public-Key Cryptography
weight: 90
description: "Complete guide to public-key cryptography with cryptopp-modern. Learn RSA, ECDSA, Ed25519, X25519, ECDH key exchange, and digital signatures with practical examples."
---

Public-key cryptography (asymmetric cryptography) uses pairs of keys: a public key for encryption/verification and a private key for decryption/signing. Unlike symmetric encryption, the keys are different and mathematically related.

## Use Cases

- **Digital Signatures**: Prove authenticity and integrity of messages
- **Key Exchange**: Securely establish shared secrets over insecure channels
- **Encryption**: Encrypt data that only the recipient can decrypt
- **Authentication**: Verify identity without sharing secrets

## Supported Algorithms

### Digital Signatures
- **Ed25519** - Modern, fast elliptic curve signatures (recommended)
- **ECDSA** - Elliptic Curve Digital Signature Algorithm
- **RSA** - Traditional RSA signatures
- **DSA** - Digital Signature Algorithm

### Key Exchange
- **X25519** - Modern elliptic curve Diffie-Hellman (recommended)
- **ECDH** - Elliptic Curve Diffie-Hellman
- **DH** - Traditional Diffie-Hellman

### Encryption
- **RSA-OAEP** - RSA with Optimal Asymmetric Encryption Padding
- **ECIES** - Elliptic Curve Integrated Encryption Scheme

## Quick Comparison

| Algorithm | Type | Security | Speed | Use Case |
|-----------|------|----------|-------|----------|
| Ed25519 | Signature | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Modern signatures (best choice) |
| X25519 | Key Exchange | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Modern key exchange (best choice) |
| ECDSA (P-256) | Signature | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | NIST standard signatures |
| ECDH (P-256) | Key Exchange | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | NIST standard key exchange |
| RSA-2048 | Signature/Encrypt | ⭐⭐⭐⭐ | ⭐⭐ | Legacy compatibility |
| RSA-4096 | Signature/Encrypt | ⭐⭐⭐⭐⭐ | ⭐ | High security, slow |

## Digital Signatures with Ed25519

**When to use:** Modern applications requiring fast, secure digital signatures

**What it does:** Create unforgeable signatures that prove a message came from you

### Basic Signing and Verification

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key pair
    ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(rng);

    // Extract public key for distribution
    ed25519::Verifier verifier(signer);

    // Sign a message
    std::string message = "This is an important message";
    std::string signature;

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature size: " << signature.size() << " bytes" << std::endl;

    // Verify signature
    std::string recovered;
    StringSource(signature + message, true,
        new SignatureVerificationFilter(verifier,
            new StringSink(recovered)
        )
    );

    if (recovered == message) {
        std::cout << "Signature verified successfully!" << std::endl;
    } else {
        std::cout << "Signature verification failed!" << std::endl;
    }

    return 0;
}
```

### Saving and Loading Keys

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

class Ed25519KeyPair {
private:
    CryptoPP::ed25519::Signer signer;
    CryptoPP::ed25519::Verifier verifier;

public:
    // Generate new key pair
    void generate() {
        CryptoPP::AutoSeededRandomPool rng;
        signer.AccessPrivateKey().GenerateRandom(rng);
        verifier = CryptoPP::ed25519::Verifier(signer);
    }

    // Save private key to file
    void savePrivateKey(const std::string& filename) {
        CryptoPP::FileSink file(filename.c_str());
        signer.AccessPrivateKey().Save(file);
    }

    // Load private key from file
    void loadPrivateKey(const std::string& filename) {
        CryptoPP::FileSource file(filename.c_str(), true);
        signer.AccessPrivateKey().Load(file);
        verifier = CryptoPP::ed25519::Verifier(signer);
    }

    // Save public key to file
    void savePublicKey(const std::string& filename) {
        CryptoPP::FileSink file(filename.c_str());
        verifier.AccessPublicKey().Save(file);
    }

    // Load public key from file (for verification only)
    void loadPublicKey(const std::string& filename) {
        CryptoPP::FileSource file(filename.c_str(), true);
        verifier.AccessPublicKey().Load(file);
    }

    // Get public key as hex string
    std::string getPublicKeyHex() const {
        std::string hex;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex));
        verifier.AccessPublicKey().Save(encoder);
        return hex;
    }

    // Sign message
    std::string sign(const std::string& message) {
        CryptoPP::AutoSeededRandomPool rng;
        std::string signature;

        CryptoPP::StringSource(message, true,
            new CryptoPP::SignerFilter(rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        return signature;
    }

    // Verify signature
    bool verify(const std::string& message, const std::string& signature) {
        try {
            std::string recovered;
            CryptoPP::StringSource(signature + message, true,
                new CryptoPP::SignatureVerificationFilter(verifier,
                    new CryptoPP::StringSink(recovered)
                )
            );
            return recovered == message;
        }
        catch (const CryptoPP::Exception&) {
            return false;
        }
    }
};

int main() {
    Ed25519KeyPair keys;

    // Generate and save keys
    keys.generate();
    keys.savePrivateKey("private.key");
    keys.savePublicKey("public.key");

    std::cout << "Keys generated and saved" << std::endl;
    std::cout << "Public key: " << keys.getPublicKeyHex() << std::endl;

    // Sign a message
    std::string message = "Important contract agreement";
    std::string signature = keys.sign(message);

    std::cout << "\nSigned message" << std::endl;

    // Load public key and verify (simulating another party)
    Ed25519KeyPair verifierKeys;
    verifierKeys.loadPublicKey("public.key");

    bool valid = verifierKeys.verify(message, signature);
    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

---

## Key Exchange with X25519

**When to use:** Establishing secure communication channels, TLS-like protocols

**What it does:** Two parties can agree on a shared secret without transmitting the secret

### Basic Key Exchange

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Alice generates her key pair
    x25519 alicePrivate, alicePublic;
    alicePrivate.GenerateRandom(rng);
    alicePrivate.GeneratePublicKey(alicePublic);

    // Bob generates his key pair
    x25519 bobPrivate, bobPublic;
    bobPrivate.GenerateRandom(rng);
    bobPrivate.GeneratePublicKey(bobPublic);

    // Alice and Bob exchange public keys (these can be sent over insecure channel)
    // Now they compute the shared secret

    SecByteBlock aliceSharedSecret(32), bobSharedSecret(32);

    // Alice computes shared secret using her private key and Bob's public key
    if (!alicePrivate.Agree(aliceSharedSecret, alicePublic, bobPublic)) {
        std::cerr << "Alice: key agreement failed" << std::endl;
        return 1;
    }

    // Bob computes shared secret using his private key and Alice's public key
    if (!bobPrivate.Agree(bobSharedSecret, bobPublic, alicePublic)) {
        std::cerr << "Bob: key agreement failed" << std::endl;
        return 1;
    }

    // Verify both computed the same shared secret
    if (aliceSharedSecret == bobSharedSecret) {
        std::cout << "Key exchange successful!" << std::endl;
        std::cout << "Both parties have the same shared secret" << std::endl;

        // Convert to hex for display
        std::string hex;
        HexEncoder encoder(new StringSink(hex));
        encoder.Put(aliceSharedSecret, aliceSharedSecret.size());
        encoder.MessageEnd();

        std::cout << "Shared secret: " << hex << std::endl;
    } else {
        std::cout << "✗ Key exchange failed - secrets don't match!" << std::endl;
    }

    return 0;
}
```

### Secure Communication with X25519 + AES-GCM

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

class SecureChannel {
private:
    CryptoPP::SecByteBlock sharedSecret;
    CryptoPP::SecByteBlock encryptionKey;
    CryptoPP::AutoSeededRandomPool rng;

    // Derive encryption key from shared secret using HKDF
    void deriveKey() {
        encryptionKey.resize(32);  // 256-bit key

        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(
            encryptionKey, encryptionKey.size(),
            sharedSecret, sharedSecret.size(),
            nullptr, 0,  // No salt
            (const CryptoPP::byte*)"encryption", 10  // Info parameter
        );
    }

public:
    // Establish shared secret from key exchange
    void establish(const CryptoPP::SecByteBlock& secret) {
        sharedSecret = secret;
        deriveKey();
    }

    // Encrypt a message
    std::string encrypt(const std::string& plaintext) {
        // Generate random nonce
        CryptoPP::SecByteBlock nonce(12);
        rng.GenerateBlock(nonce, nonce.size());

        // Encrypt
        std::string ciphertext;
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(encryptionKey, encryptionKey.size(), nonce, nonce.size());

        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Return nonce + ciphertext
        std::string result((char*)nonce.data(), nonce.size());
        result += ciphertext;
        return result;
    }

    // Decrypt a message
    bool decrypt(const std::string& encrypted, std::string& plaintext) {
        if (encrypted.size() < 12) return false;

        // Extract nonce and ciphertext
        CryptoPP::SecByteBlock nonce((const CryptoPP::byte*)encrypted.data(), 12);
        std::string ciphertext = encrypted.substr(12);

        try {
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(encryptionKey, encryptionKey.size(), nonce, nonce.size());

            CryptoPP::StringSource(ciphertext, true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(plaintext)
                )
            );
            return true;
        }
        catch (const CryptoPP::Exception&) {
            return false;
        }
    }
};

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Alice and Bob perform key exchange
    x25519 alicePrivate, alicePublic;
    alicePrivate.GenerateRandom(rng);
    alicePrivate.GeneratePublicKey(alicePublic);

    x25519 bobPrivate, bobPublic;
    bobPrivate.GenerateRandom(rng);
    bobPrivate.GeneratePublicKey(bobPublic);

    SecByteBlock aliceShared(32), bobShared(32);
    alicePrivate.Agree(aliceShared, alicePublic, bobPublic);
    bobPrivate.Agree(bobShared, bobPublic, alicePublic);

    // Establish secure channels
    SecureChannel aliceChannel, bobChannel;
    aliceChannel.establish(aliceShared);
    bobChannel.establish(bobShared);

    // Alice sends encrypted message to Bob
    std::string message = "Meet at the usual place at 3pm";
    std::string encrypted = aliceChannel.encrypt(message);

    std::cout << "Alice sends encrypted message (" << encrypted.size() << " bytes)" << std::endl;

    // Bob decrypts message from Alice
    std::string decrypted;
    if (bobChannel.decrypt(encrypted, decrypted)) {
        std::cout << "Bob received: " << decrypted << std::endl;
    } else {
        std::cout << "Decryption failed!" << std::endl;
    }

    return 0;
}
```

---

## RSA Encryption

**When to use:** Legacy systems, compatibility requirements

**What it does:** Encrypt data with public key, decrypt with private key

**Note:** For new projects, prefer X25519 + symmetric encryption. RSA is slower and requires larger keys for equivalent security.

### RSA-OAEP Encryption

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate RSA key pair (2048-bit)
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    RSA::PublicKey publicKey(privateKey);

    // Encrypt with public key
    std::string plaintext = "Secret message";
    std::string ciphertext;

    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    StringSource(plaintext, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;

    // Decrypt with private key
    std::string decrypted;

    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    StringSource(ciphertext, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(decrypted)
        )
    );

    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```

---

## ECDSA Signatures

**When to use:** NIST compliance requirements, existing ECDSA infrastructure

**What it does:** Digital signatures using elliptic curves

### ECDSA with P-256 Curve

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate ECDSA key pair using P-256 (secp256r1) curve
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Validate keys
    if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3)) {
        std::cerr << "Key validation failed" << std::endl;
        return 1;
    }

    // Sign message
    std::string message = "Transaction: Transfer $100";
    std::string signature;

    ECDSA<ECP, SHA256>::Signer signer(privateKey);

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature size: " << signature.size() << " bytes" << std::endl;

    // Verify signature
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    bool valid = false;
    StringSource(signature + message, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid))
        )
    );

    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

---

## Best Practices

### Key Generation
- **Always use `AutoSeededRandomPool`** for key generation
- Never reuse keys across different algorithms
- Generate keys with appropriate sizes:
  - Ed25519/X25519: Fixed 256-bit (secure)
  - RSA: Minimum 2048-bit, prefer 4096-bit
  - ECDSA: Use P-256 or higher curves

### Key Storage
- **Private keys must be protected:**
  - Encrypt private keys at rest
  - Use OS key stores (Windows: DPAPI, macOS: Keychain, Linux: Keyring)
  - Never hard-code private keys
  - Use `SecByteBlock` for in-memory keys
- **Public keys can be freely distributed:**
  - Share via certificates, key servers, or direct exchange
  - Verify authenticity through trusted channels

### Algorithm Selection
**For new projects:**
- **Signatures**: Use Ed25519
- **Key exchange**: Use X25519
- **Hybrid encryption**: X25519 + AES-GCM

**For compatibility:**
- **Signatures**: ECDSA with P-256, or RSA-2048+
- **Key exchange**: ECDH with P-256, or traditional DH
- **Encryption**: RSA-OAEP with 2048-bit+ keys

### Common Pitfalls

❌ **Don't encrypt large data with RSA:**
```cpp
// BAD: RSA can only encrypt small messages
std::string largeFile = readFile("document.pdf");  // 5 MB
// This will fail! RSA has message size limits
```

✅ **Do use hybrid encryption:**
```cpp
// GOOD: Use public-key crypto for key exchange, symmetric for data
SecByteBlock aesKey = generateAESKey();
std::string encryptedKey = rsaEncrypt(aesKey);
std::string encryptedData = aesGcmEncrypt(largeFile, aesKey);
// Send both encryptedKey and encryptedData
```

❌ **Don't sign without hashing:**
```cpp
// BAD: Never sign raw data with RSA
rsaSigner.sign(largeData);  // Vulnerable to attacks
```

✅ **Do hash before signing:**
```cpp
// GOOD: Hash the data first (or use RSASS-PSS)
std::string hash = sha256(largeData);
std::string signature = rsaSigner.sign(hash);
```

---

## Performance Comparison

**Key generation time (approximate):**
- Ed25519: ~0.5 ms
- ECDSA P-256: ~1 ms
- RSA-2048: ~100 ms
- RSA-4096: ~500 ms

**Signature generation:**
- Ed25519: ~0.05 ms (fastest)
- ECDSA P-256: ~0.5 ms
- RSA-2048: ~1 ms
- RSA-4096: ~5 ms

**Signature verification:**
- Ed25519: ~0.1 ms (fastest)
- ECDSA P-256: ~1 ms
- RSA-2048: ~0.05 ms (fast verification)
- RSA-4096: ~0.1 ms

**Key sizes:**
- Ed25519 public key: 32 bytes
- ECDSA P-256 public key: ~65 bytes
- RSA-2048 public key: ~294 bytes
- RSA-4096 public key: ~550 bytes

---

## Security Considerations

### Quantum Resistance
**Current status:** None of these algorithms are quantum-resistant

- Ed25519/X25519: Vulnerable to quantum computers
- ECDSA/ECDH: Vulnerable to quantum computers
- RSA: Vulnerable to quantum computers

**Future-proofing:**
- Monitor post-quantum cryptography standards (NIST PQC)
- Plan migration paths for when quantum computers become practical
- Consider hybrid schemes combining classical and post-quantum algorithms

### Side-Channel Attacks
- Ed25519 and X25519 have built-in side-channel resistance
- Use constant-time implementations (cryptopp-modern does this)
- Protect private keys in memory using `SecByteBlock`

### Implementation Vulnerabilities
- Keep cryptopp-modern updated for security patches
- Validate all keys after generation or loading
- Use authenticated encryption modes (GCM, not just CBC)

---

## Next Steps

- [Security Concepts](../../guides/security-concepts) - Essential security practices
- [Symmetric Encryption](../symmetric) - AES-GCM for data encryption
- [Hash Functions](../hashing) - SHA-256, BLAKE3 for data integrity
- [Beginner's Guide](../../guides/beginners-guide) - Complete tutorial

---

## Compile Examples

All examples can be compiled with:

```bash
g++ -std=c++11 example.cpp -o example -lcryptopp
./example
```
