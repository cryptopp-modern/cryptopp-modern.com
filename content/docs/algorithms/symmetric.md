---
title: Symmetric Encryption
weight: 80
---

Symmetric encryption uses the same key for both encryption and decryption. cryptopp-modern provides comprehensive support for modern symmetric ciphers and modes of operation.

## Supported Algorithms

### Block Ciphers
- **AES** (Advanced Encryption Standard) - Industry standard, FIPS approved
- **ChaCha20** - Modern stream cipher, excellent performance
- **Serpent** - Highly secure block cipher
- **Twofish** - Fast and flexible
- **Camellia** - International standard (ISO/IEC 18033-3)
- **ARIA** - Korean standard (RFC 5794)

### Modes of Operation
- **GCM** (Galois/Counter Mode) - Authenticated encryption (recommended)
- **CCM** (Counter with CBC-MAC) - Authenticated encryption
- **EAX** - Authenticated encryption
- **CBC** (Cipher Block Chaining) - Traditional mode
- **CTR** (Counter) - Stream cipher mode
- **CFB** (Cipher Feedback) - Stream cipher mode
- **OFB** (Output Feedback) - Stream cipher mode

## Quick Comparison

| Algorithm | Key Size | Speed | Security | Use Case |
|-----------|----------|-------|----------|----------|
| AES-GCM | 128/192/256-bit | Very Fast | ⭐⭐⭐⭐⭐ | General purpose (recommended) |
| ChaCha20-Poly1305 | 256-bit | Very Fast | ⭐⭐⭐⭐⭐ | Mobile, no AES hardware |
| AES-CBC | 128/192/256-bit | Fast | ⭐⭐⭐⭐ | Legacy compatibility |
| AES-CTR | 128/192/256-bit | Fast | ⭐⭐⭐⭐ | Parallel encryption |

## AES-GCM (Recommended)

AES-GCM provides both encryption and authentication, protecting against tampering. This is the recommended mode for most applications.

### Encryption with AES-GCM

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate random key and IV
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);  // 128-bit
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);           // 128-bit
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    // Plaintext
    std::string plaintext = "Secret message to encrypt";
    std::string ciphertext, recovered;

    try {
        // Encryption
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss1(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Decryption
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss2(ciphertext, true,
            new CryptoPP::AuthenticatedDecryptionFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        std::cout << "Plaintext:  " << plaintext << std::endl;
        std::cout << "Recovered:  " << recovered << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### AES-GCM with Additional Authenticated Data (AAD)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <string>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(12);  // GCM commonly uses 96-bit IV
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plaintext = "Secret data";
    std::string aad = "Version:1.0,UserID:12345";  // Authenticated but not encrypted
    std::string ciphertext, recovered, recoveredAAD;

    try {
        // Encryption with AAD
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::AuthenticatedEncryptionFilter ef(enc,
            new CryptoPP::StringSink(ciphertext)
        );

        ef.ChannelPut(CryptoPP::AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, (const CryptoPP::byte*)plaintext.data(), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        // Decryption with AAD verification
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(dec,
            new CryptoPP::StringSink(recovered)
        );

        df.ChannelPut(CryptoPP::AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, (const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        std::cout << "Plaintext: " << plaintext << std::endl;
        std::cout << "AAD: " << aad << std::endl;
        std::cout << "Recovered: " << recovered << std::endl;
        std::cout << "Authentication: OK" << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Authentication failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### ⚠️ Critical: GCM Nonce Reuse

**GCM has a catastrophic failure mode if you reuse a nonce (IV) with the same key.** Nonce reuse completely breaks GCM security and can leak your encryption key.

#### The Problem

```cpp
// DANGEROUS: Reusing the same nonce
CryptoPP::SecByteBlock key(16);
CryptoPP::SecByteBlock nonce(12);
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(nonce, nonce.size());  // Generated once

CryptoPP::GCM<CryptoPP::AES>::Encryption enc;

// First message - OK
enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
// ... encrypt message 1

// Second message - CATASTROPHIC FAILURE!
enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());  // SAME NONCE!
// ... encrypt message 2
// Security is now completely broken!
```

**What happens with nonce reuse:**
- Attacker can XOR two ciphertexts to cancel out the keystream
- Authentication key is exposed
- Attacker can forge authenticated messages
- Entire key must be considered compromised

#### Safe GCM Usage

**Option 1: Random Nonces (Recommended for most cases)**

```cpp
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock key(16);
prng.GenerateBlock(key, key.size());

// Generate NEW random nonce for EACH encryption
for (int i = 0; i < messages.size(); i++) {
    CryptoPP::SecByteBlock nonce(12);  // 96-bit nonce
    prng.GenerateBlock(nonce, nonce.size());  // NEW NONCE EVERY TIME

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    // ... encrypt message
    // Store nonce with ciphertext: nonce || ciphertext || tag
}
```

**Limitations:**
- With 96-bit random nonces, you have ~2^48 encryptions before collision risk
- After 2^32 messages, consider rotating the key
- Never encrypt more than 2^48 messages with the same key

**Option 2: Counter-Based Nonces**

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cstring>
#include <atomic>

class SafeGCM {
private:
    CryptoPP::SecByteBlock key;
    std::atomic<uint64_t> counter;

public:
    SafeGCM() : key(16), counter(0) {
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
    }

    std::string encrypt(const std::string& plaintext) {
        // Get next counter value
        uint64_t count = counter.fetch_add(1);

        // Ensure we don't overflow
        if (count >= (1ULL << 48)) {
            throw std::runtime_error("Nonce space exhausted - must rotate key!");
        }

        // Build nonce: 32-bit fixed || 64-bit counter
        CryptoPP::SecByteBlock nonce(12);
        memset(nonce, 0, 4);  // Fixed 32-bit prefix
        memcpy(nonce + 4, &count, 8);  // 64-bit counter

        // Encrypt
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        std::string ciphertext;
        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Return: nonce || ciphertext (includes auth tag)
        return std::string((char*)nonce.data(), nonce.size()) + ciphertext;
    }

    bool decrypt(const std::string& stored, std::string& recovered) {
        if (stored.size() < 12 + 16) {  // nonce + min ciphertext + tag
            return false;
        }

        // Extract nonce and ciphertext
        CryptoPP::SecByteBlock nonce((const CryptoPP::byte*)stored.data(), 12);
        std::string ciphertext = stored.substr(12);

        try {
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

            CryptoPP::StringSource(ciphertext, true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(recovered)
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
    SafeGCM gcm;

    // Safe: Each encryption uses a unique nonce
    std::string enc1 = gcm.encrypt("Message 1");
    std::string enc2 = gcm.encrypt("Message 2");
    std::string enc3 = gcm.encrypt("Message 3");

    std::string dec;
    if (gcm.decrypt(enc1, dec)) {
        std::cout << "Decrypted: " << dec << std::endl;
    }

    return 0;
}
```

**Benefits of counter-based nonces:**
- No collision risk (deterministic)
- Can encrypt 2^64 messages safely
- Track usage and enforce key rotation
- Suitable for high-throughput systems

**Option 3: Derived Nonces (Advanced)**

For protocols where you can't store nonces:

```cpp
// Derive unique nonce from message-specific data
// WARNING: Derivation input MUST be unique per message!
std::string deriveNonce(const std::string& messageId) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(messageId, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::StringSink(digest)
        )
    );

    // Use first 12 bytes of hash as nonce
    return digest.substr(0, 12);
}

// messageId must be unique (e.g., UUID, database ID, timestamp+counter)
std::string nonce = deriveNonce(uniqueMessageId);
```

#### Key Rotation

When to rotate keys:
- After 2^32 encryptions (4 billion) - hard limit for random nonces
- After 2^48 encryptions with counter-based nonces
- On any suspected nonce reuse
- Periodically as policy (e.g., every 90 days)

```cpp
class KeyRotatingGCM {
private:
    CryptoPP::SecByteBlock currentKey;
    std::atomic<uint64_t> messageCount;
    const uint64_t MAX_MESSAGES = (1ULL << 32);  // 2^32

public:
    void checkAndRotate() {
        if (messageCount.load() >= MAX_MESSAGES) {
            // Generate new key
            CryptoPP::AutoSeededRandomPool prng;
            currentKey.resize(16);
            prng.GenerateBlock(currentKey, currentKey.size());
            messageCount = 0;

            // Store new key securely and notify system
        }
    }

    std::string encrypt(const std::string& plaintext) {
        checkAndRotate();
        messageCount++;
        // ... perform encryption with currentKey
    }
};
```

#### Detection and Recovery

If you suspect nonce reuse has occurred:

1. **Immediately stop using the compromised key**
2. **Generate a new key**
3. **Re-encrypt all data with the new key**
4. **Investigate the cause** to prevent recurrence
5. **Audit logs** for potential exploitation

#### Summary: GCM Nonce Safety

✅ **DO:**
- Generate a new random nonce for every encryption
- Use counter-based nonces with proper tracking
- Store nonces with ciphertext (they're not secret)
- Rotate keys before reaching nonce limits
- Use 96-bit (12-byte) nonces for optimal performance

❌ **DON'T:**
- Ever reuse a nonce with the same key
- Use predictable nonces without proper construction
- Exceed 2^32 encryptions with random nonces
- Assume the library will prevent reuse (it won't)

**GCM is excellent when used correctly, but unforgiving of mistakes. If you're uncertain about nonce management, consider using ChaCha20-Poly1305 or implementing a well-tested wrapper class.**

## ChaCha20

ChaCha20 is a modern stream cipher designed by Daniel J. Bernstein. It's particularly useful when AES hardware acceleration is not available.

### ChaCha20-Poly1305 Encryption

```cpp
#include <cryptopp/chacha.h>
#include <cryptopp/poly1305.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // ChaCha20 uses 256-bit key and 96-bit IV
    CryptoPP::SecByteBlock key(32);
    CryptoPP::SecByteBlock iv(12);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plaintext = "Message encrypted with ChaCha20";
    std::string ciphertext, recovered;

    try {
        // Encryption
        CryptoPP::ChaCha::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss1(plaintext, true,
            new CryptoPP::StreamTransformationFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Decryption
        CryptoPP::ChaCha::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss2(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        std::cout << "Plaintext:  " << plaintext << std::endl;
        std::cout << "Recovered:  " << recovered << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## AES-CBC

CBC mode is a traditional block cipher mode. Note: CBC requires manual padding and does not provide authentication.

### AES-CBC Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Key and IV
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plaintext = "CBC mode encryption example";
    std::string ciphertext, recovered;

    try {
        // Encryption
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource ss1(plaintext, true,
            new CryptoPP::StreamTransformationFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Decryption
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource ss2(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        std::cout << "Plaintext:  " << plaintext << std::endl;
        std::cout << "Recovered:  " << recovered << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### AES-CBC with HMAC (Encrypt-then-MAC)

CBC mode does not provide authentication. For secure CBC usage, combine it with HMAC using the Encrypt-then-MAC construction.

#### Encryption with HMAC-SHA256

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Separate keys for encryption and authentication (important!)
    CryptoPP::SecByteBlock encKey(CryptoPP::AES::DEFAULT_KEYLENGTH);  // 128-bit
    CryptoPP::SecByteBlock macKey(32);  // 256-bit for HMAC-SHA256
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    prng.GenerateBlock(encKey, encKey.size());
    prng.GenerateBlock(macKey, macKey.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plaintext = "Sensitive data requiring authentication";
    std::string ciphertext, mac;

    try {
        // Step 1: Encrypt with AES-CBC
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(encKey, encKey.size(), iv);

        CryptoPP::StringSource ss1(plaintext, true,
            new CryptoPP::StreamTransformationFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Step 2: Compute HMAC over IV + Ciphertext (Encrypt-then-MAC)
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());

        std::string authData = std::string((char*)iv.data(), iv.size()) + ciphertext;

        CryptoPP::StringSource ss2(authData, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(mac)
            )
        );

        std::cout << "Encryption successful" << std::endl;
        std::cout << "Ciphertext length: " << ciphertext.size() << " bytes" << std::endl;
        std::cout << "MAC length: " << mac.size() << " bytes" << std::endl;

        // In practice, store: IV || Ciphertext || MAC
        std::string stored = std::string((char*)iv.data(), iv.size()) + ciphertext + mac;

    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

#### Decryption with HMAC Verification

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <string>

bool decryptAndVerify(
    const std::string& stored,
    const CryptoPP::SecByteBlock& encKey,
    const CryptoPP::SecByteBlock& macKey,
    std::string& recovered)
{
    const size_t IV_SIZE = CryptoPP::AES::BLOCKSIZE;
    const size_t MAC_SIZE = CryptoPP::SHA256::DIGESTSIZE;

    // Validate minimum size
    if (stored.size() < IV_SIZE + MAC_SIZE) {
        std::cerr << "Invalid stored data size" << std::endl;
        return false;
    }

    // Extract components: IV || Ciphertext || MAC
    std::string ivStr = stored.substr(0, IV_SIZE);
    std::string ciphertext = stored.substr(IV_SIZE, stored.size() - IV_SIZE - MAC_SIZE);
    std::string receivedMac = stored.substr(stored.size() - MAC_SIZE);

    CryptoPP::SecByteBlock iv((const CryptoPP::byte*)ivStr.data(), ivStr.size());

    try {
        // Step 1: Verify HMAC (authenticate before decrypting)
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());

        std::string authData = ivStr + ciphertext;
        std::string computedMac;

        CryptoPP::StringSource ss1(authData, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(computedMac)
            )
        );

        // Constant-time comparison
        if (!CryptoPP::VerifyBufsEqual(
                (const CryptoPP::byte*)computedMac.data(),
                (const CryptoPP::byte*)receivedMac.data(),
                MAC_SIZE)) {
            std::cerr << "HMAC verification failed - data may be tampered!" << std::endl;
            return false;
        }

        // Step 2: Decrypt (only if HMAC verified)
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(encKey, encKey.size(), iv);

        CryptoPP::StringSource ss2(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        return true;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
        return false;
    }
}

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock encKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock macKey(32);
    prng.GenerateBlock(encKey, encKey.size());
    prng.GenerateBlock(macKey, macKey.size());

    // Simulate stored encrypted data
    std::string stored = "...";  // IV || Ciphertext || MAC
    std::string recovered;

    if (decryptAndVerify(stored, encKey, macKey, recovered)) {
        std::cout << "Decryption successful" << std::endl;
        std::cout << "Recovered: " << recovered << std::endl;
    } else {
        std::cerr << "Decryption or verification failed" << std::endl;
    }

    return 0;
}
```

#### Complete Example: Encrypt-then-MAC

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

class EncryptThenMAC {
private:
    CryptoPP::SecByteBlock encKey;
    CryptoPP::SecByteBlock macKey;

public:
    EncryptThenMAC() : encKey(CryptoPP::AES::DEFAULT_KEYLENGTH), macKey(32) {
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(encKey, encKey.size());
        prng.GenerateBlock(macKey, macKey.size());
    }

    std::string encrypt(const std::string& plaintext) {
        CryptoPP::AutoSeededRandomPool prng;

        // Generate random IV
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
        prng.GenerateBlock(iv, iv.size());

        // Encrypt
        std::string ciphertext;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(encKey, encKey.size(), iv);

        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::StreamTransformationFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Compute HMAC over IV + Ciphertext
        std::string mac;
        std::string authData = std::string((char*)iv.data(), iv.size()) + ciphertext;

        CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());
        CryptoPP::StringSource(authData, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(mac)
            )
        );

        // Return: IV || Ciphertext || MAC
        return std::string((char*)iv.data(), iv.size()) + ciphertext + mac;
    }

    bool decrypt(const std::string& stored, std::string& recovered) {
        const size_t IV_SIZE = CryptoPP::AES::BLOCKSIZE;
        const size_t MAC_SIZE = CryptoPP::SHA256::DIGESTSIZE;

        if (stored.size() < IV_SIZE + MAC_SIZE) {
            return false;
        }

        // Extract components
        std::string ivStr = stored.substr(0, IV_SIZE);
        std::string ciphertext = stored.substr(IV_SIZE, stored.size() - IV_SIZE - MAC_SIZE);
        std::string receivedMac = stored.substr(stored.size() - MAC_SIZE);

        // Verify HMAC
        std::string computedMac;
        std::string authData = ivStr + ciphertext;

        CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());
        CryptoPP::StringSource(authData, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(computedMac)
            )
        );

        if (!CryptoPP::VerifyBufsEqual(
                (const CryptoPP::byte*)computedMac.data(),
                (const CryptoPP::byte*)receivedMac.data(),
                MAC_SIZE)) {
            return false;
        }

        // Decrypt
        CryptoPP::SecByteBlock iv((const CryptoPP::byte*)ivStr.data(), ivStr.size());
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(encKey, encKey.size(), iv);

        try {
            CryptoPP::StringSource(ciphertext, true,
                new CryptoPP::StreamTransformationFilter(dec,
                    new CryptoPP::StringSink(recovered)
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
    EncryptThenMAC crypto;

    std::string plaintext = "Secret message with authentication";

    // Encrypt
    std::string encrypted = crypto.encrypt(plaintext);
    std::cout << "Encrypted length: " << encrypted.size() << " bytes" << std::endl;

    // Decrypt
    std::string decrypted;
    if (crypto.decrypt(encrypted, decrypted)) {
        std::cout << "Original:  " << plaintext << std::endl;
        std::cout << "Decrypted: " << decrypted << std::endl;
        std::cout << "Match: " << (plaintext == decrypted ? "YES" : "NO") << std::endl;
    } else {
        std::cerr << "Decryption failed!" << std::endl;
    }

    // Test tampering detection
    encrypted[20] ^= 0x01;  // Flip one bit
    if (!crypto.decrypt(encrypted, decrypted)) {
        std::cout << "Tampering detected correctly!" << std::endl;
    }

    return 0;
}
```

#### Security Best Practices for CBC + HMAC

**Always use separate keys:**
```cpp
// GOOD: Different keys for encryption and MAC
CryptoPP::SecByteBlock encKey(16);
CryptoPP::SecByteBlock macKey(32);

// BAD: Never use the same key
// CryptoPP::SecByteBlock key(16);
// Use 'key' for both encryption and HMAC - NO!
```

**Always use Encrypt-then-MAC (not MAC-then-Encrypt):**
```cpp
// GOOD: Encrypt then compute HMAC over ciphertext
std::string ciphertext = encrypt(plaintext);
std::string mac = hmac(ciphertext);

// BAD: MAC-then-Encrypt is vulnerable to padding oracle attacks
// std::string mac = hmac(plaintext);
// std::string ciphertext = encrypt(plaintext + mac);  // NO!
```

**Verify HMAC before decrypting:**
```cpp
// GOOD: Check authentication first
if (verify_hmac(data)) {
    plaintext = decrypt(data);
}

// BAD: Decrypt then verify
// plaintext = decrypt(data);  // NO! Decrypt untrusted data
// if (verify_hmac(data)) { ... }
```

**Include IV in HMAC computation:**
```cpp
// GOOD: HMAC covers IV and ciphertext
std::string authData = iv + ciphertext;
std::string mac = hmac(authData);

// BAD: Not authenticating IV allows attacks
// std::string mac = hmac(ciphertext);  // NO!
```

**Use constant-time comparison:**
```cpp
// GOOD: Prevents timing attacks
bool valid = CryptoPP::VerifyBufsEqual(computed, received, MAC_SIZE);

// BAD: Variable-time comparison
// bool valid = (computed == received);  // NO!
```

## AES-CTR

Counter mode turns a block cipher into a stream cipher and allows parallel encryption/decryption.

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plaintext = "CTR mode allows parallel processing";
    std::string ciphertext, recovered;

    // Encryption
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::StreamTransformationFilter(enc,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Decryption
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(dec,
            new CryptoPP::StringSink(recovered)
        )
    );

    std::cout << "Plaintext:  " << plaintext << std::endl;
    std::cout << "Recovered:  " << recovered << std::endl;

    return 0;
}
```

## Key Sizes

### AES
- **AES-128**: 128-bit key (16 bytes) - Fast, secure for most uses
- **AES-192**: 192-bit key (24 bytes) - Higher security margin
- **AES-256**: 256-bit key (32 bytes) - Maximum security

```cpp
// AES-128
CryptoPP::SecByteBlock key128(CryptoPP::AES::DEFAULT_KEYLENGTH);  // 16 bytes

// AES-256
CryptoPP::SecByteBlock key256(CryptoPP::AES::MAX_KEYLENGTH);      // 32 bytes

CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
enc.SetKeyWithIV(key256, key256.size(), iv, iv.size());
```

### ChaCha20
- **Fixed**: 256-bit key (32 bytes)

```cpp
CryptoPP::SecByteBlock key(32);  // ChaCha20 always uses 256-bit keys
```

## IV/Nonce Requirements

### GCM Mode
- **Size**: 96 bits (12 bytes) recommended
- **Uniqueness**: MUST be unique for each encryption with same key
- **Random or counter**: Both acceptable

```cpp
CryptoPP::SecByteBlock iv(12);  // 96-bit IV for GCM
prng.GenerateBlock(iv, iv.size());
```

### CBC Mode
- **Size**: 128 bits (16 bytes) for AES
- **Uniqueness**: Must be unpredictable
- **Random**: Should be random

```cpp
CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);  // 128-bit
prng.GenerateBlock(iv, iv.size());
```

### CTR Mode
- **Size**: 128 bits (16 bytes) for AES
- **Uniqueness**: Must be unique (can use counter)
- **Never reuse**: Critical for security

## Security Best Practices

### Always Use Authenticated Encryption
```cpp
// GOOD: AES-GCM provides authentication
CryptoPP::GCM<CryptoPP::AES>::Encryption enc;

// BAD: CBC does not authenticate
// Use HMAC separately if you must use CBC
```

### Never Reuse IV/Nonce
```cpp
// GOOD: Generate new IV for each encryption
for (int i = 0; i < messages.size(); i++) {
    prng.GenerateBlock(iv, iv.size());
    // ... encrypt with new IV
}

// BAD: Reusing IV breaks security
// CryptoPP::SecByteBlock iv(12);
// prng.GenerateBlock(iv, iv.size());  // Only once - NO!
```

### Use Strong Random Keys
```cpp
// GOOD: Cryptographically secure random
CryptoPP::AutoSeededRandomPool prng;
prng.GenerateBlock(key, key.size());

// BAD: Weak randomness
// srand(time(NULL));  // NO!
// for (int i = 0; i < key.size(); i++)
//     key[i] = rand();  // NO!
```

### Store IV with Ciphertext
```cpp
// Typical storage format: IV || Ciphertext || AuthTag (for GCM)
std::string stored = ivStr + ciphertext;  // IV is not secret

// When decrypting, extract IV first
std::string ivStr = stored.substr(0, 12);
std::string ciphertext = stored.substr(12);
```

## When to Use Each Mode

### Use AES-GCM when:
- You need encryption and authentication
- Hardware AES acceleration is available
- General-purpose encryption (most common case)

### Use ChaCha20-Poly1305 when:
- No AES hardware acceleration
- Mobile devices
- Software-only implementations

### Use AES-CBC when:
- Legacy system compatibility
- You can add HMAC for authentication
- Specific protocol requirements

### Use AES-CTR when:
- You need parallelizable encryption
- Random access to encrypted data
- Streaming applications (with authentication)

## Performance Considerations

### Hardware Acceleration
Modern CPUs have AES-NI instructions that make AES extremely fast:
- **With AES-NI**: AES-GCM > 2 GB/s
- **Without AES-NI**: ChaCha20 > 500 MB/s

### Benchmarking
```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <chrono>

// Benchmark your specific use case
auto start = std::chrono::high_resolution_clock::now();
// ... perform encryption
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
```

## Building

All symmetric ciphers are included by default in cryptopp-modern.

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/chacha.h>
#include <cryptopp/modes.h>
```

Compile:
```bash
g++ -std=c++11 myapp.cpp -o myapp -lcryptopp
```

## Further Reading

- [NIST SP 800-38D: GCM Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 7539: ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc7539.html)
- [NIST AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
