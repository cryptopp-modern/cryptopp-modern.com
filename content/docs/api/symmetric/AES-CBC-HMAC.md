---
title: AES-CBC with HMAC
description: AES-CBC mode with HMAC authentication (Encrypt-then-MAC)
weight: 3
---

**Header:** `#include <cryptopp/aes.h>`, `#include <cryptopp/modes.h>`,  
and `#include <cryptopp/hmac.h>`
**Namespace:** `CryptoPP`  
**Since:** Crypto++ 3.1 (AES), 4.0 (CBC), 5.0 (HMAC)  
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

AES-CBC (Cipher Block Chaining) with HMAC provides authenticated encryption using the Encrypt-then-MAC construction. While modern applications should prefer AES-GCM or ChaCha20-Poly1305, CBC+HMAC remains important for legacy systems and standards compliance.

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate keys
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);   // 128-bit
    SecByteBlock hmacKey(SHA256::DIGESTSIZE);       // 256-bit
    byte iv[AES::BLOCKSIZE];                        // 128-bit IV

    rng.GenerateBlock(aesKey, aesKey.size());
    rng.GenerateBlock(hmacKey, hmacKey.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Secret message";

    // Encrypt with AES-CBC
    std::string ciphertext;
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(aesKey, aesKey.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Compute HMAC over IV + ciphertext
    std::string mac;
    HMAC<SHA256> hmac(hmacKey, hmacKey.size());

    StringSource(std::string((char*)iv, sizeof(iv)) + ciphertext, true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );

    std::cout << "Encrypted " << plaintext.size() << " bytes" << std::endl;
    std::cout << "MAC size: " << mac.size() << " bytes" << std::endl;

    // In a real protocol, 'receivedMac' would come from the peer
    std::string receivedMac = mac;

    // Verify HMAC (constant-time) before decrypting
    std::string computedMac;
    HMAC<SHA256> hmacVerify(hmacKey, hmacKey.size());

    StringSource(std::string((char*)iv, sizeof(iv)) + ciphertext, true,
        new HashFilter(hmacVerify,
            new StringSink(computedMac)
        )
    );

    // Use constant-time comparison for MACs
    if (!VerifyBufsEqual(
            reinterpret_cast<const byte*>(receivedMac.data()),
            reinterpret_cast<const byte*>(computedMac.data()),
            SHA256::DIGESTSIZE))
    {
        std::cerr << "Authentication failed!" << std::endl;
        return 1;
    }

    // Decrypt
    std::string recovered;
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(aesKey, aesKey.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    std::cout << "Decrypted: " << recovered << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="warning" >}}
**Modern Applications: Use AES-GCM or ChaCha20-Poly1305 instead.**

**Use AES-CBC+HMAC only for:**
- Legacy system compatibility
- Standards requiring CBC mode (TLS 1.2, etc.)
- When AEAD ciphers not available

**Critical Requirements:**
- **ALWAYS** use Encrypt-then-MAC (not MAC-then-Encrypt)
- **ALWAYS** verify HMAC before decrypting
- **NEVER** reuse IVs with the same key
- Use random IVs from CSPRNG
- Include IV in HMAC computation
- Use separate keys for AES and HMAC

**Padding Oracle Warning:**
CBC mode is vulnerable to padding oracle attacks. Only decrypt after HMAC verification succeeds.
{{< /callout >}}

## Encrypt-then-MAC Construction

The secure construction is:

1. Generate random IV
2. Encrypt plaintext with AES-CBC (produces ciphertext with padding)
3. Compute HMAC over (IV || ciphertext)
4. Send: IV || ciphertext || MAC

To decrypt:

1. Verify HMAC over (IV || ciphertext)
2. **ONLY** if HMAC valid, decrypt ciphertext
3. **NEVER** decrypt before HMAC verification

## Complete Example: Secure Authenticated Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <stdexcept>
#include <iostream>

using namespace CryptoPP;

class AES_CBC_HMAC {
public:
    AES_CBC_HMAC(const SecByteBlock& aesKey,
                 const SecByteBlock& hmacKey)
        : m_aesKey(aesKey), m_hmacKey(hmacKey) {
        // This example uses AES-128; adapt check for 192/256-bit keys if needed
        if (aesKey.size() != AES::DEFAULT_KEYLENGTH) {
            throw std::invalid_argument("AES key must be 16 bytes");
        }
        // HMAC key of 32 bytes is a good default; other sizes work too
        if (hmacKey.size() != SHA256::DIGESTSIZE) {
            throw std::invalid_argument("HMAC key must be 32 bytes");
        }
    }

    struct EncryptedMessage {
        byte iv[AES::BLOCKSIZE];
        std::string ciphertext;
        byte mac[SHA256::DIGESTSIZE];
    };

    EncryptedMessage encrypt(const std::string& plaintext) {
        EncryptedMessage msg;
        AutoSeededRandomPool rng;

        // Generate random IV
        rng.GenerateBlock(msg.iv, sizeof(msg.iv));

        // Encrypt with AES-CBC
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(m_aesKey, m_aesKey.size(), msg.iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(msg.ciphertext)
            )
        );

        // Compute HMAC over IV + ciphertext
        HMAC<SHA256> hmac(m_hmacKey, m_hmacKey.size());
        std::string macData(reinterpret_cast<char*>(msg.iv), sizeof(msg.iv));
        macData += msg.ciphertext;

        StringSource(macData, true,
            new HashFilter(hmac,
                new ArraySink(msg.mac, sizeof(msg.mac))
            )
        );

        return msg;
    }

    std::string decrypt(const EncryptedMessage& msg) {
        // Verify HMAC BEFORE decrypting
        HMAC<SHA256> hmac(m_hmacKey, m_hmacKey.size());
        std::string macData(reinterpret_cast<const char*>(msg.iv), sizeof(msg.iv));
        macData += msg.ciphertext;

        byte computedMac[SHA256::DIGESTSIZE];
        StringSource(macData, true,
            new HashFilter(hmac,
                new ArraySink(computedMac, sizeof(computedMac))
            )
        );

        // Constant-time comparison
        if (!VerifyBufsEqual(msg.mac, computedMac, sizeof(msg.mac))) {
            throw std::runtime_error("Authentication failed - HMAC mismatch");
        }

        // HMAC verified - safe to decrypt
        std::string recovered;
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(m_aesKey, m_aesKey.size(), msg.iv);

        try {
            StringSource(msg.ciphertext, true,
                new StreamTransformationFilter(dec,
                    new StringSink(recovered)
                )
            );
        } catch (const Exception& e) {
            throw std::runtime_error("Decryption failed");
        }

        return recovered;
    }

private:
    SecByteBlock m_aesKey;
    SecByteBlock m_hmacKey;
};

int main() {
    AutoSeededRandomPool rng;

    // Generate separate keys for AES and HMAC
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);   // 128-bit
    SecByteBlock hmacKey(SHA256::DIGESTSIZE);       // 256-bit

    rng.GenerateBlock(aesKey, aesKey.size());
    rng.GenerateBlock(hmacKey, hmacKey.size());

    AES_CBC_HMAC cipher(aesKey, hmacKey);

    // Encrypt message
    std::string plaintext = "Confidential document";
    auto encrypted = cipher.encrypt(plaintext);

    std::cout << "Encrypted: " << encrypted.ciphertext.size()
              << " bytes + " << sizeof(encrypted.iv) << " IV + "
              << sizeof(encrypted.mac) << " MAC" << std::endl;

    // Decrypt message
    try {
        std::string decrypted = cipher.decrypt(encrypted);
        std::cout << "Decrypted: " << decrypted << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // Try tampering with ciphertext
    encrypted.ciphertext[0] ^= 0x01;  // Flip one bit
    try {
        std::string decrypted = cipher.decrypt(encrypted);
        std::cout << "ERROR: Should have failed!" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Correctly rejected tampered message: "
                  << e.what() << std::endl;
    }

    return 0;
}
```

## Complete Example: File Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& aesKey,
                 const SecByteBlock& hmacKey) {
    AutoSeededRandomPool rng;

    // Generate random IV
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Open output file
    FileSink outFile(outputFile.c_str());

    // Write IV first
    outFile.Put(iv, sizeof(iv));

    // Encrypt file to temporary string (for HMAC)
    std::string ciphertext;
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(aesKey, aesKey.size(), iv);

    FileSource(inputFile.c_str(), true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Write ciphertext
    outFile.Put((const byte*)ciphertext.data(), ciphertext.size());

    // Compute HMAC over IV + ciphertext
    HMAC<SHA256> hmac(hmacKey, hmacKey.size());
    std::string macData(reinterpret_cast<char*>(iv), sizeof(iv));
    macData += ciphertext;

    byte mac[SHA256::DIGESTSIZE];
    StringSource(macData, true,
        new HashFilter(hmac,
            new ArraySink(mac, sizeof(mac))
        )
    );

    // Write MAC
    outFile.Put(mac, sizeof(mac));

    std::cout << "File encrypted: " << outputFile << std::endl;
    std::cout << "IV: " << sizeof(iv) << " bytes" << std::endl;
    std::cout << "Ciphertext: " << ciphertext.size() << " bytes" << std::endl;
    std::cout << "MAC: " << sizeof(mac) << " bytes" << std::endl;
}

void decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& aesKey,
                 const SecByteBlock& hmacKey) {
    // Read entire encrypted file
    std::string fileData;
    FileSource(inputFile.c_str(), true,
        new StringSink(fileData)
    );

    // Extract components
    const size_t ivSize = AES::BLOCKSIZE;
    const size_t macSize = SHA256::DIGESTSIZE;

    if (fileData.size() < ivSize + macSize) {
        throw std::runtime_error("Invalid encrypted file format");
    }

    byte iv[AES::BLOCKSIZE];
    memcpy(iv, fileData.data(), ivSize);

    size_t ciphertextSize = fileData.size() - ivSize - macSize;
    std::string ciphertext = fileData.substr(ivSize, ciphertextSize);

    byte mac[SHA256::DIGESTSIZE];
    memcpy(mac, fileData.data() + ivSize + ciphertextSize, macSize);

    // Verify HMAC BEFORE decrypting
    HMAC<SHA256> hmac(hmacKey, hmacKey.size());
    std::string macData(reinterpret_cast<char*>(iv), ivSize);
    macData += ciphertext;

    byte computedMac[SHA256::DIGESTSIZE];
    StringSource(macData, true,
        new HashFilter(hmac,
            new ArraySink(computedMac, sizeof(computedMac))
        )
    );

    // Constant-time comparison
    if (!VerifyBufsEqual(mac, computedMac, macSize)) {
        throw std::runtime_error("Authentication failed - file may be corrupted or tampered");
    }

    std::cout << "HMAC verified successfully" << std::endl;

    // HMAC verified - safe to decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(aesKey, aesKey.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new FileSink(outputFile.c_str())
        )
    );

    std::cout << "File decrypted: " << outputFile << std::endl;
}

int main() {
    AutoSeededRandomPool rng;

    // Generate keys
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    SecByteBlock hmacKey(SHA256::DIGESTSIZE);

    rng.GenerateBlock(aesKey, aesKey.size());
    rng.GenerateBlock(hmacKey, hmacKey.size());

    // Encrypt file
    encryptFile("document.pdf", "document.pdf.enc", aesKey, hmacKey);

    // Decrypt file
    try {
        decryptFile("document.pdf.enc", "document_recovered.pdf", aesKey, hmacKey);
    } catch (const std::exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
    }

    return 0;
}
```

## Key Sizes

### AES Key Sizes

```cpp
// 128-bit (recommended for most uses)
SecByteBlock key128(AES::DEFAULT_KEYLENGTH);  // 16 bytes

// 192-bit
SecByteBlock key192(24);

// 256-bit (maximum security)
SecByteBlock key256(AES::MAX_KEYLENGTH);  // 32 bytes
```

### HMAC Key Sizes

```cpp
// SHA-256 (recommended)
SecByteBlock hmacKey(SHA256::DIGESTSIZE);  // 32 bytes

// SHA-512 (higher security)
SecByteBlock hmacKey(SHA512::DIGESTSIZE);  // 64 bytes
```

## Performance

### Benchmarks (Approximate)

| Configuration | Speed (MB/s) | Notes |
|---------------|--------------|-------|
| AES-128-CBC (AES-NI) | 1000-2000 | Hardware accelerated |
| AES-256-CBC (AES-NI) | 800-1500 | Hardware accelerated |
| AES-128-CBC (software) | 50-150 | Software only |
| HMAC-SHA256 | 400-800 | Software |
| **Combined** | ~400-800 | Limited by HMAC |

**Note:** CBC+HMAC is slower than AES-GCM (~1500-3000 MB/s) because HMAC requires separate pass over data.

## Security

### Quick Summary

| Aspect | Recommendation | Why it matters |
|--------|----------------|----------------|
| Construction | Encrypt-then-MAC only | MAC-then-Encrypt is vulnerable to padding oracles |
| IV | Random 16-byte IV per encryption | Predictable IVs break CBC confidentiality |
| Keys | Separate AES and HMAC keys | Reusing keys weakens security properties |
| Verification | HMAC check before decryption | Prevents padding oracle attacks |

**Practical rules of thumb:**

- Generate a **random 16-byte IV** for every encryption; CBC requires unpredictable IVs (not just unique).
- **Always verify HMAC before decrypting** – never expose padding errors to attackers.
- Use **separate keys** for AES and HMAC; derive both from a master key using HKDF if needed.
- For new applications, **prefer AES-GCM or ChaCha20-Poly1305** – they're faster, simpler, and avoid padding oracle risks entirely.

{{< details title="Detailed Security Properties" >}}

**Algorithm Details**

- **Encryption:** AES-CBC (128/192/256-bit keys)
- **Authentication:** HMAC-SHA256/SHA512
- **IV size:** 128 bits (16 bytes)
- **MAC size:** 256 bits (32 bytes) or 512 bits (64 bytes)
- **Construction:** Encrypt-then-MAC
- **Standard:** NIST-approved primitives, historically used in TLS 1.2 CBC cipher suites

{{< /details >}}

### IV Management

**IVs must be unpredictable (random):**

```cpp
// CORRECT - Random IV per message
AutoSeededRandomPool rng;
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

// WRONG - Counter-based IV (predictable)
static byte iv[AES::BLOCKSIZE] = {0};  // NEVER DO THIS

// WRONG - Reused IV
byte iv[AES::BLOCKSIZE] = {0};
// ... encrypt multiple messages with same IV ...  // NEVER DO THIS
```

### Encrypt-then-MAC vs MAC-then-Encrypt

```cpp
// CORRECT - Encrypt-then-MAC
ciphertext = encrypt(plaintext)
mac = HMAC(IV || ciphertext)
send(IV || ciphertext || mac)

// WRONG - MAC-then-Encrypt (vulnerable to padding oracle)
mac = HMAC(plaintext)
ciphertext = encrypt(plaintext || mac)  // VULNERABLE
```

### Security Best Practices

1. **Always Verify HMAC Before Decrypting:**
   ```cpp
   // CORRECT order
   if (!verifyHMAC(...)) {
       throw std::runtime_error("Authentication failed");
   }
   decrypt(...);  // Only if HMAC valid

   // WRONG order (padding oracle attack)
   decrypt(...);  // NEVER decrypt before HMAC verification
   if (!verifyHMAC(...)) { ... }
   ```

2. **Use Separate Keys:**
   ```cpp
   // CORRECT - separate keys
   SecByteBlock aesKey(16);
   SecByteBlock hmacKey(32);

   // WRONG - same key
   SecByteBlock key(16);
   // ... use for both AES and HMAC ...  // VULNERABLE
   ```

3. **Include IV in HMAC:**
   ```cpp
   // CORRECT
   mac = HMAC(IV || ciphertext)

   // WRONG
   mac = HMAC(ciphertext)  // IV can be modified
   ```

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## When to Use AES-CBC+HMAC

### ✅ Use AES-CBC+HMAC for:

1. **Legacy Compatibility** - TLS 1.2, older systems
2. **Standards Compliance** - Protocols requiring CBC mode
3. **FIPS Compliance** - When AEAD modes not approved
4. **Compatibility** - Systems without AES-GCM support

### ❌ Don't use AES-CBC+HMAC for:

1. **New Applications** - Use AES-GCM or ChaCha20-Poly1305 instead
2. **Performance** - AEAD ciphers are faster
3. **Simplicity** - AEAD ciphers have simpler APIs

## AES-CBC+HMAC vs AES-GCM

| Feature | CBC+HMAC | AES-GCM |
|---------|----------|---------|
| Speed (AES-NI) | 400-800 MB/s | 1500-3000 MB/s |
| API complexity | Higher | Lower |
| Construction | Encrypt-then-MAC | Built-in AEAD |
| Parallelizable | No (CBC) | Yes (GCM) |
| Standards | Older (TLS 1.2) | Modern (TLS 1.3) |
| Padding oracle | Vulnerable if misused | Not vulnerable |
| Recommended | Legacy only | **Yes** |

**Use AES-GCM for new applications. Use CBC+HMAC only for legacy compatibility.**

## Exceptions

- `InvalidCiphertext` - Padding validation failed (only thrown after HMAC verification)
- `HashVerificationFilter::HashVerificationFailed` - HMAC mismatch

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Modern AEAD (recommended)
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative AEAD
- [HMAC](/docs/api/mac/hmac/) - Message authentication
- [Security Concepts](/docs/guides/security-concepts/) - Padding oracle attacks
