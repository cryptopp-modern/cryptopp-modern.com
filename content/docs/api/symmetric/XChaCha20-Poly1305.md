---
title: XChaCha20-Poly1305
description: XChaCha20-Poly1305 authenticated encryption API reference
weight: 6
---

**Header:** `#include <cryptopp/chachapoly.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 8.1
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

XChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD) cipher that extends ChaCha20-Poly1305 with a 192-bit (24-byte) nonce instead of 96-bit (12-byte). The larger nonce makes it safe to generate nonces randomly without significant collision risk, simplifying nonce management.

## Quick Example

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // 256-bit key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // 192-bit (24-byte) nonce - can be random!
    byte nonce[24];
    rng.GenerateBlock(nonce, sizeof(nonce));

    std::string plaintext = "Hello, World!";
    std::string ciphertext, recovered;

    // Encrypt
    XChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    XChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(recovered)
        )
    );

    std::cout << "Decrypted: " << recovered << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Generate random 24-byte nonces (safe due to large nonce space)
- Use for long-lived keys with many messages
- Use when random nonce generation is simpler than tracking counters
- Store nonce alongside ciphertext (it's not secret)

**Avoid:**
- Using for protocols that already handle 12-byte nonces well (use ChaCha20-Poly1305)
- Using without understanding it's slightly slower than ChaCha20-Poly1305
- Truncating or reusing nonces
{{< /callout >}}

## Why XChaCha20-Poly1305?

The key advantage over standard ChaCha20-Poly1305:

| Property | ChaCha20-Poly1305 | XChaCha20-Poly1305 |
|----------|-------------------|---------------------|
| Nonce size | 12 bytes (96-bit) | **24 bytes (192-bit)** |
| Random nonce safe? | ⚠️ Risk after ~2³² messages | ✅ Safe for ~2⁶⁴ messages |
| Counter tracking | Required for safety | Optional |
| Use case | TLS, protocols with counters | File encryption, at-rest data |

**Birthday bound:**
- 12-byte nonce: ~2³² messages before 50% collision probability
- 24-byte nonce: ~2⁶⁴ messages before 50% collision probability

## Class: XChaCha20Poly1305

### Constants

```cpp
// Key size: 32 bytes (256 bits)
// Nonce size: 24 bytes (192 bits)
// Tag size: 16 bytes (128 bits)
```

### Types

```cpp
XChaCha20Poly1305::Encryption  // For encryption
XChaCha20Poly1305::Decryption  // For decryption
```

## Methods

### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen,
                  const byte* iv, size_t ivLen);
```

Set key and nonce (IV).

**Parameters:**
- `key` - 32-byte key
- `keyLen` - Key length (must be 32)
- `iv` - 24-byte nonce
- `ivLen` - Nonce length (must be 24)

**Example:**

```cpp
XChaCha20Poly1305::Encryption enc;
enc.SetKeyWithIV(key, 32, nonce, 24);
```

### EncryptAndAuthenticate()

```cpp
void EncryptAndAuthenticate(byte* ciphertext,
                            byte* mac, size_t macSize,
                            const byte* iv, int ivLength,
                            const byte* aad, size_t aadLength,
                            const byte* message, size_t messageLength);
```

Encrypt and authenticate in one call.

**Parameters:**
- `ciphertext` - Output buffer (same size as message)
- `mac` - Output buffer for authentication tag
- `macSize` - Tag size (typically 16)
- `iv` - 24-byte nonce
- `ivLength` - Nonce length
- `aad` - Additional authenticated data (optional)
- `aadLength` - AAD length
- `message` - Plaintext
- `messageLength` - Plaintext length

### DecryptAndVerify()

```cpp
bool DecryptAndVerify(byte* message,
                      const byte* mac, size_t macSize,
                      const byte* iv, int ivLength,
                      const byte* aad, size_t aadLength,
                      const byte* ciphertext, size_t ciphertextLength);
```

Decrypt and verify in one call.

**Returns:** `true` if tag verification succeeds, `false` otherwise

## Complete Example: File Encryption with Random Nonce

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>

using namespace CryptoPP;

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    AutoSeededRandomPool rng;

    // Generate random 24-byte nonce (safe with XChaCha20!)
    byte nonce[24];
    rng.GenerateBlock(nonce, sizeof(nonce));

    // Read plaintext
    std::string plaintext;
    FileSource(inputFile.c_str(), true,
        new StringSink(plaintext)
    );

    // Encrypt
    XChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    std::string ciphertext;
    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Write: nonce || ciphertext || tag
    FileSink output(outputFile.c_str());
    output.Put(nonce, sizeof(nonce));
    output.Put((const byte*)ciphertext.data(), ciphertext.size());

    std::cout << "Encrypted: " << inputFile << " -> " << outputFile << std::endl;
    std::cout << "Nonce: " << sizeof(nonce) << " bytes (random, stored in file)" << std::endl;
}

void decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    // Read encrypted file
    std::string encrypted;
    FileSource(inputFile.c_str(), true,
        new StringSink(encrypted)
    );

    // Extract nonce (first 24 bytes)
    if (encrypted.size() < 24) {
        throw std::runtime_error("File too small");
    }

    byte nonce[24];
    std::memcpy(nonce, encrypted.data(), sizeof(nonce));
    std::string ciphertext = encrypted.substr(24);

    // Decrypt
    XChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    std::string plaintext;
    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(plaintext)
        )
    );

    // Write plaintext
    FileSink output(outputFile.c_str());
    output.Put((const byte*)plaintext.data(), plaintext.size());

    std::cout << "Decrypted: " << inputFile << " -> " << outputFile << std::endl;
}

int main() {
    AutoSeededRandomPool rng;

    // Generate key (store securely in practice!)
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    encryptFile("document.txt", "document.enc", key);
    decryptFile("document.enc", "document.dec.txt", key);

    return 0;
}
```

## Complete Example: Message Encryption with AAD

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>

using namespace CryptoPP;

struct EncryptedMessage {
    byte nonce[24];
    std::string ciphertext;  // Includes 16-byte tag
};

EncryptedMessage encryptWithAAD(const std::string& plaintext,
                                 const std::string& aad,
                                 const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    EncryptedMessage msg;

    // Random nonce (safe with 24 bytes!)
    rng.GenerateBlock(msg.nonce, sizeof(msg.nonce));

    XChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), msg.nonce, sizeof(msg.nonce));

    // Create filter with AAD
    AuthenticatedEncryptionFilter ef(enc,
        new StringSink(msg.ciphertext)
    );

    // Process AAD first (authenticated but not encrypted)
    ef.ChannelPut(AAD_CHANNEL,
        (const byte*)aad.data(), aad.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);

    // Process plaintext (encrypted and authenticated)
    ef.ChannelPut(DEFAULT_CHANNEL,
        (const byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    return msg;
}

std::string decryptWithAAD(const EncryptedMessage& msg,
                            const std::string& aad,
                            const SecByteBlock& key) {
    XChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), msg.nonce, sizeof(msg.nonce));

    std::string plaintext;

    AuthenticatedDecryptionFilter df(dec,
        new StringSink(plaintext)
    );

    // Process AAD
    df.ChannelPut(AAD_CHANNEL,
        (const byte*)aad.data(), aad.size());
    df.ChannelMessageEnd(AAD_CHANNEL);

    // Process ciphertext
    df.ChannelPut(DEFAULT_CHANNEL,
        (const byte*)msg.ciphertext.data(), msg.ciphertext.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    return plaintext;
}

int main() {
    AutoSeededRandomPool rng;

    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    std::string message = "Secret payment data";
    std::string header = "Transaction-ID: 12345";  // AAD

    // Encrypt with AAD
    EncryptedMessage encrypted = encryptWithAAD(message, header, key);

    std::cout << "Ciphertext size: " << encrypted.ciphertext.size()
              << " bytes (includes 16-byte tag)" << std::endl;

    // Decrypt with same AAD
    std::string decrypted = decryptWithAAD(encrypted, header, key);
    std::cout << "Decrypted: " << decrypted << std::endl;

    // Tampered AAD will fail
    try {
        decryptWithAAD(encrypted, "Tampered-Header", key);
    } catch (const Exception& e) {
        std::cout << "Tampered AAD detected!" << std::endl;
    }

    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Operation | Speed | Notes |
|-----------|-------|-------|
| Encryption | 1-2 GB/s | Slightly slower than ChaCha20-Poly1305 |
| Decryption | 1-2 GB/s | Includes tag verification |
| Key setup | ~1 µs | Per-message overhead |

**Platform:** Modern x86-64 CPU without AES-NI

### XChaCha20-Poly1305 vs ChaCha20-Poly1305

| Property | ChaCha20-Poly1305 | XChaCha20-Poly1305 |
|----------|-------------------|---------------------|
| Speed | Slightly faster | Slightly slower (~5%) |
| Nonce | 12 bytes | 24 bytes |
| Random nonce | ⚠️ Risky after 2³² msgs | ✅ Safe |
| TLS 1.3 | ✅ Standard | ❌ Not standard |
| File encryption | ⚠️ Need counter | ✅ Random OK |

## Security

### Security Properties

- **Security level:** ~256-bit key, ~128-bit authentication
- **Nonce size:** 192 bits (24 bytes)
- **Tag size:** 128 bits (16 bytes)
- **Max message:** ~256 GB per nonce
- **Random nonce safe:** Yes, up to ~2⁶⁴ messages

### When Random Nonces Are Safe

```
XChaCha20-Poly1305 with 24-byte nonce:
- Nonce space: 2^192
- Birthday bound: ~2^96 messages for 50% collision risk
- Practical limit: ~2^64 messages with comfortable margin

ChaCha20-Poly1305 with 12-byte nonce:
- Nonce space: 2^96
- Birthday bound: ~2^48 messages for 50% collision risk
- Practical limit: ~2^32 messages (4 billion)
```

### Security Notes

- **Nonce uniqueness:** While random nonces are safe, never reuse (nonce, key) pairs
- **No nonce misuse resistance:** Nonce reuse is still catastrophic (reveals XOR of plaintexts)
- **AAD integrity:** AAD is authenticated but not encrypted
- **Key rotation:** Consider rotating keys after ~2⁶⁴ messages (practically infinite)

## XChaCha20-Poly1305 vs AES-GCM

| Property | XChaCha20-Poly1305 | AES-GCM |
|----------|---------------------|---------|
| Nonce size | 24 bytes | 12 bytes |
| Random nonce | ✅ Safe | ⚠️ Risky |
| Hardware accel | ❌ No | ✅ AES-NI |
| Speed (with AES-NI) | Slower | Faster |
| Speed (no AES-NI) | Faster | Slower |
| Nonce misuse | Catastrophic | Catastrophic |

**Use XChaCha20-Poly1305 when:**
- Random nonce generation is preferred
- No AES-NI available
- Encrypting many messages with same key

**Use AES-GCM when:**
- Hardware acceleration available
- Protocol manages nonces (TLS)
- Performance is critical

## When to Use XChaCha20-Poly1305

### ✅ Use XChaCha20-Poly1305 for:

1. **File Encryption** - Random nonces simplify implementation
2. **Database Encryption** - Each record gets random nonce
3. **Long-lived Keys** - Safe for many messages
4. **Backup Encryption** - No counter state to manage
5. **Stateless Encryption** - No need to track nonce counters

### ❌ Don't use XChaCha20-Poly1305 for:

1. **TLS/HTTPS** - Use ChaCha20-Poly1305 (standard)
2. **When AES-NI Available** - AES-GCM may be faster
3. **Nonce Misuse Scenarios** - Consider AES-GCM-SIV instead

## Exceptions

- `InvalidKeyLength` - Key not 32 bytes
- `InvalidArgument` - Nonce not 24 bytes
- `HashVerificationFilter::HashVerificationFailed` - Tag verification failed

## See Also

- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Standard 12-byte nonce variant
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Hardware-accelerated AEAD
- [HKDF](/docs/api/kdf/hkdf/) - Key derivation
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Random nonce generation
