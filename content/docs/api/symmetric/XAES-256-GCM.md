---
title: XAES-256-GCM
description: XAES-256-GCM extended-nonce authenticated encryption API reference
weight: 2
---

**Header:** `#include <cryptopp/xaes_256_gcm.h>`
**Namespace:** `CryptoPP` **Since:** cryptopp-modern 2025.12

XAES-256-GCM is an extended-nonce variant of AES-256-GCM that enables safe random nonce generation for a virtually unlimited number of messages. It follows the [C2SP XAES-256-GCM specification](https://c2sp.org/XAES-256-GCM).

## Quick Example

```cpp
#include <cryptopp/xaes_256_gcm.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;

    // Generate random key and nonce
    SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    byte nonce[24];
    prng.GenerateBlock(nonce, sizeof(nonce));

    // Message to encrypt
    std::string plaintext = "Hello, XAES-256-GCM!";
    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];

    // Encrypt
    XAES_256_GCM::Encryption enc;
    enc.SetKey(key, key.size());
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        nonce, static_cast<int>(sizeof(nonce)),
        nullptr, 0,
        (const byte*)plaintext.data(), plaintext.size()
    );

    // Decrypt
    std::string recovered(ciphertext.size(), '\0');
    XAES_256_GCM::Decryption dec;
    dec.SetKey(key, key.size());

    bool valid = dec.DecryptAndVerify(
        (byte*)recovered.data(), tag, sizeof(tag),
        nonce, static_cast<int>(sizeof(nonce)),
        nullptr, 0,
        (const byte*)ciphertext.data(), ciphertext.size()
    );

    if (valid) {
        std::cout << "Decrypted: " << recovered << std::endl;
    }

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use XAES-256-GCM when you need safe random nonce generation
- Generate random 24-byte nonces using `AutoSeededRandomPool`
- Always verify the return value of `DecryptAndVerify()`
- Use a fresh nonce per message (one-shot APIs handle this automatically; for streaming, call `Resynchronize()` before each message)

**Avoid:**
- Calling `Restart()` (throws exception to prevent nonce reuse)
- Using keys not exactly 32 bytes (throws `InvalidKeyLength`)
- Using nonces not exactly 24 bytes (throws `InvalidArgument`)
- Ignoring authentication failures during decryption
{{< /callout >}}

## Class: XAES_256_GCM

Extended-nonce AES-256-GCM authenticated encryption with safe random nonce generation.

`XAES_256_GCM` provides two nested types:
- `XAES_256_GCM::Encryption` - for authenticated encryption
- `XAES_256_GCM::Decryption` - for authenticated decryption

### Constants

Available on `XAES_256_GCM::Encryption` and `XAES_256_GCM::Decryption`:

```cpp
XAES_256_GCM::Encryption::KEY_SIZE  // 32 (256 bits, fixed)
XAES_256_GCM::Encryption::IV_SIZE   // 24 (192 bits, fixed)
XAES_256_GCM::Encryption::TAG_SIZE  // 16 (128 bits, fixed)
```

### Key Features

| Feature | Value | Notes |
|---------|-------|-------|
| Key size | 32 bytes (256 bits) | Fixed, no other sizes supported |
| Nonce size | 24 bytes (192 bits) | Fixed, enables safe random generation |
| Tag size | 16 bytes (128 bits) | Fixed |
| Safe random nonces | Yes | ~2^80 messages before collision risk |
| Overhead | +3 AES blocks | Per-message key derivation cost |

## XAES_256_GCM::Encryption

Authenticated encryption class.

### Methods

#### SetKey()

```cpp
void SetKey(const byte* key, size_t keyLength,
            const NameValuePairs& params = g_nullNameValuePairs);
```

Set the encryption key.

**Parameters:**
- `key` - Encryption key (must be exactly 32 bytes)
- `keyLength` - Length of key in bytes (must be 32)
- `params` - Optional algorithm parameters (typically unused)

**Throws:** `InvalidKeyLength` if key is not 32 bytes

**Example:**

```cpp
XAES_256_GCM::Encryption enc;
SecByteBlock key(32);

AutoSeededRandomPool prng;
prng.GenerateBlock(key, key.size());

enc.SetKey(key, key.size());
```

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength = IV_SIZE);
```

Set key and nonce in a single call.

**Parameters:**
- `key` - Encryption key (32 bytes)
- `keyLength` - Length of key (must be 32)
- `iv` - Nonce (24 bytes)
- `ivLength` - Length of nonce (defaults to 24)

**Example:**

```cpp
XAES_256_GCM::Encryption enc;
SecByteBlock key(32);
byte nonce[24];

AutoSeededRandomPool prng;
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(nonce, sizeof(nonce));

enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));
```

#### Resynchronize()

```cpp
void Resynchronize(const byte* iv, int ivLength = -1);
```

Set a new nonce for the next message. Use this between messages with the same key.

**Parameters:**
- `iv` - New nonce (24 bytes)
- `ivLength` - Length of nonce; `-1` (default) uses `IVSize()` which is 24

**Throws:** `InvalidArgument` if nonce is not 24 bytes

**Example:**

```cpp
// Process multiple messages with same key
XAES_256_GCM::Encryption enc;
enc.SetKey(key, key.size());

// Message 1
byte nonce1[24];
prng.GenerateBlock(nonce1, sizeof(nonce1));
enc.Resynchronize(nonce1);
// ... encrypt message 1 ...

// Message 2 - MUST use fresh nonce
byte nonce2[24];
prng.GenerateBlock(nonce2, sizeof(nonce2));
enc.Resynchronize(nonce2);
// ... encrypt message 2 ...
```

#### EncryptAndAuthenticate()

```cpp
void EncryptAndAuthenticate(byte* ciphertext, byte* mac, size_t macSize,
                            const byte* iv, int ivLength,
                            const byte* aad, size_t aadLength,
                            const byte* message, size_t messageLength);
```

One-shot encryption with authentication.

**Parameters:**
- `ciphertext` - Output buffer (same size as message)
- `mac` - Output authentication tag (16 bytes)
- `macSize` - Size of MAC buffer (16)
- `iv` - Nonce (24 bytes)
- `ivLength` - Nonce length (24)
- `aad` - Additional authenticated data (can be NULL)
- `aadLength` - AAD length
- `message` - Plaintext to encrypt
- `messageLength` - Plaintext length

**Example:**

```cpp
XAES_256_GCM::Encryption enc;
enc.SetKey(key, key.size());

std::string plaintext = "Secret message";
std::string ciphertext(plaintext.size(), '\0');
byte tag[16];

enc.EncryptAndAuthenticate(
    (byte*)ciphertext.data(), tag, sizeof(tag),
    nonce, static_cast<int>(sizeof(nonce)),
    nullptr, 0,  // No AAD
    (const byte*)plaintext.data(), plaintext.size()
);
```

#### GetNextIV()

```cpp
void GetNextIV(RandomNumberGenerator& rng, byte* iv);
```

Generate a random nonce suitable for use with this cipher.

**Parameters:**
- `rng` - Random number generator
- `iv` - Output buffer for 24-byte nonce

**Example:**

```cpp
AutoSeededRandomPool prng;
XAES_256_GCM::Encryption enc;
enc.SetKey(key, key.size());

byte nonce[24];
enc.GetNextIV(prng, nonce);
enc.Resynchronize(nonce);  // uses IVSize() internally
```

## XAES_256_GCM::Decryption

Authenticated decryption class.

### Methods

#### DecryptAndVerify()

```cpp
bool DecryptAndVerify(byte* message,
                      const byte* mac, size_t macSize,
                      const byte* iv, int ivLength,
                      const byte* aad, size_t aadLength,
                      const byte* ciphertext, size_t ciphertextLength);
```

One-shot decryption with authentication verification.

**Parameters:**
- `message` - Output buffer for plaintext
- `mac` - Authentication tag to verify (16 bytes)
- `macSize` - Size of MAC (16)
- `iv` - Nonce (must match encryption)
- `ivLength` - Nonce length (24)
- `aad` - Additional authenticated data (must match encryption)
- `aadLength` - AAD length
- `ciphertext` - Encrypted data
- `ciphertextLength` - Ciphertext length

**Returns:** `true` if authentication succeeded, `false` if verification failed

**Important:** Always check the return value. If false, the message has been tampered with and you must discard the plaintext.

**Example:**

```cpp
XAES_256_GCM::Decryption dec;
dec.SetKey(key, key.size());

std::string plaintext(ciphertext.size(), '\0');
bool valid = dec.DecryptAndVerify(
    (byte*)plaintext.data(),
    tag, sizeof(tag),
    nonce, static_cast<int>(sizeof(nonce)),
    nullptr, 0,  // No AAD
    (const byte*)ciphertext.data(), ciphertext.size()
);

if (!valid) {
    SecureWipeArray((byte*)plaintext.data(), plaintext.size());
    throw std::runtime_error("Authentication failed!");
}
```

## Streaming Interface

For large messages or incremental processing.

### Streaming Encryption

```cpp
#include <cryptopp/xaes_256_gcm.h>
#include <cryptopp/osrng.h>

void streamingEncrypt() {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    byte nonce[24];
    prng.GenerateBlock(nonce, sizeof(nonce));

    XAES_256_GCM::Encryption enc;
    enc.SetKey(key, key.size());
    enc.Resynchronize(nonce);

    // Optional: Process AAD first
    std::string aad = "header-data";
    enc.Update((const byte*)aad.data(), aad.size());

    // Process plaintext in chunks
    std::string chunk1 = "First chunk. ";
    std::string chunk2 = "Second chunk.";

    std::string ct1(chunk1.size(), '\0');
    std::string ct2(chunk2.size(), '\0');

    enc.ProcessData((byte*)ct1.data(),
                    (const byte*)chunk1.data(), chunk1.size());
    enc.ProcessData((byte*)ct2.data(),
                    (const byte*)chunk2.data(), chunk2.size());

    // Finalize and get the tag
    byte tag[16];
    enc.TruncatedFinal(tag, sizeof(tag));
}
```

### Streaming Decryption

```cpp
void streamingDecrypt(const SecByteBlock& key, const byte* nonce,
                      const std::string& aad,
                      const std::string& ciphertext, const byte* tag) {
    using namespace CryptoPP;

    XAES_256_GCM::Decryption dec;
    dec.SetKey(key, key.size());
    dec.Resynchronize(nonce, 24);

    // Process AAD (must match encryption)
    dec.Update((const byte*)aad.data(), aad.size());

    // Decrypt data
    std::string plaintext(ciphertext.size(), '\0');
    dec.ProcessData((byte*)plaintext.data(),
                    (const byte*)ciphertext.data(), ciphertext.size());

    // Verify the tag
    if (!dec.TruncatedVerify(tag, 16)) {
        SecureWipeArray((byte*)plaintext.data(), plaintext.size());
        throw std::runtime_error("Authentication failed");
    }
}
```

## Additional Authenticated Data (AAD)

AAD provides authenticated (but not encrypted) metadata bound to the ciphertext.

```cpp
void encryptWithAAD() {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    byte nonce[24];
    prng.GenerateBlock(nonce, sizeof(nonce));

    // Message and AAD
    std::string plaintext = "Secret message";
    std::string aad = "message-id:12345;timestamp:2025-01-15";

    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];

    // Encrypt with AAD
    XAES_256_GCM::Encryption enc;
    enc.SetKey(key, key.size());
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        nonce, static_cast<int>(sizeof(nonce)),
        (const byte*)aad.data(), aad.size(),
        (const byte*)plaintext.data(), plaintext.size()
    );
}

void decryptWithAAD(const SecByteBlock& key, const byte* nonce,
                    const std::string& aad, const std::string& ciphertext,
                    const byte* tag) {
    using namespace CryptoPP;

    std::string recovered(ciphertext.size(), '\0');

    XAES_256_GCM::Decryption dec;
    dec.SetKey(key, key.size());

    // AAD must match exactly for verification to succeed
    bool valid = dec.DecryptAndVerify(
        (byte*)recovered.data(), tag, 16,
        nonce, 24,
        (const byte*)aad.data(), aad.size(),
        (const byte*)ciphertext.data(), ciphertext.size()
    );

    if (!valid) {
        SecureWipeArray((byte*)recovered.data(), recovered.size());
        throw std::runtime_error("Authentication failed - AAD or ciphertext tampered");
    }
}
```

## Complete Example

A full encryption/decryption round-trip with best practices.

```cpp
#include <cryptopp/xaes_256_gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <stdexcept>

using namespace CryptoPP;

struct EncryptedMessage {
    SecByteBlock nonce;
    std::string ciphertext;
    SecByteBlock tag;

    EncryptedMessage() : nonce(24), tag(16) {}
};

EncryptedMessage Encrypt(const SecByteBlock& key,
                         const std::string& plaintext,
                         const std::string& aad = "") {
    AutoSeededRandomPool prng;
    EncryptedMessage msg;

    // Generate random nonce
    prng.GenerateBlock(msg.nonce, msg.nonce.size());

    // Prepare ciphertext buffer
    msg.ciphertext.resize(plaintext.size());

    // Encrypt
    XAES_256_GCM::Encryption enc;
    enc.SetKey(key, key.size());
    enc.EncryptAndAuthenticate(
        (byte*)msg.ciphertext.data(), msg.tag, msg.tag.size(),
        msg.nonce, (int)msg.nonce.size(),
        aad.empty() ? nullptr : (const byte*)aad.data(), aad.size(),
        (const byte*)plaintext.data(), plaintext.size()
    );

    return msg;
}

std::string Decrypt(const SecByteBlock& key,
                    const EncryptedMessage& msg,
                    const std::string& aad = "") {
    std::string plaintext(msg.ciphertext.size(), '\0');

    XAES_256_GCM::Decryption dec;
    dec.SetKey(key, key.size());

    bool valid = dec.DecryptAndVerify(
        (byte*)plaintext.data(), msg.tag, msg.tag.size(),
        msg.nonce, (int)msg.nonce.size(),
        aad.empty() ? nullptr : (const byte*)aad.data(), aad.size(),
        (const byte*)msg.ciphertext.data(), msg.ciphertext.size()
    );

    if (!valid) {
        SecureWipeArray((byte*)plaintext.data(), plaintext.size());
        throw std::runtime_error("XAES-256-GCM: Authentication failed");
    }

    return plaintext;
}

int main() {
    try {
        AutoSeededRandomPool prng;

        // Generate a random key
        SecByteBlock key(32);
        prng.GenerateBlock(key, key.size());

        std::string original = "This is a secret message using XAES-256-GCM!";
        std::string aad = "user-id:alice;session:xyz123";

        std::cout << "Original:  " << original << std::endl;

        // Encrypt
        EncryptedMessage encrypted = Encrypt(key, original, aad);

        // Print hex values
        std::string nonceHex, ctHex, tagHex;
        StringSource(encrypted.nonce, encrypted.nonce.size(), true,
            new HexEncoder(new StringSink(nonceHex)));
        StringSource((const byte*)encrypted.ciphertext.data(),
            encrypted.ciphertext.size(), true,
            new HexEncoder(new StringSink(ctHex)));
        StringSource(encrypted.tag, encrypted.tag.size(), true,
            new HexEncoder(new StringSink(tagHex)));

        std::cout << "Nonce:     " << nonceHex << std::endl;
        std::cout << "Ciphertext:" << ctHex << std::endl;
        std::cout << "Tag:       " << tagHex << std::endl;

        // Decrypt
        std::string decrypted = Decrypt(key, encrypted, aad);
        std::cout << "Decrypted: " << decrypted << std::endl;

        if (original == decrypted)
            std::cout << "\nSuccess! Messages match." << std::endl;

        return 0;
    }
    catch (const Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
        return 1;
    }
}
```

## Error Handling

### Invalid Key Length

```cpp
void handleInvalidKey() {
    try {
        XAES_256_GCM::Encryption enc;

        // Wrong key size - must be exactly 32 bytes
        SecByteBlock shortKey(16);
        enc.SetKey(shortKey, shortKey.size());  // Throws!
    }
    catch (const InvalidKeyLength& e) {
        std::cerr << "Key error: " << e.what() << std::endl;
    }
}
```

### Invalid Nonce Length

```cpp
void handleInvalidNonce() {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    try {
        XAES_256_GCM::Encryption enc;
        enc.SetKey(key, key.size());

        // Wrong nonce size - must be exactly 24 bytes
        byte shortNonce[12];
        enc.Resynchronize(shortNonce, sizeof(shortNonce));  // Throws!
    }
    catch (const InvalidArgument& e) {
        std::cerr << "Nonce error: " << e.what() << std::endl;
    }
}
```

### Authentication Failure

```cpp
void handleAuthFailure() {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    byte nonce[24];
    prng.GenerateBlock(nonce, sizeof(nonce));

    // Encrypt
    std::string plaintext = "Original message";
    std::string ciphertext(plaintext.size(), '\0');
    byte tag[16];

    XAES_256_GCM::Encryption enc;
    enc.SetKey(key, key.size());
    enc.EncryptAndAuthenticate(
        (byte*)ciphertext.data(), tag, sizeof(tag),
        nonce, static_cast<int>(sizeof(nonce)), nullptr, 0,
        (const byte*)plaintext.data(), plaintext.size()
    );

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    // Decrypt - will fail verification
    std::string recovered(ciphertext.size(), '\0');
    XAES_256_GCM::Decryption dec;
    dec.SetKey(key, key.size());

    bool valid = dec.DecryptAndVerify(
        (byte*)recovered.data(), tag, sizeof(tag),
        nonce, static_cast<int>(sizeof(nonce)), nullptr, 0,
        (const byte*)ciphertext.data(), ciphertext.size()
    );

    if (!valid) {
        // IMPORTANT: Do not use recovered data!
        SecureWipeArray((byte*)recovered.data(), recovered.size());
        std::cerr << "Authentication failed - data was tampered!" << std::endl;
    }
}
```

## Security

### Quick Summary

| Aspect | Value | Why it matters |
|--------|-------|----------------|
| Key size | 256 bits (fixed) | Full AES-256 security |
| Nonce size | 192 bits (fixed) | Safe random generation |
| Tag length | 128 bits (fixed) | Strong authenticity |
| Message limit | ~2^80 per key | Birthday bound on 192-bit nonce |
| Key derivation | NIST SP 800-108r1 | CMAC-based, adds 3 AES blocks overhead |

**Security best practices:**

- Generate a **random 24-byte nonce** for every encryption; the large nonce space makes collisions negligible
- Always verify the return value of `DecryptAndVerify()` before using decrypted data
- Use `SecByteBlock` for keys to ensure automatic zeroing on destruction
- `Restart()` is intentionally disabled (throws exception) to prevent nonce reuse

{{< details title="Detailed Security Properties" >}}

**Why XAES-256-GCM?**

Standard AES-GCM uses a 12-byte (96-bit) nonce, which has a birthday bound of ~2^32 messages before collision risk becomes significant. With random nonces, this limits you to ~4 billion messages per key.

XAES-256-GCM extends the nonce to 24 bytes (192 bits), raising the birthday bound to ~2^80 messages. This makes random nonce generation safe for virtually any application.

**Key Derivation**

XAES-256-GCM derives a per-message key using NIST SP 800-108r1 (CMAC-based KDF):
1. Takes the 32-byte master key and the **first 12 bytes** of the 24-byte nonce
2. Derives a 32-byte subkey using CMAC
3. Uses the **last 12 bytes** of the nonce as the GCM IV
4. Overhead: 3 additional AES block encryptions per message

**Restart() Protection**

Unlike standard GCM, calling `Restart()` on XAES-256-GCM throws a `BadState` exception. This prevents accidental nonce reuse. Always use `Resynchronize()` with a fresh nonce instead.

{{< /details >}}

## Comparison with Standard GCM

| Feature | AES-256-GCM | XAES-256-GCM |
|---------|-------------|--------------|
| Key size | 32 bytes | 32 bytes |
| Nonce size | 12 bytes | 24 bytes |
| Tag size | 16 bytes | 16 bytes |
| Safe random nonce | No (~2^32 messages) | Yes (~2^80 messages) |
| Per-message overhead | None | +3 AES blocks |
| Standard | NIST SP 800-38D | C2SP XAES-256-GCM |

**When to use XAES-256-GCM:**
- Random nonce generation is preferred
- Managing unique nonces is impractical
- High message volume per key
- Distributed systems where nonce coordination is difficult

**When to use standard AES-GCM:**
- Counter-based nonces are feasible
- Maximum performance is critical
- Interoperability with legacy systems required

## Thread Safety

**Not thread-safe.** Create separate `XAES_256_GCM::Encryption` and `XAES_256_GCM::Decryption` objects for each thread.

```cpp
// WRONG - sharing between threads
XAES_256_GCM::Encryption shared_enc;

// CORRECT - one per thread
void threadFunc() {
    XAES_256_GCM::Encryption enc;  // Thread-local
    // ... use enc ...
}
```

## Exceptions

- `InvalidKeyLength` - Key size is not exactly 32 bytes
- `InvalidArgument` - Nonce size is not exactly 24 bytes
- `BadState` - `Restart()` was called (use `Resynchronize()` instead)

## Algorithm Details

- **Base algorithm:** AES-256-GCM
- **Key derivation:** NIST SP 800-108r1 (CMAC-based)
- **Key size:** 256 bits (fixed)
- **Nonce size:** 192 bits (24 bytes, fixed)
- **Tag size:** 128 bits (16 bytes, fixed)
- **Standard:** [C2SP XAES-256-GCM](https://c2sp.org/XAES-256-GCM)

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Standard GCM mode
- [XChaCha20-Poly1305](/docs/api/symmetric/xchacha20-poly1305/) - Another extended-nonce AEAD
- [Security Concepts](/docs/guides/security-concepts/) - Understanding cryptographic security
