---
title: AES-EAX
description: AES-EAX authenticated encryption API reference
weight: 5
---

**Header:** `#include <cryptopp/aes.h>` and `#include <cryptopp/eax.h>`
**Namespace:** `CryptoPP` **Since:** Crypto++ 5.6.0

AES-EAX (AES in EAX Mode) is an authenticated encryption algorithm that provides both confidentiality and authenticity. EAX is a two-pass mode built from CTR encryption and CMAC authentication, designed by Bellare, Rogaway, and Wagner.

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Generate random key and nonce
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 16 bytes
    SecByteBlock nonce(16);  // EAX supports variable nonce length
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(nonce, nonce.size());

    std::string plaintext = "Hello, World!";
    std::string ciphertext, decrypted;

    // Encrypt
    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(decrypted)
        )
    );

    std::cout << "Decrypted: " << decrypted << std::endl;
    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use EAX when you need a patent-free authenticated encryption mode
- Use unique nonces for each encryption with the same key
- Use 128-bit or 256-bit keys for new systems
- Verify authentication before using decrypted data

**Avoid:**
- Reusing nonces with the same key
- Ignoring authentication failures during decryption
- Using EAX for extremely high-throughput applications (GCM is faster)
{{< /callout >}}

## Why Choose EAX?

| Feature | EAX | GCM | CCM |
|---------|-----|-----|-----|
| **Patent status** | Free | Free | Free |
| **Nonce flexibility** | Any length | 12 bytes optimal | 7-13 bytes |
| **Online** | Yes | Yes | No (needs lengths upfront) |
| **Two-pass** | Yes | No | Yes |
| **Speed** | Moderate | Fast | Moderate |
| **Simplicity** | Simple | Complex | Moderate |

**Choose EAX when:**
- You need a simple, well-analyzed mode
- Variable-length nonces are useful
- Patent concerns exist (historically relevant)
- GCM hardware acceleration isn't available

## Class: EAX\<AES\>

Template class for AES in EAX authenticated encryption mode.

### Template Parameters

```cpp
template <class T_BlockCipher>
struct EAX {
    typedef EAX_Final<T_BlockCipher, true> Encryption;
    typedef EAX_Final<T_BlockCipher, false> Decryption;
};
```

- `T_BlockCipher` - The underlying block cipher (e.g., `AES`)

### Key Sizes

| Key Size | Security | Constant | Recommended |
|----------|----------|----------|-------------|
| 128-bit | 128-bit | `AES::DEFAULT_KEYLENGTH` (16) | Acceptable |
| 192-bit | 192-bit | 24 bytes | Rare |
| 256-bit | 256-bit | `AES::MAX_KEYLENGTH` (32) | ✓ Recommended |

### Constants

```cpp
// Inherited from AES
static const int MIN_KEYLENGTH = 16;     // 128 bits
static const int MAX_KEYLENGTH = 32;     // 256 bits
static const int DEFAULT_KEYLENGTH = 16; // 128 bits
static const int BLOCKSIZE = 16;         // 128 bits
```

**Tag size:** Up to the block size (16 bytes for AES). Default is 16 bytes; you can truncate via the `truncatedDigestSize` argument to `AuthenticatedEncryptionFilter` / `AuthenticatedDecryptionFilter`.

**Nonce size:** Any length from 0 to `UINT_MAX`; 12-16 bytes is a good practical choice.

## EAX\<AES\>::Encryption

Authenticated encryption class.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set encryption key and nonce (IV).

**Parameters:**
- `key` - Encryption key (16, 24, or 32 bytes)
- `keyLength` - Length of key in bytes
- `iv` - Nonce (any length, block size recommended)
- `ivLength` - Length of nonce in bytes

**Thread Safety:** Not thread-safe. Create separate objects per thread.

**Example:**

```cpp
EAX<AES>::Encryption enc;
SecByteBlock key(32);   // 256-bit key
SecByteBlock nonce(16); // 128-bit nonce

AutoSeededRandomPool rng;
rng.GenerateBlock(key, key.size());
rng.GenerateBlock(nonce, nonce.size());

enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
```

#### AlgorithmName()

```cpp
std::string AlgorithmName() const;
```

Returns the algorithm name (e.g., "AES/EAX").

#### DigestSize()

```cpp
unsigned int DigestSize() const;
```

Returns the authentication tag size (default: 16 bytes).

#### IVSize()

```cpp
unsigned int IVSize() const;
```

Returns the default nonce size (block size, 16 bytes for AES).

#### MinIVLength() / MaxIVLength()

```cpp
unsigned int MinIVLength() const;  // Returns 0
unsigned int MaxIVLength() const;  // Returns UINT_MAX
```

EAX accepts nonces of any length from 0 bytes up to `UINT_MAX`. In practice, use at least 12-16 bytes.

## EAX\<AES\>::Decryption

Authenticated decryption class.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set decryption key and nonce (same as encryption).

## Complete Example: Message Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

class SecureMessenger {
public:
    SecureMessenger() {
        // Generate random 256-bit key
        AutoSeededRandomPool rng;
        key_.resize(AES::MAX_KEYLENGTH);
        rng.GenerateBlock(key_, key_.size());
    }

    std::string encrypt(const std::string& plaintext) {
        AutoSeededRandomPool rng;

        // Generate random nonce for each message
        SecByteBlock nonce(AES::BLOCKSIZE);
        rng.GenerateBlock(nonce, nonce.size());

        // Encrypt
        std::string ciphertext;
        EAX<AES>::Encryption enc;
        enc.SetKeyWithIV(key_, key_.size(), nonce, nonce.size());

        StringSource(plaintext, true,
            new AuthenticatedEncryptionFilter(enc,
                new StringSink(ciphertext)
            )
        );

        // Prepend nonce to ciphertext
        std::string result;
        result.append((const char*)nonce.data(), nonce.size());
        result.append(ciphertext);
        return result;
    }

    std::string decrypt(const std::string& encrypted) {
        if (encrypted.size() < AES::BLOCKSIZE + 16) {
            throw std::runtime_error("Ciphertext too short");
        }

        // Extract nonce (first 16 bytes)
        SecByteBlock nonce((const byte*)encrypted.data(), AES::BLOCKSIZE);

        // Extract ciphertext (remainder)
        std::string ciphertext = encrypted.substr(AES::BLOCKSIZE);

        // Decrypt
        std::string plaintext;
        EAX<AES>::Decryption dec;
        dec.SetKeyWithIV(key_, key_.size(), nonce, nonce.size());

        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(plaintext)
            )
        );

        return plaintext;
    }

private:
    SecByteBlock key_;
};

int main() {
    try {
        SecureMessenger messenger;

        std::string original = "This is a secret message!";
        std::cout << "Original: " << original << std::endl;

        std::string encrypted = messenger.encrypt(original);
        std::cout << "Encrypted length: " << encrypted.size() << " bytes" << std::endl;

        std::string decrypted = messenger.decrypt(encrypted);
        std::cout << "Decrypted: " << decrypted << std::endl;

        // Verify round-trip
        if (original == decrypted) {
            std::cout << "Success: Messages match!" << std::endl;
        }

    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        std::cerr << "Authentication failed: message tampered!" << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Additional Authenticated Data (AAD)

EAX supports authenticated but unencrypted header data:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>

void encryptWithAAD() {
    using namespace CryptoPP;

    SecByteBlock key(32), nonce(16);
    // ... initialize key and nonce ...

    std::string header = "message-type:secure";  // AAD (authenticated, not encrypted)
    std::string plaintext = "Secret payload";
    std::string ciphertext;

    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    AuthenticatedEncryptionFilter aef(enc,
        new StringSink(ciphertext)
    );

    // Add AAD first
    aef.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    aef.ChannelMessageEnd(AAD_CHANNEL);

    // Then add plaintext
    aef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    aef.ChannelMessageEnd(DEFAULT_CHANNEL);

    // ciphertext now contains: encrypted payload + authentication tag
    // The header is authenticated but transmitted separately
}

void decryptWithAAD(const std::string& header,
                    const std::string& ciphertext,
                    const SecByteBlock& key,
                    const SecByteBlock& nonce) {
    using namespace CryptoPP;

    std::string plaintext;

    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    AuthenticatedDecryptionFilter adf(dec,
        new StringSink(plaintext)
    );

    // Must provide same AAD during decryption
    adf.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    adf.ChannelMessageEnd(AAD_CHANNEL);

    adf.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
    adf.ChannelMessageEnd(DEFAULT_CHANNEL);

    // If AAD doesn't match, authentication will fail
}
```

## Streaming Encryption

EAX is an "online" mode, meaning you can encrypt data without knowing the total length upfront:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>

void encryptStream(std::istream& in, std::ostream& out,
                   const SecByteBlock& key) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    SecByteBlock nonce(16);
    rng.GenerateBlock(nonce, nonce.size());

    // Write nonce first
    out.write((const char*)nonce.data(), nonce.size());

    // Stream encryption
    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    FileSource(in, true,
        new AuthenticatedEncryptionFilter(enc,
            new FileSink(out)
        )
    );
}
```

## Performance

EAX is a two-pass mode (CMAC + CTR), so it's generally slower than single-pass modes like GCM:

| Mode | Passes | Relative Speed | Hardware Accel |
|------|--------|----------------|----------------|
| GCM | 1 | Fastest | AES-NI + PCLMULQDQ |
| EAX | 2 | ~50% of GCM | AES-NI only |
| CCM | 2 | ~50% of GCM | AES-NI only |

**Approximate throughput (AES-256, modern x86 with AES-NI):**

| Operation | EAX | GCM |
|-----------|-----|-----|
| Encryption | 1000-1500 MB/s | 2000-4000 MB/s |
| Decryption | 1000-1500 MB/s | 2000-4000 MB/s |

## Security

### Quick Summary

| Property | Value |
|----------|-------|
| **Confidentiality** | 128/192/256-bit (AES key size) |
| **Authenticity** | 128-bit (full tag) |
| **Nonce requirement** | Must be unique per key |
| **Nonce reuse impact** | Reveals plaintext XOR, forgery possible |
| **Specification** | Bellare-Rogaway-Wagner 2004 |

### Security Properties

- **Provably secure**: Reduces to security of underlying block cipher
- **IND-CCA2**: Indistinguishable under adaptive chosen-ciphertext attack
- **INT-CTXT**: Integrity of ciphertext (forgery-resistant)
- **Two-pass**: Authentication computed over ciphertext (Encrypt-then-MAC)

### Nonce Requirements

Nonces must be unique per key. Reusing a nonce with the same key breaks both confidentiality and integrity, at minimum revealing the XOR of plaintexts and enabling forgeries.

```cpp
// Generate unique nonce for each message
AutoSeededRandomPool rng;
SecByteBlock nonce(16);
rng.GenerateBlock(nonce, nonce.size());
```

**Safe approaches:**
1. **Random nonce**: 128-bit random value per message
2. **Counter nonce**: Incrementing counter (requires state management)
3. **Message-derived**: Hash of message ID + timestamp (ensure uniqueness)

## Thread Safety

**Not thread-safe.** Create separate `EAX<AES>::Encryption` and `EAX<AES>::Decryption` objects for each thread.

```cpp
// WRONG - sharing between threads
EAX<AES>::Encryption shared_enc;

// CORRECT - one per thread
void threadFunc() {
    EAX<AES>::Encryption enc;  // Thread-local
    // ... use enc ...
}
```

## Exceptions

- `InvalidKeyLength` - Key size is not 16, 24, or 32 bytes
- `HashVerificationFilter::HashVerificationFailed` - Authentication failed (message tampered)

## EAX vs Other Modes

| Aspect | EAX | GCM | CCM |
|--------|-----|-----|-----|
| **Speed** | Moderate | Fast | Moderate |
| **Nonce size** | Any | 12 bytes optimal | 7-13 bytes |
| **Online** | Yes | Yes | No |
| **Simplicity** | Simple | Complex | Moderate |
| **Analysis** | Well-studied | Well-studied | Well-studied |
| **Hardware** | AES-NI | AES-NI + PCLMULQDQ | AES-NI |

## Algorithm Details

- **Construction**: CTR mode encryption + CMAC authentication
- **Authentication**: OMAC (One-Key CBC-MAC) variant
- **Key sizes**: 128, 192, or 256 bits (AES)
- **Block size**: 128 bits (AES)
- **Nonce size**: Any length (block size recommended)
- **Tag size**: Up to block size (128 bits default)
- **Specification**: Bellare-Rogaway-Wagner, "The EAX Mode of Operation" (2004)

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Faster authenticated encryption
- [AES-CCM](/docs/api/symmetric/aes-ccm/) - Alternative two-pass mode
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Non-AES alternative
- [Symmetric Encryption Guide](/docs/algorithms/symmetric/) - Conceptual overview
