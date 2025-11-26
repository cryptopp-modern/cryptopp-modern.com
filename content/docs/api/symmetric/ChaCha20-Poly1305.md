---
title: ChaCha20-Poly1305
description: ChaCha20-Poly1305 authenticated encryption API reference
weight: 2
---

**Header:** `#include <cryptopp/chachapoly.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 8.1
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

ChaCha20-Poly1305 is a modern authenticated encryption with associated data (AEAD) algorithm. It combines the ChaCha20 stream cipher with the Poly1305 MAC for authentication. Excellent alternative to AES-GCM, especially on platforms without AES hardware acceleration.

## Quick Example

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key and nonce
    SecByteBlock key(32);  // 256-bit key
    byte nonce[12];        // 96-bit nonce
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(nonce, sizeof(nonce));

    // Encrypt with authentication
    ChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    std::string plaintext = "Secret message";
    std::string ciphertext;  // Tag is appended to ciphertext by AuthenticatedEncryptionFilter

    AuthenticatedEncryptionFilter ef(enc,
        new StringSink(ciphertext),
        false, TAG_SIZE
    );

    ef.Put((const byte*)plaintext.data(), plaintext.size());
    ef.MessageEnd();

    std::cout << "Encrypted " << plaintext.size() << " bytes" << std::endl;

    // Decrypt and verify
    ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    std::string recovered;
    AuthenticatedDecryptionFilter df(dec,
        new StringSink(recovered)
    );

    df.Put((const byte*)ciphertext.data(), ciphertext.size());
    df.MessageEnd();

    std::cout << "Decrypted: " << recovered << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use ChaCha20-Poly1305 on systems without AES-NI hardware
- Use when constant-time operation is important (ChaCha20-Poly1305 is designed for simple, constant-time software implementations)
- Use 96-bit (12-byte) nonces
- Generate random nonces for each message (or use counters)
- Include associated data (AAD) for metadata authentication

**Avoid:**
- Reusing nonces with the same key (catastrophic security failure)
- Generally avoid on systems with AES-NI if maximum throughput is your primary goal (AES-GCM will usually be faster)
- Nonces smaller than 96 bits
{{< /callout >}}

## Class: ChaCha20Poly1305::Encryption

Encrypt and authenticate data.

### Constants

```cpp
static const int KEY_LENGTH = 32;         // 256-bit key
static const int IV_LENGTH = 12;          // 96-bit nonce (recommended)
static const int DEFAULT_TAG_LENGTH = 16; // 128-bit tag
static const int TAG_SIZE = 16;           // 128-bit authentication tag
```

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen,
                  const byte* iv, size_t ivLen);
```

Initialize with key and nonce.

**Parameters:**
- `key` - Secret key (32 bytes)
- `keyLen` - Key length (must be 32)
- `iv` - Nonce (12 bytes recommended)
- `ivLen` - Nonce length (typically 12)

**Example:**

```cpp
SecByteBlock key(32);
byte nonce[12];
rng.GenerateBlock(key, key.size());
rng.GenerateBlock(nonce, sizeof(nonce));

ChaCha20Poly1305::Encryption enc;
enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));
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
- `ciphertext` - Output buffer for encrypted data
- `mac` - Output buffer for authentication tag (16 bytes)
- `macSize` - Tag size (must be 16)
- `iv` - Nonce
- `ivLength` - Nonce length
- `aad` - Associated data (can be NULL)
- `aadLength` - AAD length
- `message` - Plaintext to encrypt
- `messageLength` - Plaintext length

**Example:**

```cpp
ChaCha20Poly1305::Encryption enc;
enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

std::string plaintext = "Secret data";
std::string aad = "User: Alice";

byte ciphertext[1024];
byte tag[16];

enc.EncryptAndAuthenticate(
    ciphertext, tag, sizeof(tag),
    nonce, sizeof(nonce),
    (const byte*)aad.data(), aad.size(),
    (const byte*)plaintext.data(), plaintext.size()
);
```

## Class: ChaCha20Poly1305::Decryption

Decrypt and verify authentication.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen,
                  const byte* iv, size_t ivLen);
```

Initialize with key and nonce (same as encryption).

#### DecryptAndVerify()

```cpp
bool DecryptAndVerify(byte* message,
                      const byte* mac, size_t macSize,
                      const byte* iv, int ivLength,
                      const byte* aad, size_t aadLength,
                      const byte* ciphertext, size_t ciphertextLength);
```

One-shot decryption with verification.

**Returns:** `true` if authentication succeeded, `false` if tag mismatch

**Example:**

```cpp
ChaCha20Poly1305::Decryption dec;
dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

byte recovered[1024];

bool valid = dec.DecryptAndVerify(
    recovered,
    tag, sizeof(tag),
    nonce, sizeof(nonce),
    (const byte*)aad.data(), aad.size(),
    ciphertext, ciphertextLength
);

if (!valid) {
    std::cerr << "Authentication failed!" << std::endl;
    // DO NOT use decrypted data
}
```

## Complete Example: Secure Messaging with AAD

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

struct SecureMessage {
    byte nonce[12];
    std::string ciphertext;

    std::string encrypt(const SecByteBlock& key,
                       const std::string& plaintext,
                       const std::string& metadata) {
        AutoSeededRandomPool rng;

        // Generate random nonce
        rng.GenerateBlock(nonce, sizeof(nonce));

        // Encrypt with metadata as AAD
        ChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

        AuthenticatedEncryptionFilter ef(enc,
            new StringSink(ciphertext),
            false, ChaCha20Poly1305::Encryption::TAG_SIZE
        );

        // Add AAD (metadata)
        ef.ChannelPut(AAD_CHANNEL, (const byte*)metadata.data(),
                      metadata.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);

        // Encrypt plaintext
        ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(),
                      plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        return ciphertext;
    }

    std::string decrypt(const SecByteBlock& key,
                       const std::string& metadata) {
        ChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

        std::string recovered;
        AuthenticatedDecryptionFilter df(dec,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS
        );

        // Add AAD (must match encryption)
        df.ChannelPut(AAD_CHANNEL, (const byte*)metadata.data(),
                      metadata.size());
        df.ChannelMessageEnd(AAD_CHANNEL);

        // Decrypt ciphertext
        try {
            df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(),
                          ciphertext.size());
            df.ChannelMessageEnd(DEFAULT_CHANNEL);
        } catch (const HashVerificationFilter::HashVerificationFailed&) {
            throw std::runtime_error("Authentication failed!");
        }

        return recovered;
    }
};

int main() {
    AutoSeededRandomPool rng;

    // Generate shared key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Create message
    SecureMessage msg;
    std::string plaintext = "Transfer $1000 to Bob";
    std::string metadata = "From: Alice, To: Bob, Timestamp: 2024-11-26";

    // Encrypt
    std::string ciphertext = msg.encrypt(key, plaintext, metadata);
    std::cout << "Encrypted: " << ciphertext.size() << " bytes" << std::endl;

    // Decrypt
    try {
        std::string recovered = msg.decrypt(key, metadata);
        std::cout << "Decrypted: " << recovered << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // Try with wrong metadata (will fail)
    try {
        std::string wrong_metadata = "From: Eve, To: Bob, Timestamp: 2024-11-26";
        std::string recovered = msg.decrypt(key, wrong_metadata);
        std::cout << "This should not print!" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Authentication correctly failed with wrong AAD" << std::endl;
    }

    return 0;
}
```

## Complete Example: File Encryption

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    AutoSeededRandomPool rng;

    // Generate random nonce
    byte nonce[12];
    rng.GenerateBlock(nonce, sizeof(nonce));

    // Write nonce to output file first
    FileSink outFile(outputFile.c_str());
    outFile.Put(nonce, sizeof(nonce));

    // Encrypt file
    ChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    FileSource(inputFile.c_str(), true,
        new AuthenticatedEncryptionFilter(enc,
            new Redirector(outFile),
            false, ChaCha20Poly1305::Encryption::TAG_SIZE
        )
    );

    std::cout << "File encrypted: " << outputFile << std::endl;
}

void decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    // Read nonce from input file
    byte nonce[12];
    FileSource inFile(inputFile.c_str(), false);
    inFile.Pump(sizeof(nonce));
    inFile.Get(nonce, sizeof(nonce));

    // Decrypt file
    ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    try {
        ArraySource(inFile, true,
            new AuthenticatedDecryptionFilter(dec,
                new FileSink(outputFile.c_str())
            )
        );
        std::cout << "File decrypted: " << outputFile << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed&) {
        std::cerr << "Authentication failed! File may be corrupted." << std::endl;
    }
}

int main() {
    AutoSeededRandomPool rng;

    // Generate key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Encrypt file
    encryptFile("document.pdf", "document.pdf.enc", key);

    // Decrypt file
    decryptFile("document.pdf.enc", "document_decrypted.pdf", key);

    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Platform | Speed (MB/s) | Notes |
|----------|--------------|-------|
| **Software** | 400-800 | Pure software implementation |
| **SSSE3** | 600-1200 | With SSSE3 optimizations |
| **AVX2** | 800-1600 | With AVX2 optimizations |
| **ARM NEON** | 500-1000 | ARM processors |

### Comparison with AES-GCM

| Platform | AES-GCM | ChaCha20-Poly1305 | Winner |
|----------|---------|-------------------|--------|
| With AES-NI | 1500-3000 MB/s | 800-1600 MB/s | AES-GCM |
| Without AES-NI | 100-300 MB/s | 400-800 MB/s | **ChaCha20-Poly1305** |
| ARM (no Crypto) | 100-300 MB/s | 500-1000 MB/s | **ChaCha20-Poly1305** |
| ARM (with Crypto) | 1000-2000 MB/s | 500-1000 MB/s | AES-GCM |

**Key Insight:** ChaCha20-Poly1305 is 2-5x faster than AES-GCM on platforms without hardware acceleration.

## Security

### Quick Summary

| Aspect | Recommendation | Why it matters |
|--------|----------------|----------------|
| Key size | 256-bit (32 bytes) only | Full ChaCha20 security level |
| Nonce | 12-byte unique nonce per encryption | Reuse with same key is catastrophic |
| Tag length | 128-bit tag (16 bytes) | Strong integrity / authenticity margin |
| Key lifetime | Re-key well before ~2³² encryptions | Keeps nonce-collision risk negligible |

**Practical rules of thumb:**

- Generate a **random 12-byte nonce** for every encryption under a given key; never reuse the same `(key, nonce)` pair.
- Always use and verify the **authentication tag**; treat any verification failure as a hard error and discard the ciphertext.
- For high-volume or long-lived keys, **rotate keys periodically** (e.g., well below ~2³² encryptions per key), or use XChaCha20-Poly1305 for its larger nonce space.

{{< details title="Detailed Security Properties" >}}

**Algorithm Details**

- **Encryption:** ChaCha20 stream cipher (256-bit key)
- **Authentication:** Poly1305 MAC (128-bit tag)
- **Nonce size:** 96 bits (12 bytes) recommended
- **Key size:** 256 bits (32 bytes) only
- **Tag size:** 128 bits (16 bytes)
- **Standard:** RFC 8439 (IETF)

{{< /details >}}

### Nonce Management

**CRITICAL: Never reuse nonces with the same key.**

```cpp
// CORRECT - Random nonce per message
AutoSeededRandomPool rng;
for (int i = 0; i < 100; i++) {
    byte nonce[12];
    rng.GenerateBlock(nonce, sizeof(nonce));
    // ... encrypt with unique nonce ...
}

// CORRECT - Counter-based nonces
uint64_t counter = 0;
for (int i = 0; i < 100; i++) {
    byte nonce[12] = {0};
    memcpy(nonce, &counter, sizeof(counter));
    counter++;
    // ... encrypt with unique nonce ...
}

// CATASTROPHIC - Nonce reuse
byte nonce[12] = {0};  // Same nonce!
// ... encrypt multiple messages ...  // NEVER DO THIS
```

**Nonce reuse consequences:**
- Attackers can recover plaintext
- Attackers can forge messages
- Complete security failure

### Security Best Practices

1. **Never Reuse Nonces:**
   - Use random 96-bit nonces from a CSPRNG, or a well-designed counter scheme
   - With random 96-bit nonces, after about 2³² encryptions under one key there is already a ~2⁻³² chance of a collision
   - Plan to **re-key well before** you approach that scale, or consider XChaCha20-Poly1305 for very high message counts

2. **Authenticate-then-Decrypt:**
   ```cpp
   // Authentication happens automatically in DecryptionFilter
   try {
       df.Put(ciphertext, size);
       df.MessageEnd();
       // Authentication succeeded - safe to use plaintext
   } catch (const HashVerificationFilter::HashVerificationFailed&) {
       // Authentication failed - DO NOT use plaintext
   }
   ```

3. **Use AAD for Metadata:**
   ```cpp
   // Include message headers, timestamps, etc. as AAD
   std::string aad = "From: Alice, To: Bob, ID: 12345";
   // AAD is authenticated but not encrypted
   ```

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## When to Use ChaCha20-Poly1305

### ✅ Use ChaCha20-Poly1305 for:

1. **Mobile Devices** - ARM processors without AES acceleration
2. **IoT/Embedded** - Systems without AES-NI
3. **Constant-Time** - When timing side-channels are a concern
4. **TLS/QUIC** - Modern network protocols
5. **Broad Compatibility** - Software-only implementations

### ❌ Don't use ChaCha20-Poly1305 for:

1. **Systems with AES-NI** - AES-GCM will be faster
2. **Legacy Systems** - May not support ChaCha20-Poly1305

## ChaCha20-Poly1305 vs AES-GCM

**Choose ChaCha20-Poly1305 when:**
- No hardware AES acceleration available
- Constant-time operation critical
- Mobile/embedded deployment
- Software-only implementation

**Choose AES-GCM when:**
- Hardware AES-NI available
- Maximum performance with hardware
- Standards compliance requires AES

**Both are excellent choices for authenticated encryption.**

## Exceptions

- `HashVerificationFilter::HashVerificationFailed` - Authentication failed (wrong key, corrupted data, or modified ciphertext/AAD)
- `InvalidArgument` - Invalid key or nonce size

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Hardware-accelerated alternative
- [HMAC](/docs/api/mac/hmac/) - For message authentication without encryption
- [Symmetric Encryption](/docs/algorithms/symmetric/) - Conceptual overview
- [Security Concepts](/docs/guides/security-concepts/) - Nonce management
