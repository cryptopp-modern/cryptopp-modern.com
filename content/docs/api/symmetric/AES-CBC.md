---
title: AES-CBC
description: AES Cipher Block Chaining mode encryption API reference
weight: 5
---

**Header:** `#include <cryptopp/aes.h>`, `#include <cryptopp/modes.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 3.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

AES-CBC (Cipher Block Chaining) is a classic block cipher mode that chains blocks together by XORing each plaintext block with the previous ciphertext block before encryption. It provides confidentiality but **not** authentication.

{{< callout type="warning" >}}
**Important:** CBC mode provides **encryption only**, not authentication. It is vulnerable to padding oracle attacks if decryption errors are distinguishable from MAC failures. For authenticated encryption, use [AES-GCM](/docs/api/symmetric/aes-gcm/) or [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/).
{{< /callout >}}

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// 128-bit key
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
rng.GenerateBlock(key, key.size());

// 16-byte IV
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

std::string plaintext = "Secret message";
std::string ciphertext, recovered;

// Encrypt (PKCS7 padding applied automatically)
CBC_Mode<AES>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv);

StringSource(plaintext, true,
    new StreamTransformationFilter(enc,
        new StringSink(ciphertext)
    )
);

// Decrypt
CBC_Mode<AES>::Decryption dec;
dec.SetKeyWithIV(key, key.size(), iv);

StringSource(ciphertext, true,
    new StreamTransformationFilter(dec,
        new StringSink(recovered)
    )
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use a unique, random IV for every message
- Always combine with HMAC for authenticated encryption (Encrypt-then-MAC)
- Use PKCS7 padding (default in Crypto++)
- Verify MAC before decrypting to prevent padding oracle attacks
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- **CRITICAL:** Never reuse an IV with the same key
- Don't use without authentication in any real application
- Don't expose padding errors separately from authentication errors
- Don't use for new designs when GCM is available
{{< /callout >}}

## How CBC Works

```
Encryption:
C₀ = IV
Cᵢ = AES(key, Pᵢ ⊕ Cᵢ₋₁)

Decryption:
Pᵢ = AES⁻¹(key, Cᵢ) ⊕ Cᵢ₋₁
```

Each ciphertext block depends on all previous blocks, providing diffusion but preventing parallelization during encryption.

## Constants

```cpp
AES::DEFAULT_KEYLENGTH    // 16 bytes (128-bit)
AES::MAX_KEYLENGTH        // 32 bytes (256-bit)
AES::BLOCKSIZE            // 16 bytes (IV size)
```

## Constructors

```cpp
// Default constructor (must call SetKeyWithIV)
CBC_Mode<AES>::Encryption enc;
CBC_Mode<AES>::Decryption dec;
```

## Methods

### SetKeyWithIV

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen, const byte* iv, size_t ivLen = BLOCKSIZE);
```

Sets the encryption/decryption key and initialization vector.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `const byte*` | Encryption key (16, 24, or 32 bytes) |
| `keyLen` | `size_t` | Key length in bytes |
| `iv` | `const byte*` | Initialization vector (16 bytes) |
| `ivLen` | `size_t` | IV length (default: block size) |

### ProcessData

```cpp
void ProcessData(byte* outString, const byte* inString, size_t length);
```

Processes data. For CBC, length must be a multiple of block size (use StreamTransformationFilter for automatic padding).

## Complete Examples

### Example 1: Basic Encryption/Decryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 128-bit
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "The quick brown fox jumps over the lazy dog";
    std::string ciphertext, recovered;

    // Encrypt
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Note: ciphertext is padded to multiple of 16 bytes
    std::cout << "Plaintext size:  " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

    // Decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    std::cout << "Recovered: " << recovered << std::endl;

    return 0;
}
```

### Example 2: AES-256-CBC

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // 256-bit key
    SecByteBlock key(AES::MAX_KEYLENGTH);  // 32 bytes
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "High security message";
    std::string ciphertext, recovered;

    // Encrypt with AES-256
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    return 0;
}
```

### Example 3: File Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <fstream>

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate random IV
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Write IV first
    std::ofstream out(outputFile, std::ios::binary);
    out.write((const char*)iv, sizeof(iv));

    // Encrypt file
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    FileSource(inputFile, true,
        new StreamTransformationFilter(enc,
            new FileSink(out)
        )
    );
}

void decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    using namespace CryptoPP;

    // Read IV
    std::ifstream in(inputFile, std::ios::binary);
    byte iv[AES::BLOCKSIZE];
    in.read((char*)iv, sizeof(iv));

    // Decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    FileSource(in, true,
        new StreamTransformationFilter(dec,
            new FileSink(outputFile)
        )
    );
}
```

### Example 4: Manual Padding Control

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Test";
    std::string ciphertext, recovered;

    // Encrypt with explicit padding mode
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    // PKCS_PADDING is default, but can be explicit
    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            StreamTransformationFilter::PKCS_PADDING
        )
    );

    // For data already padded or exact block size multiples:
    // StreamTransformationFilter::NO_PADDING

    // Decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered),
            StreamTransformationFilter::PKCS_PADDING
        )
    );

    return 0;
}
```

### Example 5: In-Place Encryption (Block-Aligned Data)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Data must be multiple of block size for raw ProcessData
    std::vector<byte> data(32);  // 2 blocks
    memcpy(data.data(), "Hello World!1234Hello World!1234", 32);

    std::cout << "Original: ";
    std::cout.write((const char*)data.data(), data.size());
    std::cout << std::endl;

    // Encrypt in place
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    enc.ProcessData(data.data(), data.data(), data.size());

    // Decrypt in place
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    dec.ProcessData(data.data(), data.data(), data.size());

    std::cout << "Decrypted: ";
    std::cout.write((const char*)data.data(), data.size());
    std::cout << std::endl;

    return 0;
}
```

## Padding

CBC mode requires plaintext to be a multiple of the block size. Crypto++ uses PKCS7 padding by default:

```
Original: "Hello" (5 bytes)
Padded:   "Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" (16 bytes)

Padding byte value = number of padding bytes needed
```

### Padding Options

```cpp
// PKCS7 padding (default, recommended)
StreamTransformationFilter::PKCS_PADDING

// No padding (data must be block-aligned)
StreamTransformationFilter::NO_PADDING

// Zero padding (not recommended - ambiguous)
StreamTransformationFilter::ZEROS_PADDING

// One-and-zeros padding (ISO 7816-4)
StreamTransformationFilter::ONE_AND_ZEROS_PADDING
```

## Padding Oracle Attacks

{{< callout type="error" title="Security Warning" >}}
CBC mode is vulnerable to padding oracle attacks when:
1. Decryption errors can be distinguished from authentication failures
2. An attacker can submit arbitrary ciphertexts for decryption

**Mitigation:** Always use Encrypt-then-MAC and verify MAC before decrypting. See [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/).
{{< /callout >}}

```cpp
// WRONG - Leaks padding information
try {
    // Decrypt
} catch (const InvalidCiphertext& e) {
    return "Padding error";  // Padding oracle!
}

// CORRECT - Verify MAC first, generic error
if (!verifyHMAC(ciphertext, mac)) {
    return "Authentication failed";  // No padding info leaked
}
// Only then decrypt
```

## IV Requirements

### Critical: Never Reuse IV with Same Key

```
If IV is reused:
- Identical plaintext blocks at the start produce identical ciphertext
- Information about plaintext structure is leaked
- Chosen-plaintext attacks become possible
```

### Safe IV Generation

```cpp
// Always use cryptographically random IV
AutoSeededRandomPool rng;
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

// Store/transmit IV with ciphertext (IV is not secret)
```

## CBC vs Other Modes

| Feature | CBC | CTR | GCM |
|---------|-----|-----|-----|
| **Padding** | Yes (PKCS7) | No | No |
| **Encrypt parallel** | No | Yes | Yes |
| **Decrypt parallel** | Yes | Yes | Yes |
| **Random access** | No | Yes | No |
| **Authentication** | No | No | Yes |
| **IV reuse impact** | Info leak | Catastrophic | Catastrophic |

## Performance

### Benchmarks (approximate)

| Configuration | Encrypt | Decrypt |
|---------------|---------|---------|
| AES-CBC with AES-NI | ~2 GB/s | ~3 GB/s |
| AES-CBC (software) | ~200 MB/s | ~300 MB/s |

Decryption is faster because it can be parallelized (each block only needs previous ciphertext block).

## Security Properties

| Property | Value |
|----------|-------|
| **Confidentiality** | Yes (with unique IV) |
| **Integrity** | No (must add MAC) |
| **Key size** | 128, 192, or 256 bits |
| **Block size** | 128 bits |
| **IV size** | 128 bits |

## When to Use CBC

### ✅ Use CBC for:

1. **Legacy compatibility** with existing CBC-based systems
2. **Combined with HMAC** (Encrypt-then-MAC) when GCM unavailable
3. **Disk encryption** schemes (with proper sector IVs)

### ❌ Don't use CBC alone for:

1. **New applications** (use GCM or ChaCha20-Poly1305)
2. **Network protocols** without authentication
3. **Any scenario** where padding errors might be observable

## Thread Safety

CBC mode objects are **not thread-safe**:

```cpp
// WRONG - shared instance
CBC_Mode<AES>::Encryption sharedEnc;

// CORRECT - per-thread
void encryptInThread(const std::string& plaintext,
                     const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext;
    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );
}
```

## Error Handling

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <iostream>

void safeCBC(const SecByteBlock& key, const byte* iv,
             const std::string& ciphertext) {
    using namespace CryptoPP;

    try {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        std::string plaintext;
        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(plaintext)
            )
        );

    } catch (const InvalidKeyLength& e) {
        std::cerr << "Invalid key length" << std::endl;

    } catch (const InvalidCiphertext& e) {
        // CAREFUL: Don't leak this as distinct from MAC failure
        // In production, verify MAC first!
        std::cerr << "Decryption failed" << std::endl;

    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## See Also

- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Authenticated CBC (recommended)
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Modern authenticated encryption
- [AES-CTR](/docs/api/symmetric/aes-ctr/) - Stream cipher mode
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Pipeline filter
- [Security Concepts](/docs/guides/security-concepts/) - Padding oracle attacks
