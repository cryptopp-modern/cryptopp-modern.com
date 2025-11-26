---
title: AES-CTR
description: AES Counter Mode encryption API reference
weight: 4
---

**Header:** `#include <cryptopp/aes.h>`, `#include <cryptopp/modes.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

AES-CTR (Counter Mode) is a stream cipher mode that converts AES into a stream cipher by encrypting sequential counter values. It provides confidentiality but **not** authentication—you must add a MAC (like HMAC) or use AES-GCM instead for authenticated encryption.

{{< callout type="warning" >}}
**Important:** CTR mode provides **encryption only**, not authentication. An attacker can flip bits in the ciphertext to flip corresponding bits in the plaintext. For most applications, use [AES-GCM](/docs/api/symmetric/aes-gcm/) or [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) instead.
{{< /callout >}}

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// 256-bit key
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
rng.GenerateBlock(key, key.size());

// 16-byte IV (counter initial value)
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

std::string plaintext = "Secret message";
std::string ciphertext, recovered;

// Encrypt
CTR_Mode<AES>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv);

StringSource(plaintext, true,
    new StreamTransformationFilter(enc,
        new StringSink(ciphertext)
    )
);

// Decrypt
CTR_Mode<AES>::Decryption dec;
dec.SetKeyWithIV(key, key.size(), iv);

StringSource(ciphertext, true,
    new StreamTransformationFilter(dec,
        new StringSink(recovered)
    )
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use a unique IV/nonce for every message with the same key
- Combine with HMAC for authenticated encryption (Encrypt-then-MAC)
- Use for random-access encryption (e.g., disk encryption)
- Prefer AES-GCM for new applications needing authentication
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- **CRITICAL:** Never reuse an IV with the same key (catastrophic failure)
- Don't use without authentication in network protocols
- Don't encrypt more than 2^64 blocks with same key
- Don't use for scenarios where authentication is needed
{{< /callout >}}

## Why CTR Mode?

CTR mode has unique properties that make it useful for specific scenarios:

| Property | Benefit |
|----------|---------|
| **No padding** | Output size equals input size |
| **Random access** | Can decrypt any block independently |
| **Parallelizable** | Encryption/decryption can be parallelized |
| **Pre-computation** | Key stream can be generated before plaintext |
| **Same operation** | Encryption and decryption are identical |

## Constants

```cpp
AES::DEFAULT_KEYLENGTH    // 16 bytes (128-bit)
AES::MAX_KEYLENGTH        // 32 bytes (256-bit)
AES::BLOCKSIZE            // 16 bytes (IV size)
```

## Constructors

```cpp
// Default constructor (must call SetKeyWithIV)
CTR_Mode<AES>::Encryption enc;
CTR_Mode<AES>::Decryption dec;
```

## Methods

### SetKeyWithIV

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen, const byte* iv, size_t ivLen = BLOCKSIZE);
```

Sets the encryption/decryption key and initial counter value.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `const byte*` | Encryption key (16, 24, or 32 bytes) |
| `keyLen` | `size_t` | Key length in bytes |
| `iv` | `const byte*` | Initial counter value (16 bytes) |
| `ivLen` | `size_t` | IV length (default: block size) |

### ProcessData

```cpp
void ProcessData(byte* outString, const byte* inString, size_t length);
```

Encrypts or decrypts data in place or to output buffer.

### Seek

```cpp
void Seek(lword position);
```

Seeks to a specific byte position in the key stream (for random access).

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
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "The quick brown fox jumps over the lazy dog";
    std::string ciphertext, recovered;

    // Encrypt
    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Note: ciphertext.size() == plaintext.size() (no padding!)

    // Decrypt
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    std::cout << "Original:  " << plaintext << std::endl;
    std::cout << "Recovered: " << recovered << std::endl;

    return 0;
}
```

### Example 2: CTR with HMAC (Encrypt-then-MAC)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

class AES_CTR_HMAC {
    SecByteBlock encKey;
    SecByteBlock macKey;

public:
    AES_CTR_HMAC() {
        using namespace CryptoPP;
        AutoSeededRandomPool rng;

        encKey.resize(AES::DEFAULT_KEYLENGTH);
        macKey.resize(32);  // HMAC-SHA256 key

        rng.GenerateBlock(encKey, encKey.size());
        rng.GenerateBlock(macKey, macKey.size());
    }

    std::string encrypt(const std::string& plaintext) {
        using namespace CryptoPP;

        AutoSeededRandomPool rng;

        // Generate random IV
        byte iv[AES::BLOCKSIZE];
        rng.GenerateBlock(iv, sizeof(iv));

        // Encrypt
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(encKey, encKey.size(), iv);

        std::string ciphertext;
        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );

        // Prepend IV
        std::string result;
        result.assign((const char*)iv, sizeof(iv));
        result += ciphertext;

        // Compute HMAC over IV + ciphertext
        HMAC<SHA256> hmac(macKey, macKey.size());
        std::string mac;
        StringSource(result, true,
            new HashFilter(hmac,
                new StringSink(mac)
            )
        );

        // Append MAC
        result += mac;

        return result;  // IV || ciphertext || MAC
    }

    std::string decrypt(const std::string& data) {
        using namespace CryptoPP;

        if (data.size() < AES::BLOCKSIZE + 32) {
            throw std::runtime_error("Data too short");
        }

        // Split: IV || ciphertext || MAC
        size_t macOffset = data.size() - 32;
        std::string ivAndCiphertext = data.substr(0, macOffset);
        std::string receivedMac = data.substr(macOffset);

        // Verify MAC first (Encrypt-then-MAC)
        HMAC<SHA256> hmac(macKey, macKey.size());
        std::string computedMac;
        StringSource(ivAndCiphertext, true,
            new HashFilter(hmac,
                new StringSink(computedMac)
            )
        );

        if (computedMac != receivedMac) {
            throw std::runtime_error("MAC verification failed");
        }

        // Extract IV and ciphertext
        byte iv[AES::BLOCKSIZE];
        memcpy(iv, ivAndCiphertext.data(), sizeof(iv));
        std::string ciphertext = ivAndCiphertext.substr(sizeof(iv));

        // Decrypt
        CTR_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(encKey, encKey.size(), iv);

        std::string plaintext;
        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(plaintext)
            )
        );

        return plaintext;
    }
};

int main() {
    AES_CTR_HMAC cipher;

    std::string plaintext = "Secret authenticated message";
    std::string encrypted = cipher.encrypt(plaintext);
    std::string decrypted = cipher.decrypt(encrypted);

    std::cout << "Original:  " << plaintext << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```

### Example 3: Random Access Decryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <cstring>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Encrypt a large block
    std::string plaintext(1000, 'A');
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = 'A' + (i % 26);
    }

    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext(plaintext.size(), '\0');
    enc.ProcessData((byte*)ciphertext.data(),
                    (const byte*)plaintext.data(),
                    plaintext.size());

    // Decrypt only bytes 500-509 (random access!)
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    // Seek to position 500
    dec.Seek(500);

    byte decrypted[10];
    dec.ProcessData(decrypted, (const byte*)ciphertext.data() + 500, 10);

    std::cout << "Decrypted bytes 500-509: ";
    std::cout.write((const char*)decrypted, 10);
    std::cout << std::endl;

    // Verify against original
    std::cout << "Original bytes 500-509:  ";
    std::cout << plaintext.substr(500, 10) << std::endl;

    return 0;
}
```

### Example 4: File Encryption

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
    CTR_Mode<AES>::Encryption enc;
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
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    FileSource(in, true,
        new StreamTransformationFilter(dec,
            new FileSink(outputFile)
        )
    );
}
```

### Example 5: In-Place Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <vector>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Data buffer
    std::vector<byte> data = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

    std::cout << "Original: ";
    std::cout.write((const char*)data.data(), data.size());
    std::cout << std::endl;

    // Encrypt in place
    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    enc.ProcessData(data.data(), data.data(), data.size());

    std::cout << "Encrypted (hex): ";
    for (byte b : data) {
        printf("%02X", b);
    }
    std::cout << std::endl;

    // Decrypt in place
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    dec.ProcessData(data.data(), data.data(), data.size());

    std::cout << "Decrypted: ";
    std::cout.write((const char*)data.data(), data.size());
    std::cout << std::endl;

    return 0;
}
```

## IV/Nonce Requirements

### Critical: Never Reuse IV with Same Key

```
If IV is reused with same key:
- keystream₁ = AES(key, counter + IV)
- keystream₂ = AES(key, counter + IV)  // Same!

ciphertext₁ ⊕ ciphertext₂ = plaintext₁ ⊕ plaintext₂

Attacker learns XOR of plaintexts - catastrophic information leak!
```

### Safe IV Generation

```cpp
// Option 1: Random IV (recommended for most cases)
AutoSeededRandomPool rng;
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

// Option 2: Counter-based (for high-volume encryption)
// Requires careful management to prevent reuse
uint64_t messageCounter = 0;
byte iv[AES::BLOCKSIZE] = {0};
memcpy(iv, &messageCounter, sizeof(messageCounter));
messageCounter++;

// Option 3: Nonce + Counter (hybrid)
byte nonce[8];  // Random per session
rng.GenerateBlock(nonce, sizeof(nonce));
uint64_t counter = 0;
byte iv[16];
memcpy(iv, nonce, 8);
memcpy(iv + 8, &counter, 8);
```

## CTR Mode vs Other Modes

| Feature | CTR | CBC | GCM |
|---------|-----|-----|-----|
| **Padding** | No | Yes (PKCS7) | No |
| **Parallelizable** | Yes | Decrypt only | Yes |
| **Random access** | Yes | No | No |
| **Authentication** | No | No | Yes |
| **IV reuse impact** | Catastrophic | Catastrophic | Catastrophic |

## Performance

### Benchmarks (approximate)

| Configuration | Speed |
|---------------|-------|
| AES-CTR with AES-NI | ~4-6 GB/s |
| AES-CTR (software) | ~300-500 MB/s |
| AES-CBC with AES-NI | ~2-3 GB/s |
| AES-GCM with AES-NI | ~3-5 GB/s |

CTR mode is faster than CBC because:
- No chaining dependency (parallelizable)
- Same operation for encrypt/decrypt
- Pre-computation possible

## Security Properties

| Property | Value |
|----------|-------|
| **Confidentiality** | Yes (with unique IV) |
| **Integrity** | No (must add MAC) |
| **Key size** | 128, 192, or 256 bits |
| **Block size** | 128 bits |
| **Max data per key** | 2^64 blocks (~256 exabytes) |

### Security Notes

1. **No authentication:** Ciphertext can be modified undetected
2. **Bit-flipping attacks:** Attacker can flip specific plaintext bits
3. **IV uniqueness:** Each (key, IV) pair must be used only once
4. **Counter overflow:** Don't encrypt more than 2^64 blocks

## When to Use CTR Mode

### ✅ Use CTR for:

1. **Disk/file encryption** with separate integrity check
2. **Random access requirements** (seek to any position)
3. **Streaming encryption** where length is unknown
4. **When combined with HMAC** (Encrypt-then-MAC)
5. **Building custom AEAD** constructions

### ❌ Don't use CTR alone for:

1. **Network protocols** (use GCM or ChaCha20-Poly1305)
2. **Any scenario needing integrity** without adding MAC
3. **When simpler authenticated modes are available**

## Thread Safety

CTR mode objects are **not thread-safe**:

```cpp
// WRONG - shared instance
CTR_Mode<AES>::Encryption sharedEnc;

// CORRECT - per-thread
void encryptInThread(const std::string& plaintext,
                     const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    CTR_Mode<AES>::Encryption enc;
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
#include <iostream>

void safeCTR(const SecByteBlock& key, const byte* iv,
             const std::string& plaintext) {
    using namespace CryptoPP;

    try {
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv);

        std::string ciphertext;
        StringSource(plaintext, true,
            new StreamTransformationFilter(enc,
                new StringSink(ciphertext)
            )
        );

    } catch (const InvalidKeyLength& e) {
        std::cerr << "Invalid key length: " << e.what() << std::endl;
        // AES requires 16, 24, or 32 byte keys
    } catch (const Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
    }
}
```

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption (recommended)
- [AES-CBC](/docs/api/symmetric/aes-cbc/) - Block cipher mode with padding
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative AEAD
- [HMAC](/docs/api/mac/hmac/) - For Encrypt-then-MAC with CTR
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Pipeline filter
- [Security Concepts](/docs/guides/security-concepts/) - Nonce management
