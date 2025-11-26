---
title: StreamTransformationFilter
description: Pipeline filter for symmetric encryption and decryption
weight: 10
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

StreamTransformationFilter is a pipeline filter that applies symmetric encryption or decryption as data flows through. It handles padding automatically for block ciphers and works with any `StreamTransformation` (AES-CBC, AES-CTR, ChaCha20, etc.).

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// Generate key and IV
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(key, key.size());
rng.GenerateBlock(iv, sizeof(iv));

std::string plaintext = "Secret message to encrypt";
std::string ciphertext, recovered;

// Encrypt
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
- Use `AuthenticatedEncryptionFilter` for AEAD modes (GCM, CCM)
- Use `StreamTransformationFilter` for non-AEAD modes (CBC, CTR)
- Always use random IVs for each encryption
- Prefer AEAD modes (GCM) over CBC for new applications
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use CBC without authentication (use GCM instead)
- Don't reuse IVs with the same key
- Don't use ECB mode (patterns leak)
- Don't skip padding for block ciphers
{{< /callout >}}

## Constructor

```cpp
StreamTransformationFilter(StreamTransformation& cipher,
                           BufferedTransformation* attachment = nullptr,
                           BlockPaddingScheme padding = DEFAULT_PADDING);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `cipher` | `StreamTransformation&` | Encryption or decryption object |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |
| `padding` | `BlockPaddingScheme` | Padding scheme for block ciphers |

### Padding Schemes

```cpp
// For block ciphers (AES-CBC, etc.)
DEFAULT_PADDING           // PKCS#7 padding (recommended)
PKCS_PADDING              // Explicit PKCS#7
ONE_AND_ZEROS_PADDING     // ISO 10126
ZEROS_PADDING             // Pad with zeros (not recommended)
NO_PADDING                // No padding (input must be block-aligned)

// For stream ciphers (CTR, ChaCha20)
// Padding is ignored - stream ciphers don't need padding
```

## Cipher Modes

### Block Cipher Modes (Require Padding)

| Mode | Class | Authentication | Parallelizable |
|------|-------|----------------|----------------|
| CBC | `CBC_Mode<AES>` | ❌ No | ❌ No |
| ECB | `ECB_Mode<AES>` | ❌ No | ✅ Yes |

### Stream Cipher Modes (No Padding Needed)

| Mode | Class | Authentication | Parallelizable |
|------|-------|----------------|----------------|
| CTR | `CTR_Mode<AES>` | ❌ No | ✅ Yes |
| OFB | `OFB_Mode<AES>` | ❌ No | ❌ No |
| CFB | `CFB_Mode<AES>` | ❌ No | ❌ No |

### AEAD Modes (Use AuthenticatedEncryptionFilter instead)

| Mode | Filter | Authentication |
|------|--------|----------------|
| GCM | `AuthenticatedEncryptionFilter` | ✅ Yes |
| CCM | `AuthenticatedEncryptionFilter` | ✅ Yes |
| EAX | `AuthenticatedEncryptionFilter` | ✅ Yes |

## Complete Examples

### Example 1: AES-CBC Encryption

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 128-bit
    byte iv[AES::BLOCKSIZE];                    // 128-bit
    rng.GenerateBlock(key, key.size());
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

    std::cout << "Plaintext size: " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    // Note: ciphertext is padded to block boundary

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

### Example 2: AES-CTR Mode (Stream Cipher)

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // 256-bit key for maximum security
    SecByteBlock key(AES::MAX_KEYLENGTH);
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "CTR mode produces ciphertext same size as plaintext";
    std::string ciphertext, recovered;

    // Encrypt with CTR mode
    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    std::cout << "Plaintext size: " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    // CTR mode: same size (no padding)

    // Decrypt
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    return 0;
}
```

### Example 3: ChaCha20 Stream Cipher

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // ChaCha20 uses 256-bit key and 64-bit or 96-bit nonce
    SecByteBlock key(ChaCha::MAX_KEYLENGTH);  // 32 bytes
    byte iv[ChaCha::IV_LENGTH];               // 8 bytes
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "ChaCha20 is a high-speed stream cipher";
    std::string ciphertext, recovered;

    // Encrypt
    ChaCha::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    ChaCha::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    return 0;
}
```

### Example 4: File Encryption

```cpp
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
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

    // Write IV to output file first
    std::ofstream out(outputFile, std::ios::binary);
    out.write(reinterpret_cast<const char*>(iv), sizeof(iv));

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

    // Read IV from input file
    std::ifstream in(inputFile, std::ios::binary);
    byte iv[AES::BLOCKSIZE];
    in.read(reinterpret_cast<char*>(iv), sizeof(iv));

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

### Example 5: Hex Output

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

std::string encryptToHex(const std::string& plaintext,
                          const SecByteBlock& key,
                          const byte* iv) {
    using namespace CryptoPP;

    std::string hexCiphertext;

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new HexEncoder(new StringSink(hexCiphertext))
        )
    );

    return hexCiphertext;
}

std::string decryptFromHex(const std::string& hexCiphertext,
                            const SecByteBlock& key,
                            const byte* iv) {
    using namespace CryptoPP;

    std::string plaintext;

    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(hexCiphertext, true,
        new HexDecoder(
            new StreamTransformationFilter(dec,
                new StringSink(plaintext)
            )
        )
    );

    return plaintext;
}
```

### Example 6: Custom Padding

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

void encryptWithPadding(const std::string& plaintext,
                         const SecByteBlock& key,
                         const byte* iv,
                         BlockPaddingScheme padding) {
    using namespace CryptoPP;

    std::string ciphertext;

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext),
            padding  // Explicit padding scheme
        )
    );
}

// Usage examples:
// PKCS#7 padding (default, recommended)
encryptWithPadding(data, key, iv, StreamTransformationFilter::PKCS_PADDING);

// No padding (data must be multiple of block size)
encryptWithPadding(blockAlignedData, key, iv, StreamTransformationFilter::NO_PADDING);

// Zeros padding (be careful - can't distinguish padding from data)
encryptWithPadding(data, key, iv, StreamTransformationFilter::ZEROS_PADDING);
```

## AuthenticatedEncryptionFilter

For AEAD modes (GCM, CCM, EAX), use `AuthenticatedEncryptionFilter`:

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    byte iv[12];  // 96-bit IV for GCM
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Authenticated encryption protects integrity too";
    std::string ciphertext, recovered;

    // Encrypt with authentication
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );
    // ciphertext includes authentication tag

    // Decrypt and verify
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    try {
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(recovered)
            )
        );
        // Decryption succeeded and data is authentic
    } catch (const HashVerificationFilter::HashVerificationFailed&) {
        // Data was tampered with
        std::cerr << "Authentication failed!" << std::endl;
    }

    return 0;
}
```

## Ciphertext Size

| Mode | Ciphertext Size |
|------|-----------------|
| CBC | Padded to next block boundary |
| CTR | Same as plaintext |
| GCM | Plaintext + 16 bytes (tag) |
| ChaCha20 | Same as plaintext |
| ChaCha20-Poly1305 | Plaintext + 16 bytes (tag) |

```cpp
// CBC padding calculation
size_t cbcCiphertextSize(size_t plaintextSize) {
    size_t blockSize = AES::BLOCKSIZE;  // 16
    return ((plaintextSize / blockSize) + 1) * blockSize;
}

// CTR - no padding
size_t ctrCiphertextSize(size_t plaintextSize) {
    return plaintextSize;
}

// GCM - adds authentication tag
size_t gcmCiphertextSize(size_t plaintextSize) {
    return plaintextSize + 16;  // 16-byte tag
}
```

## IV/Nonce Management

### Random IV (Recommended for CBC)

```cpp
AutoSeededRandomPool rng;
byte iv[AES::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

// Store IV with ciphertext (IV doesn't need to be secret)
std::string output;
output.assign(reinterpret_cast<const char*>(iv), sizeof(iv));
output += ciphertext;
```

### Counter-based Nonce (For CTR/GCM)

```cpp
// Use a counter to ensure unique nonces
uint64_t messageCounter = 0;

void encrypt(const std::string& plaintext, const SecByteBlock& key) {
    byte nonce[12];  // 96-bit nonce for GCM

    // First 4 bytes: random sender ID (generated once)
    // Last 8 bytes: counter (incremented each message)
    memcpy(nonce, senderID, 4);
    memcpy(nonce + 4, &messageCounter, 8);
    messageCounter++;

    // Use nonce...
}
```

## Error Handling

```cpp
void safeDecrypt(const std::string& ciphertext,
                 const SecByteBlock& key,
                 const byte* iv) {
    using namespace CryptoPP;

    try {
        std::string plaintext;

        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(plaintext)
            )
        );

        // Success
    } catch (const InvalidCiphertext& e) {
        // Padding error (possible tampering or wrong key)
        std::cerr << "Decryption failed: invalid padding" << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Crypto error: " << e.what() << std::endl;
    }
}
```

## Security Considerations

### CBC Mode Vulnerabilities

```cpp
// WARNING: CBC without authentication is vulnerable to:
// 1. Padding oracle attacks
// 2. Bit-flipping attacks

// SOLUTION: Use AEAD modes (GCM) or add HMAC

// Better: Use GCM
GCM<AES>::Encryption enc;

// Alternative: CBC + HMAC (Encrypt-then-MAC)
// See AES-CBC-HMAC documentation
```

### IV Reuse

```cpp
// CRITICAL: Never reuse IV with the same key

// WRONG
byte fixedIV[16] = {0};  // Same IV every time

// CORRECT
AutoSeededRandomPool rng;
byte iv[16];
rng.GenerateBlock(iv, sizeof(iv));  // Fresh IV each time
```

## Performance Tips

### Reuse Cipher Objects

```cpp
// Efficient - reuse cipher object
CBC_Mode<AES>::Encryption enc;
enc.SetKey(key, key.size());

for (const auto& plaintext : messages) {
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));
    enc.Resynchronize(iv);  // New IV, same key

    std::string ciphertext;
    StringSource(plaintext, true,
        new StreamTransformationFilter(enc, new StringSink(ciphertext))
    );
}
```

### In-Place Encryption (CTR mode)

```cpp
// CTR mode can encrypt in-place
CTR_Mode<AES>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv);

byte buffer[1024];
// Fill buffer with plaintext...

enc.ProcessData(buffer, buffer, sizeof(buffer));
// buffer now contains ciphertext
```

## Thread Safety

StreamTransformationFilter is **not thread-safe**:

```cpp
// WRONG - shared cipher
CBC_Mode<AES>::Encryption sharedEnc;

// CORRECT - per-thread cipher
void encryptInThread(const std::string& data, const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext;
    StringSource(data, true,
        new StreamTransformationFilter(enc, new StringSink(ciphertext))
    );
}
```

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Recommended AEAD mode
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative AEAD
- [AES-CBC with HMAC](/docs/api/symmetric/aes-cbc-hmac/) - Authenticated CBC
- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File I/O
- [Security Concepts](/docs/guides/security-concepts/) - IV management
