---
title: AuthenticatedEncryptionFilter / AuthenticatedDecryptionFilter
description: Pipeline filters for AEAD encryption and decryption
weight: 11
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.6.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

`AuthenticatedEncryptionFilter` and `AuthenticatedDecryptionFilter` are pipeline filters for authenticated encryption with associated data (AEAD). They work with ciphers like AES-GCM, ChaCha20-Poly1305, and other authenticated encryption modes.

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

SecByteBlock key(AES::DEFAULT_KEYLENGTH);
rng.GenerateBlock(key, key.size());

byte iv[12];
rng.GenerateBlock(iv, sizeof(iv));

std::string plaintext = "Secret message";
std::string ciphertext, recovered;

// Encrypt with authentication
GCM<AES>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv);

StringSource(plaintext, true,
    new AuthenticatedEncryptionFilter(enc,
        new StringSink(ciphertext)
    )
);
// ciphertext includes 16-byte authentication tag

// Decrypt and verify
GCM<AES>::Decryption dec;
dec.SetKeyWithIV(key, key.size(), iv);

StringSource(ciphertext, true,
    new AuthenticatedDecryptionFilter(dec,
        new StringSink(recovered)
    )
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use with AEAD ciphers (GCM, CCM, EAX, ChaCha20-Poly1305)
- Include Associated Data (AAD) for authenticated headers
- Catch `HashVerificationFailed` to detect tampering
- Use default tag size (16 bytes) for maximum security
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use with non-AEAD ciphers (CBC, CTR)
- Don't ignore authentication failures
- Don't use truncated tags unless required by protocol
- Don't process data after authentication failure
{{< /callout >}}

## AuthenticatedEncryptionFilter

### Constructor

```cpp
AuthenticatedEncryptionFilter(
    AuthenticatedSymmetricCipher& cipher,
    BufferedTransformation* attachment = nullptr,
    bool putAAD = false,
    int tagSize = -1,           // -1 = default tag size
    const std::string& channel = DEFAULT_CHANNEL,
    BlockPaddingScheme padding = DEFAULT_PADDING
);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `cipher` | `AuthenticatedSymmetricCipher&` | AEAD cipher (GCM, CCM, etc.) |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |
| `putAAD` | `bool` | Output AAD before ciphertext |
| `tagSize` | `int` | Tag size (-1 for default) |
| `channel` | `string` | Channel name |
| `padding` | `BlockPaddingScheme` | Padding scheme |

### Methods

#### ChannelPut

```cpp
size_t ChannelPut(const std::string& channel, const byte* inString,
                  size_t length, bool blocking = true);
```

Put data on a specific channel. Use `AAD_CHANNEL` for associated data.

## AuthenticatedDecryptionFilter

### Constructor

```cpp
AuthenticatedDecryptionFilter(
    AuthenticatedSymmetricCipher& cipher,
    BufferedTransformation* attachment = nullptr,
    word32 flags = DEFAULT_FLAGS,
    int tagSize = -1,
    const std::string& channel = DEFAULT_CHANNEL
);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `cipher` | `AuthenticatedSymmetricCipher&` | AEAD cipher |
| `attachment` | `BufferedTransformation*` | Next filter |
| `flags` | `word32` | Behavior flags |
| `tagSize` | `int` | Expected tag size |

### Flags

```cpp
// Throw exception on verification failure (default)
AuthenticatedDecryptionFilter::THROW_EXCEPTION

// Put MAC verification result in channel
AuthenticatedDecryptionFilter::MAC_AT_END

// Default flags
AuthenticatedDecryptionFilter::DEFAULT_FLAGS
```

## Complete Examples

### Example 1: Basic AES-GCM

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];  // GCM recommended IV size
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Confidential data";
    std::string ciphertext, recovered;

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    std::cout << "Plaintext size:  " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    // Ciphertext = plaintext + 16-byte tag

    // Decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    try {
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(recovered)
            )
        );
        std::cout << "Decrypted: " << recovered << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        std::cerr << "Authentication failed!" << std::endl;
    }

    return 0;
}
```

### Example 2: With Associated Data (AAD)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string aad = "Header: authenticated but not encrypted";
    std::string plaintext = "Body: encrypted and authenticated";
    std::string ciphertext, recovered;

    // Encrypt with AAD
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    AuthenticatedEncryptionFilter ef(enc, new StringSink(ciphertext));

    // Put AAD first (on AAD channel)
    ef.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);

    // Put plaintext (on default channel)
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::cout << "AAD: " << aad << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

    // Decrypt with AAD verification
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    AuthenticatedDecryptionFilter df(dec, new StringSink(recovered));

    // Must provide same AAD for verification
    df.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
    df.ChannelMessageEnd(AAD_CHANNEL);

    // Put ciphertext
    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());

    try {
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        std::cout << "Decrypted: " << recovered << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed&) {
        std::cerr << "Authentication failed - AAD or ciphertext modified!" << std::endl;
    }

    return 0;
}
```

### Example 3: ChaCha20-Poly1305

```cpp
#include <cryptopp/chachapoly.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(ChaCha20Poly1305::DEFAULT_KEYLENGTH);  // 32 bytes
    rng.GenerateBlock(key, key.size());

    byte nonce[12];
    rng.GenerateBlock(nonce, sizeof(nonce));

    std::string plaintext = "Message for ChaCha20-Poly1305";
    std::string ciphertext, recovered;

    // Encrypt
    ChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    try {
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(recovered)
            )
        );
        std::cout << "Success: " << recovered << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed&) {
        std::cerr << "Tampering detected!" << std::endl;
    }

    return 0;
}
```

### Example 4: File Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <fstream>

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate random IV
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Write IV to output
    std::ofstream out(outputFile, std::ios::binary);
    out.write((const char*)iv, sizeof(iv));

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    FileSource(inputFile, true,
        new AuthenticatedEncryptionFilter(enc,
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
    byte iv[12];
    in.read((char*)iv, sizeof(iv));

    // Decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    FileSource(in, true,
        new AuthenticatedDecryptionFilter(dec,
            new FileSink(outputFile)
        )
    );
}
```

### Example 5: Custom Tag Size

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Test message";
    std::string ciphertext, recovered;

    const int TAG_SIZE = 12;  // 12-byte tag instead of 16

    // Encrypt with custom tag size
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext),
            false,      // putAAD
            TAG_SIZE    // custom tag size
        )
    );

    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    // plaintext.size() + TAG_SIZE

    // Decrypt with same tag size
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            TAG_SIZE
        )
    );

    std::cout << "Decrypted: " << recovered << std::endl;

    return 0;
}
```

### Example 6: Tampering Detection

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Original message";
    std::string ciphertext;

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Tamper with ciphertext
    if (!ciphertext.empty()) {
        ciphertext[0] ^= 0x01;  // Flip one bit
    }

    // Try to decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    std::string recovered;

    try {
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(recovered)
            )
        );
        std::cout << "Decrypted (shouldn't happen): " << recovered << std::endl;
    } catch (const HashVerificationFilter::HashVerificationFailed&) {
        std::cout << "SUCCESS: Tampering detected!" << std::endl;
        // Do NOT use any data from recovered
    }

    return 0;
}
```

### Example 7: Streaming with Progress

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Large data
    std::string plaintext(1000000, 'A');  // 1 MB
    std::string ciphertext;

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    // Stream through filter
    StringSink sink(ciphertext);
    AuthenticatedEncryptionFilter filter(enc, new Redirector(sink));

    const size_t CHUNK_SIZE = 64 * 1024;  // 64 KB chunks
    size_t processed = 0;

    while (processed < plaintext.size()) {
        size_t chunk = std::min(CHUNK_SIZE, plaintext.size() - processed);
        filter.Put((const byte*)plaintext.data() + processed, chunk);
        processed += chunk;

        std::cout << "\rEncrypting: " << (processed * 100 / plaintext.size()) << "%" << std::flush;
    }
    filter.MessageEnd();

    std::cout << std::endl << "Encrypted " << ciphertext.size() << " bytes" << std::endl;

    return 0;
}
```

## AEAD Cipher Compatibility

| Cipher | Works with These Filters | Tag Size |
|--------|-------------------------|----------|
| `GCM<AES>` | ✅ Yes | 4-16 bytes (16 default) |
| `CCM<AES>` | ✅ Yes | 4-16 bytes |
| `EAX<AES>` | ✅ Yes | 1-16 bytes |
| `ChaCha20Poly1305` | ✅ Yes | 16 bytes |
| `XChaCha20Poly1305` | ✅ Yes | 16 bytes |
| `CBC_Mode<AES>` | ❌ No (not AEAD) | N/A |
| `CTR_Mode<AES>` | ❌ No (not AEAD) | N/A |

## Error Handling

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <iostream>

void safeDecrypt(const std::string& ciphertext,
                 const SecByteBlock& key,
                 const byte* iv) {
    using namespace CryptoPP;

    try {
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, 12);

        std::string plaintext;
        StringSource(ciphertext, true,
            new AuthenticatedDecryptionFilter(dec,
                new StringSink(plaintext)
            )
        );

        // Only reaches here if authentication succeeded
        std::cout << "Authenticated: " << plaintext << std::endl;

    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        // Authentication failed - data was tampered
        std::cerr << "AUTHENTICATION FAILED: " << e.what() << std::endl;
        // Do NOT use any decrypted data!

    } catch (const InvalidCiphertext& e) {
        // Malformed ciphertext
        std::cerr << "Invalid ciphertext: " << e.what() << std::endl;

    } catch (const InvalidKeyLength& e) {
        std::cerr << "Invalid key length: " << e.what() << std::endl;

    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## Security Properties

| Property | AuthenticatedEncryptionFilter |
|----------|-------------------------------|
| **Confidentiality** | Yes |
| **Integrity** | Yes |
| **Authenticity** | Yes |
| **AAD Support** | Yes |
| **Tag verification** | Automatic on MessageEnd |

## Thread Safety

These filters are **not thread-safe**:

```cpp
// WRONG - shared across threads
GCM<AES>::Encryption sharedEnc;

// CORRECT - per-operation
void encryptInThread(const std::string& plaintext,
                     const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext;
    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );
}
```

## vs StreamTransformationFilter

| Feature | AuthenticatedEncryptionFilter | StreamTransformationFilter |
|---------|-------------------------------|----------------------------|
| **Authentication** | Yes | No |
| **Tag handling** | Automatic | N/A |
| **AAD support** | Yes | No |
| **Use with** | AEAD ciphers | Non-AEAD ciphers |
| **Tampering detection** | Yes | No |

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Primary AEAD cipher
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative AEAD
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Non-AEAD filter
- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File I/O
- [Security Concepts](/docs/guides/security-concepts/) - Authenticated encryption
