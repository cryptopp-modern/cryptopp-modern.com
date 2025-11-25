---
title: AES-GCM
description: AES-GCM authenticated encryption API reference
weight: 1
---

**Header:** `#include <cryptopp/aes.h>` and `#include <cryptopp/gcm.h>`
**Namespace:** `CryptoPP`
**Since:** Crypto++ 3.1 (AES), 5.6.0 (GCM mode)

AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) is an authenticated encryption algorithm that provides both confidentiality and authenticity. It's the gold standard for symmetric encryption and is widely used in TLS, IPsec, and disk encryption.

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Key and IV (in real code, generate randomly)
    byte key[AES::DEFAULT_KEYLENGTH] = {0}; // 16 bytes for AES-128
    byte iv[12] = {0};  // 12 bytes recommended for GCM

    // Message to encrypt
    std::string plaintext = "Hello, World!";
    std::string ciphertext, decrypted;

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

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
- Use AES-GCM for authenticated encryption (encryption + integrity)
- Use 256-bit keys (AES-256-GCM) for new systems
- Generate random IVs using `AutoSeededRandomPool`
- Use 12-byte IVs (recommended for GCM)
- Never reuse an IV with the same key

**Avoid:**
- Using ECB or CBC mode without authentication (use GCM instead)
- Hardcoded keys or IVs (shown in examples for clarity only)
- Reusing IVs - each encryption must use a unique IV
- Ignoring authentication failures during decryption
{{< /callout >}}

## Class: GCM<AES>

Template class for AES in GCM (Galois/Counter Mode) authenticated encryption.

### Key Sizes

| Key Size | Security | Constant | Recommended |
|----------|----------|----------|-------------|
| 128-bit | 128-bit | `AES::DEFAULT_KEYLENGTH` (16) | Acceptable |
| 192-bit | 192-bit | 24 bytes | Rare |
| 256-bit | 256-bit | `AES::MAX_KEYLENGTH` (32) | ✓ Recommended |

### Constants

```cpp
static const int MIN_KEYLENGTH = 16;    // 128 bits
static const int MAX_KEYLENGTH = 32;    // 256 bits
static const int DEFAULT_KEYLENGTH = 16; // 128 bits
static const int BLOCKSIZE = 16;        // 128 bits (always)
static const int IV_LENGTH = 12;        // 96 bits (recommended)
static const int TAG_SIZE = 16;         // 128 bits
```

## GCM<AES>::Encryption

Authenticated encryption class.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set encryption key and initialization vector.

**Parameters:**
- `key` - Encryption key (16, 24, or 32 bytes)
- `keyLength` - Length of key in bytes
- `iv` - Initialization vector (12 bytes recommended)
- `ivLength` - Length of IV in bytes

**Thread Safety:** Not thread-safe. Create separate objects per thread.

**Example:**

```cpp
GCM<AES>::Encryption enc;
byte key[32];  // 256-bit key
byte iv[12];   // 96-bit IV

AutoSeededRandomPool rng;
rng.GenerateBlock(key, sizeof(key));
rng.GenerateBlock(iv, sizeof(iv));

enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
```

#### SpecifyDataLengths()

```cpp
void SpecifyDataLengths(lword headerLength, lword messageLength,
                        lword footerLength = 0);
```

Specify lengths of additional authenticated data (AAD) and message.

**Parameters:**
- `headerLength` - Length of AAD in bytes
- `messageLength` - Length of plaintext in bytes
- `footerLength` - Length of footer (usually 0)

**Optional:** Only needed for optimal performance with known lengths.

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
- `macSize` - Size of MAC buffer (usually 16)
- `iv` - Initialization vector
- `ivLength` - IV length (12 bytes recommended)
- `aad` - Additional authenticated data (can be NULL)
- `aadLength` - AAD length
- `message` - Plaintext to encrypt
- `messageLength` - Plaintext length

**Throws:** Nothing (authentication happens during decryption)

**Example:**

```cpp
GCM<AES>::Encryption enc;
enc.SetKey(key, sizeof(key));

byte ciphertext[100];
byte tag[16];
std::string plaintext = "Secret message";

enc.EncryptAndAuthenticate(
    ciphertext, tag, sizeof(tag),
    iv, sizeof(iv),
    nullptr, 0,  // No AAD
    (const byte*)plaintext.data(), plaintext.size()
);
```

## GCM<AES>::Decryption

Authenticated decryption class.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set decryption key and IV (same as encryption).

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
- `macSize` - Size of MAC (usually 16)
- `iv` - Initialization vector (must match encryption)
- `ivLength` - IV length
- `aad` - Additional authenticated data (must match encryption)
- `aadLength` - AAD length
- `ciphertext` - Encrypted data
- `ciphertextLength` - Ciphertext length

**Returns:** `true` if authentication succeeded, `false` if verification failed

**Important:** Always check the return value. If false, the message has been tampered with.

**Example:**

```cpp
GCM<AES>::Decryption dec;
dec.SetKey(key, sizeof(key));

byte plaintext[100];
bool valid = dec.DecryptAndVerify(
    plaintext,
    tag, sizeof(tag),
    iv, sizeof(iv),
    nullptr, 0,  // No AAD
    ciphertext, ciphertextLength
);

if (!valid) {
    std::cerr << "Authentication failed! Message tampered." << std::endl;
    return 1;
}
```

## Complete Example: File Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

void encryptFile(const std::string& filename, const SecByteBlock& key) {
    // Generate random IV
    AutoSeededRandomPool rng;
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Read file
    std::string plaintext;
    FileSource(filename.c_str(), true, new StringSink(plaintext));

    // Encrypt
    std::string ciphertext;
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    AuthenticatedEncryptionFilter aef(enc,
        new StringSink(ciphertext)
    );
    aef.Put((const byte*)plaintext.data(), plaintext.size());
    aef.MessageEnd();

    // Save: IV + ciphertext + tag (tag is appended automatically)
    std::ofstream out(filename + ".enc", std::ios::binary);
    out.write((const char*)iv, sizeof(iv));
    out.write(ciphertext.data(), ciphertext.size());
}

bool decryptFile(const std::string& filename, const SecByteBlock& key) {
    // Read encrypted file
    std::ifstream in(filename, std::ios::binary);

    // Read IV
    byte iv[12];
    in.read((char*)iv, sizeof(iv));

    // Read ciphertext + tag
    std::string ciphertext;
    FileSource(in, true, new StringSink(ciphertext));

    // Decrypt and verify
    try {
        std::string plaintext;
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

        AuthenticatedDecryptionFilter adf(dec,
            new StringSink(plaintext),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS
        );

        StringSource(ciphertext, true,
            new Redirector(adf)
        );

        // Save decrypted file
        std::string outname = filename.substr(0, filename.size() - 4);
        FileSink(outname.c_str()).Put((const byte*)plaintext.data(),
                                       plaintext.size());
        return true;

    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        std::cerr << "Authentication failed: " << e.what() << std::endl;
        return false;
    }
}

int main() {
    // Generate 256-bit key
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::MAX_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    // Encrypt
    encryptFile("document.txt", key);
    std::cout << "File encrypted successfully" << std::endl;

    // Decrypt
    if (decryptFile("document.txt.enc", key)) {
        std::cout << "File decrypted successfully" << std::endl;
    }

    return 0;
}
```

## Additional Authenticated Data (AAD)

AAD is data that's authenticated but not encrypted (like packet headers).

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>

void encryptWithAAD() {
    using namespace CryptoPP;

    byte key[32], iv[12];
    // ... initialize key and iv ...

    std::string header = "packet-id:12345";  // AAD (not encrypted)
    std::string plaintext = "Secret payload";
    std::string ciphertext;

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Add AAD before plaintext
    AuthenticatedEncryptionFilter aef(enc,
        new StringSink(ciphertext)
    );

    aef.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    aef.ChannelMessageEnd(AAD_CHANNEL);

    aef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(),
                   plaintext.size());
    aef.ChannelMessageEnd(DEFAULT_CHANNEL);

    // Now ciphertext contains: encrypted payload + tag
    // Header remains in plaintext but is authenticated
}
```

## Performance

### Hardware Acceleration

AES-GCM benefits from hardware acceleration on modern CPUs:

| Platform | Instructions | Speedup |
|----------|-------------|---------|
| Intel/AMD x86-64 | AES-NI + PCLMULQDQ | 5-10x |
| ARM v8+ | AES + PMULL | 5-10x |
| Apple Silicon | AES + PMULL | 8-12x |
| POWER8+ | AES + VPMSUMB | 4-8x |

### Benchmarks (AES-256-GCM)

Approximate speeds on modern hardware with AES-NI:

| Operation | Speed (MB/s) | Notes |
|-----------|--------------|-------|
| Encryption | 2000-4000 | With hardware acceleration |
| Decryption | 2000-4000 | Same as encryption |
| No acceleration | 50-200 | Software implementation |

**Note:** GCM mode provides parallel processing, making it faster than CBC mode.

## Security

### Security Properties

- **Confidentiality:** 128-bit (AES-128) or 256-bit (AES-256)
- **Authenticity:** 128-bit MAC (prevents tampering)
- **Nonce requirement:** Must never reuse IV with same key
- **Standard:** NIST SP 800-38D, FIPS 197

### Important Security Notes

1. **IV Reuse is Catastrophic:** Reusing an IV with the same key completely breaks GCM security. Always generate random IVs.

2. **Authentication is Critical:** Always verify the authentication tag. A failed verification means the data has been tampered with.

3. **Key Management:** Store keys securely using `SecByteBlock` which zeroes memory on destruction.

4. **IV Management:**
   - Use 12-byte (96-bit) IVs for best performance
   - Generate IVs using `AutoSeededRandomPool`
   - Store IV alongside ciphertext (IV doesn't need to be secret)

### Test Vectors (NIST SP 800-38D)

```cpp
// AES-128-GCM Test Vector
byte key[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

byte iv[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

byte plaintext[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

// Expected ciphertext
byte expected_ciphertext[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91
};

// Expected authentication tag
byte expected_tag[] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};
```

## Common Patterns

### Generate Key from Password

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

SecByteBlock deriveKey(const std::string& password,
                       const byte* salt, size_t saltLen) {
    SecByteBlock key(32);  // 256-bit key

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(
        key, key.size(),
        0,  // unused
        (const byte*)password.data(), password.size(),
        salt, saltLen,
        100000  // iterations
    );

    return key;
}
```

### Stream Processing

```cpp
void encryptLargeFile(const std::string& infile,
                      const std::string& outfile,
                      const SecByteBlock& key) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    // Write IV first
    FileSink out(outfile.c_str());
    out.Put(iv, sizeof(iv));

    // Stream encryption
    FileSource(infile.c_str(), true,
        new AuthenticatedEncryptionFilter(enc,
            new Redirector(out)
        )
    );
}
```

## Thread Safety

**Not thread-safe.** Create separate `GCM<AES>::Encryption` and `GCM<AES>::Decryption` objects for each thread.

```cpp
// WRONG - sharing between threads
GCM<AES>::Encryption shared_enc;

// CORRECT - one per thread
void threadFunc() {
    GCM<AES>::Encryption enc;  // Thread-local
    // ... use enc ...
}
```

## Exceptions

- `InvalidKeyLength` - Key size is not 16, 24, or 32 bytes
- `HashVerificationFilter::HashVerificationFailed` - Authentication tag verification failed (message tampered)

## Algorithm Details

- **Algorithm:** AES (Rijndael with 128-bit blocks)
- **Mode:** GCM (Galois/Counter Mode)
- **Key sizes:** 128, 192, or 256 bits
- **Block size:** 128 bits (fixed)
- **IV size:** 96 bits (12 bytes) recommended, 1 byte to 2^64-1 bytes supported
- **Tag size:** 128 bits (16 bytes) default, 96-128 bits supported
- **Standard:** FIPS 197 (AES), NIST SP 800-38D (GCM)

## See Also

- [AES-GCM Guide](/docs/algorithms/aes-gcm/) - Conceptual overview
- [Symmetric Encryption Overview](/docs/guides/symmetric-encryption/) - Choosing encryption algorithms
- [Security Concepts](/docs/guides/security-concepts/) - Understanding cryptographic security
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Alternative authenticated cipher
