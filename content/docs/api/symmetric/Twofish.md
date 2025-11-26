---
title: Twofish
description: Twofish block cipher API reference
weight: 8
---

**Header:** `#include <cryptopp/twofish.h>`, `#include <cryptopp/modes.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 3.1
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

Twofish is a 128-bit block cipher designed by Bruce Schneier and team as an AES finalist. While AES (Rijndael) was selected, Twofish remains a highly regarded cipher with no known successful attacks. It supports key sizes of 128, 192, and 256 bits.

{{< callout type="info" >}}
**Status:** Twofish is cryptographically sound with no known weaknesses. However, AES is the industry standard with hardware acceleration on most modern CPUs. Use Twofish when you need an AES alternative or for defense-in-depth layered encryption.
{{< /callout >}}

## Quick Example

```cpp
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// 256-bit key
SecByteBlock key(Twofish::MAX_KEYLENGTH);
rng.GenerateBlock(key, key.size());

// 16-byte IV
byte iv[Twofish::BLOCKSIZE];
rng.GenerateBlock(iv, sizeof(iv));

std::string plaintext = "Secret message";
std::string ciphertext, recovered;

// Encrypt with Twofish-CBC
CBC_Mode<Twofish>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), iv);

StringSource(plaintext, true,
    new StreamTransformationFilter(enc,
        new StringSink(ciphertext)
    )
);

// Decrypt
CBC_Mode<Twofish>::Decryption dec;
dec.SetKeyWithIV(key, key.size(), iv);

StringSource(ciphertext, true,
    new StreamTransformationFilter(dec,
        new StringSink(recovered)
    )
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use with authenticated modes (GCM, EAX) or add HMAC
- Use 256-bit keys for maximum security
- Generate random IVs for each message
- Consider for defense-in-depth (layered with AES)
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Using without authentication (same as any block cipher)
- Reusing IVs with the same key
- ECB mode (reveals patterns)
- Expecting hardware acceleration (Twofish has none)
{{< /callout >}}

## Class: Twofish

### Constants

```cpp
static const int BLOCKSIZE = 16;           // 128 bits
static const int DEFAULT_KEYLENGTH = 16;   // 128 bits
static const int MAX_KEYLENGTH = 32;       // 256 bits
static const int MIN_KEYLENGTH = 16;       // 128 bits
```

### Types

```cpp
Twofish::Encryption  // Raw block encryption
Twofish::Decryption  // Raw block decryption

// Mode wrappers
CBC_Mode<Twofish>::Encryption
CBC_Mode<Twofish>::Decryption
CTR_Mode<Twofish>::Encryption
CTR_Mode<Twofish>::Decryption
CFB_Mode<Twofish>::Encryption
CFB_Mode<Twofish>::Decryption
OFB_Mode<Twofish>::Encryption
OFB_Mode<Twofish>::Decryption
EAX<Twofish>::Encryption
EAX<Twofish>::Decryption
```

## Methods

### SetKey()

```cpp
void SetKey(const byte* key, size_t length);
```

Set the encryption/decryption key.

**Parameters:**
- `key` - Key bytes (16, 24, or 32 bytes)
- `length` - Key length in bytes

### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLen,
                  const byte* iv, size_t ivLen = BLOCKSIZE);
```

Set key and initialization vector (for modes).

### ProcessBlock()

```cpp
void ProcessBlock(const byte* inBlock, byte* outBlock) const;
void ProcessBlock(byte* inoutBlock) const;  // In-place
```

Encrypt or decrypt a single 16-byte block (raw cipher, no mode).

## Complete Examples

### Example 1: Twofish-CBC with HMAC (Authenticated)

```cpp
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <iostream>

using namespace CryptoPP;

struct EncryptedData {
    byte iv[Twofish::BLOCKSIZE];
    std::string ciphertext;
    byte mac[SHA256::DIGESTSIZE];
};

EncryptedData encryptAuthenticated(const std::string& plaintext,
                                    const SecByteBlock& encKey,
                                    const SecByteBlock& macKey) {
    AutoSeededRandomPool rng;
    EncryptedData result;

    // Generate random IV
    rng.GenerateBlock(result.iv, sizeof(result.iv));

    // Encrypt
    CBC_Mode<Twofish>::Encryption enc;
    enc.SetKeyWithIV(encKey, encKey.size(), result.iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(result.ciphertext)
        )
    );

    // Compute HMAC over IV || ciphertext (Encrypt-then-MAC)
    HMAC<SHA256> hmac(macKey, macKey.size());
    hmac.Update(result.iv, sizeof(result.iv));
    hmac.Update((const byte*)result.ciphertext.data(),
                result.ciphertext.size());
    hmac.Final(result.mac);

    return result;
}

std::string decryptAuthenticated(const EncryptedData& data,
                                  const SecByteBlock& encKey,
                                  const SecByteBlock& macKey) {
    // Verify MAC first (before decryption!)
    HMAC<SHA256> hmac(macKey, macKey.size());
    hmac.Update(data.iv, sizeof(data.iv));
    hmac.Update((const byte*)data.ciphertext.data(),
                data.ciphertext.size());

    byte computedMac[SHA256::DIGESTSIZE];
    hmac.Final(computedMac);

    if (!VerifyBufsEqual(data.mac, computedMac, SHA256::DIGESTSIZE)) {
        throw std::runtime_error("Authentication failed");
    }

    // Decrypt
    CBC_Mode<Twofish>::Decryption dec;
    dec.SetKeyWithIV(encKey, encKey.size(), data.iv);

    std::string plaintext;
    StringSource(data.ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(plaintext)
        )
    );

    return plaintext;
}

int main() {
    AutoSeededRandomPool rng;

    // Separate keys for encryption and MAC
    SecByteBlock encKey(Twofish::MAX_KEYLENGTH);  // 256-bit
    SecByteBlock macKey(32);
    rng.GenerateBlock(encKey, encKey.size());
    rng.GenerateBlock(macKey, macKey.size());

    std::string message = "Secret Twofish message";

    EncryptedData encrypted = encryptAuthenticated(message, encKey, macKey);
    std::string decrypted = decryptAuthenticated(encrypted, encKey, macKey);

    std::cout << "Original:  " << message << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```

### Example 2: Twofish-CTR Mode

```cpp
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    SecByteBlock key(Twofish::MAX_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[Twofish::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "CTR mode allows random access";
    std::string ciphertext, recovered;

    // CTR mode - no padding needed
    CTR_Mode<Twofish>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Ciphertext same length as plaintext (no padding)
    std::cout << "Plaintext size:  " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

    // Decrypt
    CTR_Mode<Twofish>::Decryption dec;
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

### Example 3: Twofish-EAX (Authenticated Encryption)

```cpp
#include <cryptopp/twofish.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    SecByteBlock key(Twofish::MAX_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[Twofish::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Authenticated with EAX mode";
    std::string header = "Additional authenticated data";
    std::string ciphertext, recovered;

    // EAX mode provides authenticated encryption
    EAX<Twofish>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    // Process AAD
    enc.SpecifyDataLengths(header.size(), plaintext.size());

    AuthenticatedEncryptionFilter ef(enc,
        new StringSink(ciphertext)
    );

    ef.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::cout << "Ciphertext + tag size: " << ciphertext.size() << std::endl;

    // Decrypt and verify
    EAX<Twofish>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    dec.SpecifyDataLengths(header.size(), ciphertext.size() - Twofish::BLOCKSIZE);

    AuthenticatedDecryptionFilter df(dec,
        new StringSink(recovered)
    );

    df.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    df.ChannelMessageEnd(AAD_CHANNEL);
    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::cout << "Recovered: " << recovered << std::endl;

    return 0;
}
```

### Example 4: Raw Block Cipher

```cpp
#include <cryptopp/twofish.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate 256-bit key
    SecByteBlock key(Twofish::MAX_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    // Single block (16 bytes)
    byte plainBlock[Twofish::BLOCKSIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    byte cipherBlock[Twofish::BLOCKSIZE];
    byte decryptedBlock[Twofish::BLOCKSIZE];

    // Raw encryption (single block, no mode)
    Twofish::Encryption enc;
    enc.SetKey(key, key.size());
    enc.ProcessBlock(plainBlock, cipherBlock);

    // Raw decryption
    Twofish::Decryption dec;
    dec.SetKey(key, key.size());
    dec.ProcessBlock(cipherBlock, decryptedBlock);

    // Display
    std::string hexPlain, hexCipher, hexDecrypted;
    StringSource(plainBlock, sizeof(plainBlock), true,
        new HexEncoder(new StringSink(hexPlain)));
    StringSource(cipherBlock, sizeof(cipherBlock), true,
        new HexEncoder(new StringSink(hexCipher)));
    StringSource(decryptedBlock, sizeof(decryptedBlock), true,
        new HexEncoder(new StringSink(hexDecrypted)));

    std::cout << "Plain:     " << hexPlain << std::endl;
    std::cout << "Cipher:    " << hexCipher << std::endl;
    std::cout << "Decrypted: " << hexDecrypted << std::endl;

    return 0;
}
```

### Example 5: Layered Encryption (AES + Twofish)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

// Defense-in-depth: encrypt with Twofish, then AES
std::string doubleEncrypt(const std::string& plaintext,
                          const SecByteBlock& aesKey,
                          const SecByteBlock& twofishKey,
                          byte* aesIV, byte* twofishIV) {
    std::string inner, outer;

    // First layer: Twofish
    CTR_Mode<Twofish>::Encryption twofishEnc;
    twofishEnc.SetKeyWithIV(twofishKey, twofishKey.size(), twofishIV);
    StringSource(plaintext, true,
        new StreamTransformationFilter(twofishEnc,
            new StringSink(inner)
        )
    );

    // Second layer: AES
    CTR_Mode<AES>::Encryption aesEnc;
    aesEnc.SetKeyWithIV(aesKey, aesKey.size(), aesIV);
    StringSource(inner, true,
        new StreamTransformationFilter(aesEnc,
            new StringSink(outer)
        )
    );

    return outer;
}

std::string doubleDecrypt(const std::string& ciphertext,
                          const SecByteBlock& aesKey,
                          const SecByteBlock& twofishKey,
                          const byte* aesIV, const byte* twofishIV) {
    std::string inner, plaintext;

    // First: remove AES layer
    CTR_Mode<AES>::Decryption aesDec;
    aesDec.SetKeyWithIV(aesKey, aesKey.size(), aesIV);
    StringSource(ciphertext, true,
        new StreamTransformationFilter(aesDec,
            new StringSink(inner)
        )
    );

    // Second: remove Twofish layer
    CTR_Mode<Twofish>::Decryption twofishDec;
    twofishDec.SetKeyWithIV(twofishKey, twofishKey.size(), twofishIV);
    StringSource(inner, true,
        new StreamTransformationFilter(twofishDec,
            new StringSink(plaintext)
        )
    );

    return plaintext;
}

int main() {
    AutoSeededRandomPool rng;

    SecByteBlock aesKey(AES::MAX_KEYLENGTH);
    SecByteBlock twofishKey(Twofish::MAX_KEYLENGTH);
    rng.GenerateBlock(aesKey, aesKey.size());
    rng.GenerateBlock(twofishKey, twofishKey.size());

    byte aesIV[AES::BLOCKSIZE], twofishIV[Twofish::BLOCKSIZE];
    rng.GenerateBlock(aesIV, sizeof(aesIV));
    rng.GenerateBlock(twofishIV, sizeof(twofishIV));

    std::string message = "Double-encrypted message";
    std::string encrypted = doubleEncrypt(message, aesKey, twofishKey, aesIV, twofishIV);
    std::string decrypted = doubleDecrypt(encrypted, aesKey, twofishKey, aesIV, twofishIV);

    std::cout << "Original:  " << message << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```

## Twofish vs AES

| Property | Twofish | AES (Rijndael) |
|----------|---------|----------------|
| Block size | 128 bits | 128 bits |
| Key sizes | 128, 192, 256 bits | 128, 192, 256 bits |
| Rounds | 16 | 10, 12, 14 |
| Hardware accel | No | Yes (AES-NI) |
| Speed (software) | Medium | Medium |
| Speed (with AES-NI) | Medium | Very fast |
| Cryptanalysis | No practical attacks | No practical attacks |
| Standard | AES finalist | NIST standard |

## Performance

### Benchmarks (Approximate)

| Mode | Software | With AES-NI (AES comparison) |
|------|----------|------------------------------|
| Twofish-CBC | ~150-250 MB/s | N/A |
| Twofish-CTR | ~150-250 MB/s | N/A |
| AES-CBC | ~150-250 MB/s | ~2-4 GB/s |
| AES-CTR | ~150-250 MB/s | ~3-5 GB/s |

**Note:** Twofish performance is comparable to AES in software, but AES with hardware acceleration is 10-20x faster.

## Security

### Security Properties

| Property | Value |
|----------|-------|
| **Block size** | 128 bits |
| **Key sizes** | 128, 192, 256 bits |
| **Rounds** | 16 (fixed) |
| **Best known attack** | None practical |
| **Security margin** | Full |

### Design Features

- **Feistel network** - 16 rounds
- **Key-dependent S-boxes** - derived from key material
- **MDS matrix** - maximum distance separable for diffusion
- **PHT (Pseudo-Hadamard Transform)** - additional mixing
- **Whitening** - XOR with key material before/after rounds

### Known Cryptanalysis

| Attack | Rounds | Complexity | Status |
|--------|--------|------------|--------|
| Impossible differential | 6 | 2^256 | Academic |
| Truncated differential | 5 | 2^128 | Academic |
| Full cipher | 16 | None | Secure |

No practical attacks exist against full Twofish.

## When to Use Twofish

### Use Twofish for:

1. **AES Alternative** - When you want cipher diversity
2. **Defense-in-Depth** - Layered encryption with different algorithms
3. **No AES-NI Available** - Software performance is competitive
4. **Personal Preference** - When you prefer Schneier's design

### Don't use Twofish for:

1. **Performance Critical** - AES with AES-NI is much faster
2. **Compliance Requirements** - Many standards specify AES
3. **Hardware Acceleration** - Twofish has no hardware support
4. **Interoperability** - AES is more widely implemented

## Key Schedule

Twofish uses a complex key schedule:

```
Key Schedule Features:
- Key-dependent S-boxes (derived from first half of key)
- Subkey generation uses MDS matrix
- 40 words of expanded key material
- Two halves of key used differently
```

This makes Twofish slower to set up than AES, but provides additional security margin.

## Test Vector

```cpp
#include <cryptopp/twofish.h>
#include <cassert>
#include <cstring>

// Test vector from Twofish specification
// Key: 0x00000000...00000000 (256-bit zero key)
// Plaintext: 0x00000000...00000000 (128-bit zero block)
// Ciphertext: 0x57FF739D4DC92C1BD7FC01700CC8216F

void testTwofish() {
    using namespace CryptoPP;

    byte key[32] = {0};
    byte plaintext[16] = {0};
    byte ciphertext[16];
    byte expected[16] = {
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };

    Twofish::Encryption enc;
    enc.SetKey(key, sizeof(key));
    enc.ProcessBlock(plaintext, ciphertext);

    assert(std::memcmp(ciphertext, expected, 16) == 0);
}
```

## Exceptions

- `InvalidKeyLength` - Key not 16, 24, or 32 bytes
- `InvalidCiphertext` - Padding error during decryption (CBC mode)

## Thread Safety

Twofish objects are **not thread-safe**. Use separate instances per thread:

```cpp
// WRONG - shared instance
Twofish::Encryption sharedEnc;

// CORRECT - per-thread instances
void encryptInThread(const std::string& data, const SecByteBlock& key) {
    AutoSeededRandomPool rng;
    byte iv[Twofish::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<Twofish>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    // ... encrypt ...
}
```

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Standard authenticated encryption
- [AES-CBC](/docs/api/symmetric/aes-cbc/) - AES in CBC mode
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Modern stream cipher AEAD
- [HMAC](/docs/api/mac/hmac/) - For Encrypt-then-MAC with Twofish
- [Security Concepts](/docs/guides/security-concepts/) - Block cipher modes
