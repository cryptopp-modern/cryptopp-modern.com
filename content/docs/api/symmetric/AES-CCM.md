---
title: AES-CCM
description: AES-CCM authenticated encryption API reference
weight: 6
---

**Header:** `#include <cryptopp/aes.h>` and `#include <cryptopp/ccm.h>`
**Namespace:** `CryptoPP` **Since:** Crypto++ 5.6.0

AES-CCM (AES in Counter with CBC-MAC Mode) is an authenticated encryption algorithm that provides both confidentiality and authenticity. CCM is widely used in wireless protocols such as Wi-Fi (WPA2 and WPA3 CCMP-128), Bluetooth and Zigbee (via AES-CCM/CCM*), and is also supported as an AEAD mode in TLS 1.2 and 1.3 cipher suites.

## Quick Example

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Generate random key and nonce
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 16 bytes
    byte nonce[12];  // CCM nonce: 7-13 bytes (12 common)
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(nonce, sizeof(nonce));

    std::string plaintext = "Hello, World!";
    std::string ciphertext, decrypted;

    const int TAG_SIZE = 16;  // Authentication tag size

    // Encrypt
    CCM<AES, TAG_SIZE>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));
    enc.SpecifyDataLengths(0, plaintext.size());  // CCM requires lengths upfront

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    CCM<AES, TAG_SIZE>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));
    dec.SpecifyDataLengths(0, ciphertext.size() - TAG_SIZE);

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
- Use CCM when protocol compatibility requires it (WiFi, Bluetooth, TLS)
- Always specify data lengths before encryption/decryption
- Use unique nonces for each encryption with the same key
- Use 128-bit or 256-bit keys for new systems

**Avoid:**
- Using CCM for streaming data (it requires knowing lengths upfront)
- Reusing nonces with the same key
- Using CCM when GCM would work (GCM is faster and more flexible)
- Ignoring authentication failures during decryption
{{< /callout >}}

## Key Difference: CCM Requires Pre-specified Lengths

Unlike GCM and EAX, **CCM requires you to know the plaintext and AAD lengths before encryption begins**. This is because CCM's authentication tag calculation depends on these lengths.

```cpp
// REQUIRED for CCM - must call before processing data
enc.SpecifyDataLengths(aadLength, plaintextLength);
```

If you don't know the data length upfront, use [AES-GCM](/docs/api/symmetric/aes-gcm/) or [AES-EAX](/docs/api/symmetric/aes-eax/) instead.

## Class: CCM\<AES, TAG_SIZE\>

Template class for AES in CCM authenticated encryption mode.

### Template Parameters

```cpp
template <class T_BlockCipher, int T_DefaultDigestSize = 16>
struct CCM {
    typedef CCM_Final<T_BlockCipher, T_DefaultDigestSize, true> Encryption;
    typedef CCM_Final<T_BlockCipher, T_DefaultDigestSize, false> Decryption;
};
```

- `T_BlockCipher` - The underlying block cipher (must have 16-byte block size, e.g., `AES`)
- `T_DefaultDigestSize` - Authentication tag size in bytes (4, 6, 8, 10, 12, 14, or 16)

### Key Sizes

| Key Size | Security | Constant | Recommended |
|----------|----------|----------|-------------|
| 128-bit | 128-bit | `AES::DEFAULT_KEYLENGTH` (16) | Acceptable |
| 192-bit | 192-bit | 24 bytes | Rare |
| 256-bit | 256-bit | `AES::MAX_KEYLENGTH` (32) | ✓ Recommended |

### Constants

```cpp
// AES constants
static const int MIN_KEYLENGTH = 16;     // 128 bits
static const int MAX_KEYLENGTH = 32;     // 256 bits
static const int DEFAULT_KEYLENGTH = 16; // 128 bits
static const int BLOCKSIZE = 16;         // Required by CCM

// CCM-specific
static const int REQUIRED_BLOCKSIZE = 16;
// Nonce (IV) size: 7-13 bytes
// Tag sizes: 4, 6, 8, 10, 12, 14, or 16 bytes
```

### Valid Tag Sizes

CCM only supports specific tag sizes:

| Tag Size | Security | Use Case |
|----------|----------|----------|
| 4 bytes | 32-bit | Constrained environments only |
| 6 bytes | 48-bit | Low-security applications |
| 8 bytes | 64-bit | Resource-constrained |
| 10 bytes | 80-bit | Legacy compatibility |
| 12 bytes | 96-bit | Good balance |
| 14 bytes | 112-bit | High security |
| **16 bytes** | **128-bit** | **✓ Recommended** |

## CCM\<AES\>::Encryption

Authenticated encryption class.

### Methods

#### SetKeyWithIV()

```cpp
void SetKeyWithIV(const byte* key, size_t keyLength,
                  const byte* iv, size_t ivLength);
```

Set encryption key and nonce.

**Parameters:**
- `key` - Encryption key (16, 24, or 32 bytes)
- `keyLength` - Length of key in bytes
- `iv` - Nonce (7-13 bytes)
- `ivLength` - Length of nonce in bytes

**Nonce size constraints:**
- Minimum: 7 bytes
- Maximum: 13 bytes
- Common: 12 bytes (allows messages up to 2^24 bytes)

The nonce size determines the maximum message length:
| Nonce Size | Max Message Length |
|------------|-------------------|
| 7 bytes | 2^64 - 1 bytes |
| 8 bytes | 2^56 - 1 bytes |
| ... | ... |
| 12 bytes | 2^24 - 1 bytes (~16 MB) |
| 13 bytes | 2^16 - 1 bytes (~64 KB) |

#### SpecifyDataLengths() - REQUIRED

```cpp
void SpecifyDataLengths(lword headerLength, lword messageLength,
                        lword footerLength = 0);
```

**Must be called before processing any data.** Specifies the lengths of AAD and plaintext.

**Parameters:**
- `headerLength` - Length of AAD in bytes (0 if none)
- `messageLength` - Length of plaintext in bytes
- `footerLength` - Footer length (usually 0)

**Example:**

```cpp
CCM<AES>::Encryption enc;
enc.SetKeyWithIV(key, sizeof(key), nonce, sizeof(nonce));

// REQUIRED: specify lengths before encryption
enc.SpecifyDataLengths(0, plaintext.size());

// Now proceed with encryption
```

#### IVSize() / MinIVLength() / MaxIVLength()

```cpp
unsigned int IVSize() const;       // Default: 8 bytes
unsigned int MinIVLength() const;  // Returns 7
unsigned int MaxIVLength() const;  // Returns 13
```

#### DigestSize()

```cpp
unsigned int DigestSize() const;
```

Returns the authentication tag size (template parameter, default 16).

## CCM\<AES\>::Decryption

Authenticated decryption class.

### Methods

#### SetKeyWithIV()

Same as encryption.

#### SpecifyDataLengths() - REQUIRED

```cpp
void SpecifyDataLengths(lword headerLength, lword messageLength,
                        lword footerLength = 0);
```

**Must be called before processing any data.** For decryption, `messageLength` is the plaintext length (ciphertext length minus tag size).

```cpp
CCM<AES, 16>::Decryption dec;
dec.SetKeyWithIV(key, sizeof(key), nonce, sizeof(nonce));

// messageLength = ciphertext.size() - TAG_SIZE
dec.SpecifyDataLengths(aadLength, ciphertext.size() - 16);
```

## Complete Example: WiFi-Style Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <vector>

using namespace CryptoPP;

class WirelessEncryptor {
public:
    static const int TAG_SIZE = 8;  // WiFi uses 8-byte tags
    static const int NONCE_SIZE = 13;

    WirelessEncryptor(const SecByteBlock& key) : key_(key) {
        if (key.size() != 16 && key.size() != 32) {
            throw std::invalid_argument("Key must be 16 or 32 bytes");
        }
    }

    // Encrypt a packet with header (AAD) and payload
    std::vector<byte> encryptPacket(const std::vector<byte>& header,
                                     const std::vector<byte>& payload,
                                     uint64_t packetNumber) {
        // Create nonce from packet number
        byte nonce[NONCE_SIZE] = {0};
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_SIZE - 1 - i] = (packetNumber >> (i * 8)) & 0xFF;
        }

        CCM<AES, TAG_SIZE>::Encryption enc;
        enc.SetKeyWithIV(key_, key_.size(), nonce, sizeof(nonce));
        enc.SpecifyDataLengths(header.size(), payload.size());

        std::string ciphertext;

        AuthenticatedEncryptionFilter aef(enc,
            new StringSink(ciphertext)
        );

        // Process AAD (header)
        if (!header.empty()) {
            aef.ChannelPut(AAD_CHANNEL, header.data(), header.size());
            aef.ChannelMessageEnd(AAD_CHANNEL);
        }

        // Process payload
        aef.ChannelPut(DEFAULT_CHANNEL, payload.data(), payload.size());
        aef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // Return: header + encrypted_payload + tag
        std::vector<byte> result;
        result.insert(result.end(), header.begin(), header.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        return result;
    }

    std::vector<byte> decryptPacket(const std::vector<byte>& packet,
                                     size_t headerSize,
                                     uint64_t packetNumber) {
        if (packet.size() < headerSize + TAG_SIZE) {
            throw std::runtime_error("Packet too short");
        }

        // Extract header and ciphertext
        std::vector<byte> header(packet.begin(), packet.begin() + headerSize);
        std::vector<byte> ciphertext(packet.begin() + headerSize, packet.end());

        // Reconstruct nonce
        byte nonce[NONCE_SIZE] = {0};
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_SIZE - 1 - i] = (packetNumber >> (i * 8)) & 0xFF;
        }

        size_t payloadSize = ciphertext.size() - TAG_SIZE;

        CCM<AES, TAG_SIZE>::Decryption dec;
        dec.SetKeyWithIV(key_, key_.size(), nonce, sizeof(nonce));
        dec.SpecifyDataLengths(header.size(), payloadSize);

        std::string plaintext;

        AuthenticatedDecryptionFilter adf(dec,
            new StringSink(plaintext)
        );

        // Process AAD
        if (!header.empty()) {
            adf.ChannelPut(AAD_CHANNEL, header.data(), header.size());
            adf.ChannelMessageEnd(AAD_CHANNEL);
        }

        // Process ciphertext
        adf.ChannelPut(DEFAULT_CHANNEL, ciphertext.data(), ciphertext.size());
        adf.ChannelMessageEnd(DEFAULT_CHANNEL);

        return std::vector<byte>(plaintext.begin(), plaintext.end());
    }

private:
    SecByteBlock key_;
};

int main() {
    try {
        // Generate key
        AutoSeededRandomPool rng;
        SecByteBlock key(16);  // AES-128
        rng.GenerateBlock(key, key.size());

        WirelessEncryptor encryptor(key);

        // Simulate packet
        std::vector<byte> header = {0x08, 0x00, 0x00, 0x00};  // Packet header
        std::string message = "Hello, wireless world!";
        std::vector<byte> payload(message.begin(), message.end());

        uint64_t packetNum = 12345;

        // Encrypt
        auto encrypted = encryptor.encryptPacket(header, payload, packetNum);
        std::cout << "Encrypted packet: " << encrypted.size() << " bytes" << std::endl;

        // Decrypt
        auto decrypted = encryptor.decryptPacket(encrypted, header.size(), packetNum);
        std::string result(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted: " << result << std::endl;

    } catch (const HashVerificationFilter::HashVerificationFailed& e) {
        std::cerr << "Authentication failed!" << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Additional Authenticated Data (AAD)

CCM supports authenticating header data without encrypting it:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>

void encryptWithAAD() {
    using namespace CryptoPP;

    SecByteBlock key(32);
    byte nonce[12];
    // ... initialize ...

    std::string header = "packet-header";
    std::string plaintext = "secret-payload";
    std::string ciphertext;

    CCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, sizeof(nonce));

    // CRITICAL: specify lengths BEFORE processing
    enc.SpecifyDataLengths(header.size(), plaintext.size());

    AuthenticatedEncryptionFilter aef(enc,
        new StringSink(ciphertext)
    );

    // Process AAD first
    aef.ChannelPut(AAD_CHANNEL, (const byte*)header.data(), header.size());
    aef.ChannelMessageEnd(AAD_CHANNEL);

    // Then plaintext
    aef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    aef.ChannelMessageEnd(DEFAULT_CHANNEL);
}
```

## Performance

CCM is a two-pass mode, making it slower than GCM:

| Mode | Passes | Parallelizable | Relative Speed |
|------|--------|----------------|----------------|
| GCM | 1 | Yes | Fastest |
| CCM | 2 | Limited (MAC serial) | ~50% of GCM |
| EAX | 2 | Partial | ~50% of GCM |

**Approximate throughput (AES-128, modern x86 with AES-NI):**

| Mode | Encryption | Decryption |
|------|------------|------------|
| GCM | 3000 MB/s | 3000 MB/s |
| CCM | 1500 MB/s | 1500 MB/s |

## Security

### Quick Summary

| Property | Value |
|----------|-------|
| **Confidentiality** | 128/192/256-bit (AES key size) |
| **Authenticity** | Up to 128-bit (tag size dependent) |
| **Nonce requirement** | Must be unique per key |
| **Nonce size** | 7-13 bytes |
| **Standard** | NIST SP 800-38C, RFC 3610 |

### Security Bounds

| Tag Size | Forgery Probability |
|----------|-------------------|
| 4 bytes | 2^-32 per attempt |
| 8 bytes | 2^-64 per attempt |
| 16 bytes | 2^-128 per attempt |

### Nonce Management

CCM uses the nonce to create a counter for CTR mode encryption. The nonce must be:
- **Unique** for each message under the same key
- **7-13 bytes** in length
- **Not secret** (can be transmitted with ciphertext)

```cpp
// Counter-based nonce (recommended for protocols)
byte nonce[12];
uint64_t counter = getNextCounter();
memset(nonce, 0, sizeof(nonce));
memcpy(nonce + 4, &counter, 8);  // 64-bit counter

// Random nonce (use with care - birthday bound)
AutoSeededRandomPool rng;
rng.GenerateBlock(nonce, sizeof(nonce));
```

## Thread Safety

**Not thread-safe.** Create separate objects per thread.

## Exceptions

- `InvalidKeyLength` - Key size is not 16, 24, or 32 bytes
- `InvalidArgument` - Nonce size not in 7-13 byte range
- `InvalidArgument` - Data lengths not specified before processing
- `HashVerificationFilter::HashVerificationFailed` - Authentication failed

## CCM vs Other Modes

| Feature | CCM | GCM | EAX |
|---------|-----|-----|-----|
| **Speed** | Moderate | Fast | Moderate |
| **Online** | No | Yes | Yes |
| **Nonce size** | 7-13 bytes | Any (12 optimal) | Any |
| **Parallelizable** | Limited (MAC serial) | Yes | Partial |
| **Use cases** | Wi-Fi, Bluetooth, TLS | General purpose | General purpose |

## Protocol Usage

CCM is mandated or commonly used in:

| Protocol | Key Size | Nonce Size | Tag Size |
|----------|----------|------------|----------|
| Wi-Fi WPA2/WPA3 (CCMP-128) | 128-bit | 13 bytes | 8 bytes |
| Bluetooth LE | 128-bit | 13 bytes | 4 bytes |
| Zigbee (AES-CCM* variant) | 128-bit | 13 bytes | 4/8/16 bytes |
| TLS 1.2/1.3 | 128/256-bit | 12 bytes | 16 bytes |

**Note:** WPA3-Enterprise also defines GCMP-256 (AES-GCM with 16-byte tag), which is not CCM.

## Algorithm Details

- **Construction**: CTR mode encryption + CBC-MAC authentication
- **Block cipher**: Must have 128-bit block size (AES)
- **Key sizes**: 128, 192, or 256 bits
- **Nonce size**: 7-13 bytes (affects max message length)
- **Tag sizes**: 4, 6, 8, 10, 12, 14, or 16 bytes
- **Standard**: NIST SP 800-38C, RFC 3610

## See Also

- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Faster, more flexible AEAD
- [AES-EAX](/docs/api/symmetric/aes-eax/) - Alternative two-pass mode
- [ChaCha20-Poly1305](/docs/api/symmetric/chacha20-poly1305/) - Non-AES alternative
- [Symmetric Encryption Guide](/docs/algorithms/symmetric/) - Conceptual overview
