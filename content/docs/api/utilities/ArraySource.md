---
title: ArraySource / ArraySink
description: Byte array data sources and sinks for pipeline operations
weight: 7
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

ArraySource and ArraySink provide direct byte array I/O for the Crypto++ pipeline system. They offer zero-copy semantics for working with raw byte buffers, making them ideal for performance-critical code and interfacing with C-style APIs.

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

// Hash a byte array directly into another byte array
byte input[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
byte digest[SHA256::DIGESTSIZE];

ArraySource(input, sizeof(input), true,
    new HashFilter(SHA256(),
        new ArraySink(digest, sizeof(digest))
    )
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use `ArraySource`/`ArraySink` for fixed-size buffers
- Pre-allocate output arrays to exact required size
- Use for interfacing with C APIs and hardware
- Prefer when avoiding `std::string` overhead
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use undersized output buffers (undefined behavior)
- Don't use for variable-length output (use StringSink instead)
- Don't forget to check actual bytes written
{{< /callout >}}

## ArraySource

### Constructor

```cpp
ArraySource(const byte* array, size_t length, bool pumpAll,
            BufferedTransformation* attachment = nullptr);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `array` | `const byte*` | Pointer to input byte array |
| `length` | `size_t` | Number of bytes to process |
| `pumpAll` | `bool` | If `true`, process all data immediately |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |

## ArraySink

### Constructor

```cpp
ArraySink(byte* array, size_t size);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `array` | `byte*` | Pointer to output byte array |
| `size` | `size_t` | Maximum bytes the array can hold |

### Methods

```cpp
// Get number of bytes actually written
size_t TotalPutLength() const;

// Get remaining space in array
size_t AvailableSize() const;
```

## Complete Examples

### Example 1: Hash to Fixed Buffer

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <iomanip>

int main() {
    using namespace CryptoPP;

    // Input data
    const byte message[] = "The quick brown fox jumps over the lazy dog";

    // Output buffer - exact size for SHA-256
    byte digest[SHA256::DIGESTSIZE];

    // Compute hash directly into array
    ArraySource(message, sizeof(message) - 1, true,  // -1 to exclude null terminator
        new HashFilter(SHA256(),
            new ArraySink(digest, sizeof(digest))
        )
    );

    // Display result
    std::cout << "SHA-256: ";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(digest[i]);
    }
    std::cout << std::endl;

    return 0;
}
```

### Example 2: Encryption with Fixed Buffers

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cstring>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Key and IV
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[12];
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    // Plaintext
    const byte plaintext[] = "Secret message!";
    const size_t plaintextLen = sizeof(plaintext) - 1;

    // Ciphertext buffer (plaintext + tag)
    byte ciphertext[256];
    size_t ciphertextLen = 0;

    // Encrypt
    {
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

        ArraySink sink(ciphertext, sizeof(ciphertext));

        ArraySource(plaintext, plaintextLen, true,
            new AuthenticatedEncryptionFilter(enc,
                new Redirector(sink)
            )
        );

        ciphertextLen = sink.TotalPutLength();
    }

    // Decrypt
    byte recovered[256];
    size_t recoveredLen = 0;

    {
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

        ArraySink sink(recovered, sizeof(recovered));

        ArraySource(ciphertext, ciphertextLen, true,
            new AuthenticatedDecryptionFilter(dec,
                new Redirector(sink)
            )
        );

        recoveredLen = sink.TotalPutLength();
    }

    // Null-terminate for display
    recovered[recoveredLen] = '\0';
    std::cout << "Recovered: " << recovered << std::endl;

    return 0;
}
```

### Example 3: HMAC with Fixed Buffers

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>

void computeHMAC(const byte* key, size_t keyLen,
                 const byte* message, size_t messageLen,
                 byte* mac, size_t macLen) {
    using namespace CryptoPP;

    HMAC<SHA256> hmac(key, keyLen);

    ArraySource(message, messageLen, true,
        new HashFilter(hmac,
            new ArraySink(mac, macLen)
        )
    );
}

bool verifyHMAC(const byte* key, size_t keyLen,
                const byte* message, size_t messageLen,
                const byte* expectedMac, size_t macLen) {
    using namespace CryptoPP;

    byte computedMac[SHA256::DIGESTSIZE];
    computeHMAC(key, keyLen, message, messageLen, computedMac, sizeof(computedMac));

    // Constant-time comparison
    return CryptoPP::VerifyBufsEqual(computedMac, expectedMac, macLen);
}
```

### Example 4: Working with SecByteBlock

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

SecByteBlock hashData(const byte* data, size_t length) {
    using namespace CryptoPP;

    SecByteBlock digest(SHA256::DIGESTSIZE);

    ArraySource(data, length, true,
        new HashFilter(SHA256(),
            new ArraySink(digest.data(), digest.size())
        )
    );

    return digest;
}

// Usage
SecByteBlock key(32);
rng.GenerateBlock(key, key.size());

SecByteBlock keyHash = hashData(key.data(), key.size());
```

### Example 5: Hex Encoding to Buffer

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

void toHex(const byte* input, size_t inputLen,
           char* output, size_t outputLen) {
    using namespace CryptoPP;

    // Hex encoding doubles the size
    if (outputLen < inputLen * 2) {
        throw std::runtime_error("Output buffer too small");
    }

    ArraySource(input, inputLen, true,
        new HexEncoder(
            new ArraySink(reinterpret_cast<byte*>(output), outputLen)
        )
    );
}

void fromHex(const char* input, size_t inputLen,
             byte* output, size_t outputLen) {
    using namespace CryptoPP;

    ArraySource(reinterpret_cast<const byte*>(input), inputLen, true,
        new HexDecoder(
            new ArraySink(output, outputLen)
        )
    );
}
```

## Checking Output Size

Always verify the actual bytes written:

```cpp
byte output[100];
ArraySink sink(output, sizeof(output));

ArraySource(input, inputLen, true,
    new SomeFilter(new Redirector(sink))
);

size_t actualBytes = sink.TotalPutLength();
std::cout << "Wrote " << actualBytes << " bytes" << std::endl;
```

## Buffer Size Requirements

| Operation | Output Size |
|-----------|-------------|
| SHA-256 hash | 32 bytes (fixed) |
| SHA-512 hash | 64 bytes (fixed) |
| HMAC-SHA256 | 32 bytes (fixed) |
| AES-GCM encrypt | plaintext + 16 bytes (tag) |
| Hex encode | input × 2 |
| Base64 encode | ⌈input × 4/3⌉ + padding |

### Safe Buffer Allocation

```cpp
// For hashing - use DIGESTSIZE constant
byte hash[SHA256::DIGESTSIZE];

// For AEAD encryption - add tag size
size_t ciphertextSize = plaintextSize + AES::BLOCKSIZE;  // GCM tag is 16 bytes
std::vector<byte> ciphertext(ciphertextSize);

// For hex encoding
size_t hexSize = binarySize * 2;
std::vector<byte> hex(hexSize);
```

## Using Redirector

When you need to track output size, use `Redirector`:

```cpp
byte output[256];
ArraySink sink(output, sizeof(output));

ArraySource(input, inputLen, true,
    new HashFilter(SHA256(),
        new Redirector(sink)  // Redirector passes data to sink
    )
);

size_t written = sink.TotalPutLength();
```

Without `Redirector`, filters take ownership and delete the sink:

```cpp
// WRONG - sink deleted after ArraySource completes
ArraySource(input, inputLen, true,
    new HashFilter(SHA256(), new ArraySink(output, size))
);
// sink is already deleted here!

// CORRECT - use Redirector to maintain access to sink
ArraySink sink(output, size);
ArraySource(input, inputLen, true,
    new HashFilter(SHA256(), new Redirector(sink))
);
size_t written = sink.TotalPutLength();  // sink still valid
```

## Performance Benefits

ArraySource/ArraySink offer performance advantages:

1. **Zero-copy:** Data isn't copied between buffers
2. **No allocation:** Output goes directly to your buffer
3. **Stack-friendly:** Works with stack-allocated arrays
4. **Cache-friendly:** Predictable memory access patterns

```cpp
// Zero heap allocations
void processData(const byte* in, size_t inLen, byte* out, size_t outLen) {
    ArraySink sink(out, outLen);
    ArraySource(in, inLen, true,
        new HashFilter(SHA256(), new Redirector(sink))
    );
}
```

## Interfacing with C APIs

ArraySource/ArraySink are ideal for C interoperability:

```cpp
extern "C" {
    int compute_sha256(const unsigned char* data, size_t data_len,
                       unsigned char* hash, size_t hash_len) {
        using namespace CryptoPP;

        if (hash_len < SHA256::DIGESTSIZE) {
            return -1;  // Buffer too small
        }

        try {
            ArraySource(data, data_len, true,
                new HashFilter(SHA256(),
                    new ArraySink(hash, hash_len)
                )
            );
            return SHA256::DIGESTSIZE;
        } catch (...) {
            return -2;  // Error
        }
    }
}
```

## Common Patterns

### Hash with Known Output Size

```cpp
template<typename Hash>
void computeHash(const byte* input, size_t inputLen,
                 byte* output) {
    using namespace CryptoPP;

    ArraySource(input, inputLen, true,
        new HashFilter(Hash(),
            new ArraySink(output, Hash::DIGESTSIZE)
        )
    );
}

// Usage
byte sha256[SHA256::DIGESTSIZE];
computeHash<SHA256>(data, dataLen, sha256);

byte sha512[SHA512::DIGESTSIZE];
computeHash<SHA512>(data, dataLen, sha512);
```

### In-place Processing (where supported)

```cpp
// Some operations support in-place processing
// Check documentation for specific filters

byte buffer[256];
// Fill buffer with data...

// NOT generally safe - input and output must not overlap
// ArraySource(buffer, len, true, new SomeFilter(new ArraySink(buffer, len)));
```

## Error Handling

```cpp
void safeArrayOperation(const byte* input, size_t inputLen,
                        byte* output, size_t outputLen) {
    using namespace CryptoPP;

    try {
        ArraySink sink(output, outputLen);

        ArraySource(input, inputLen, true,
            new HashFilter(SHA256(), new Redirector(sink))
        );

        if (sink.TotalPutLength() > outputLen) {
            // Should never happen with HashFilter, but good practice
            throw std::runtime_error("Output buffer overflow");
        }

    } catch (const Exception& e) {
        throw std::runtime_error(std::string("Crypto error: ") + e.what());
    }
}
```

## ArraySink Overflow Behavior

If the output exceeds the buffer size:

```cpp
byte smallBuffer[10];
ArraySink sink(smallBuffer, sizeof(smallBuffer));

// If filter produces more than 10 bytes:
// - Only first 10 bytes are written
// - Remaining bytes are silently discarded
// - TotalPutLength() still reports total bytes that WOULD have been written
```

To detect overflow:

```cpp
byte buffer[10];
ArraySink sink(buffer, sizeof(buffer));

// ... process data ...

if (sink.TotalPutLength() > sizeof(buffer)) {
    throw std::runtime_error("Output truncated - buffer too small");
}
```

## Thread Safety

ArraySource and ArraySink are **not thread-safe**:

```cpp
// WRONG - shared buffer access
byte sharedBuffer[256];

void thread1() {
    ArraySink sink(sharedBuffer, sizeof(sharedBuffer));  // Race!
}

// CORRECT - thread-local buffers
void processInThread(const byte* input, size_t len) {
    byte localBuffer[256];  // Stack-allocated, thread-safe
    ArraySource(input, len, true,
        new HashFilter(SHA256(),
            new ArraySink(localBuffer, sizeof(localBuffer))
        )
    );
}
```

## See Also

- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String-based I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File-based I/O
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure memory allocation
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation filter
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Encryption filter
