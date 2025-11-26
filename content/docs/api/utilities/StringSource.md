---
title: StringSource / StringSink
description: String-based data sources and sinks for pipeline operations
weight: 5
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

StringSource and StringSink are the most commonly used data adapters in Crypto++. They connect `std::string` and byte arrays to the filter pipeline system, enabling fluent cryptographic operations.

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

// Hash a string and get hex output
std::string message = "Hello, World!";
std::string hexDigest;

StringSource(message, true,
    new HashFilter(SHA256(),
        new HexEncoder(new StringSink(hexDigest))
    )
);

// hexDigest = "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F"
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use `StringSource` for in-memory data processing
- Pass `true` as second parameter for one-shot processing
- Chain filters using `new` (ownership is transferred)
- Use `StringSink` to collect output into `std::string`
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't reuse StringSource objects (create new ones)
- Don't delete filters manually (ownership transfers to pipeline)
- Don't use for very large data (use FileSource instead)
{{< /callout >}}

## StringSource

### Constructors

```cpp
// From std::string
StringSource(const std::string& string, bool pumpAll,
             BufferedTransformation* attachment = nullptr);

// From byte array
StringSource(const byte* string, size_t length, bool pumpAll,
             BufferedTransformation* attachment = nullptr);

// From C-string
StringSource(const char* string, bool pumpAll,
             BufferedTransformation* attachment = nullptr);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `string` | Various | Input data (string, byte array, or C-string) |
| `length` | `size_t` | Length of byte array (only for byte* overload) |
| `pumpAll` | `bool` | If `true`, process all data immediately |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline (takes ownership) |

### The `pumpAll` Parameter

```cpp
// pumpAll = true: Process everything immediately (most common)
StringSource(data, true, new HexEncoder(new StringSink(output)));

// pumpAll = false: Manual pumping (advanced usage)
StringSource ss(data, false, new HexEncoder(new StringSink(output)));
ss.PumpAll();  // Process all data
// OR
ss.Pump(100);  // Process 100 bytes at a time
```

## StringSink

### Constructor

```cpp
StringSink(std::string& output);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `output` | `std::string&` | Reference to string that receives output |

### Important Notes

- StringSink **appends** to the output string (doesn't clear it first)
- Clear the output string before use if needed
- The string reference must remain valid during pipeline operation

```cpp
std::string output;
output = "prefix: ";  // Will be preserved

StringSource(data, true,
    new HexEncoder(new StringSink(output))
);
// output = "prefix: DEADBEEF..."

// To replace instead of append:
output.clear();
StringSource(data, true, new HexEncoder(new StringSink(output)));
```

## Pipeline Architecture

Crypto++ uses a pipeline (or "filter") architecture where data flows through connected transformations:

```
Source → Filter → Filter → ... → Sink
```

```cpp
StringSource(input, true,           // Source: provides data
    new HashFilter(SHA256(),        // Filter: transforms data
        new HexEncoder(             // Filter: transforms data
            new StringSink(output)  // Sink: collects result
        )
    )
);
```

### Ownership Model

When you use `new` in the pipeline, ownership transfers automatically:

```cpp
// CORRECT - ownership transfers, automatic cleanup
StringSource(data, true,
    new HexEncoder(new StringSink(output))  // new is correct here
);

// WRONG - don't manage filter lifetime manually
HexEncoder* encoder = new HexEncoder(new StringSink(output));
StringSource(data, true, encoder);
delete encoder;  // WRONG! Double-free will occur
```

## Complete Examples

### Example 1: Hashing

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string message = "The quick brown fox jumps over the lazy dog";
    std::string digest, hexDigest;

    // Get raw hash bytes
    SHA256 hash;
    StringSource(message, true,
        new HashFilter(hash, new StringSink(digest))
    );

    // Convert to hex for display
    StringSource(digest, true,
        new HexEncoder(new StringSink(hexDigest))
    );

    std::cout << "SHA-256: " << hexDigest << std::endl;
    // SHA-256: D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592

    return 0;
}
```

### Example 2: Encryption with AES-GCM

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(12);  // 96-bit IV for GCM
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, iv.size());

    std::string plaintext = "Secret message to encrypt";
    std::string ciphertext, recovered;

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(recovered)
        )
    );

    std::cout << "Original:  " << plaintext << std::endl;
    std::cout << "Recovered: " << recovered << std::endl;

    return 0;
}
```

### Example 3: Base64 Encoding/Decoding

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string plaintext = "Hello, World!";
    std::string encoded, decoded;

    // Encode to Base64
    StringSource(plaintext, true,
        new Base64Encoder(new StringSink(encoded), false)  // false = no newlines
    );

    std::cout << "Base64: " << encoded << std::endl;
    // Base64: SGVsbG8sIFdvcmxkIQ==

    // Decode from Base64
    StringSource(encoded, true,
        new Base64Decoder(new StringSink(decoded))
    );

    std::cout << "Decoded: " << decoded << std::endl;
    // Decoded: Hello, World!

    return 0;
}
```

### Example 4: HMAC Authentication

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate HMAC key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    std::string message = "Message to authenticate";
    std::string mac, hexMac;

    // Compute HMAC
    HMAC<SHA256> hmac(key, key.size());
    StringSource(message, true,
        new HashFilter(hmac, new StringSink(mac))
    );

    // Display as hex
    StringSource(mac, true,
        new HexEncoder(new StringSink(hexMac))
    );

    std::cout << "HMAC-SHA256: " << hexMac << std::endl;

    return 0;
}
```

### Example 5: Multiple Operations in Sequence

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <vector>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::vector<std::string> messages = {
        "First message",
        "Second message",
        "Third message"
    };

    SHA256 hash;

    for (const auto& msg : messages) {
        std::string digest;

        StringSource(msg, true,
            new HashFilter(hash,
                new HexEncoder(new StringSink(digest))
            )
        );

        std::cout << "Hash of \"" << msg << "\": " << digest << std::endl;
    }

    return 0;
}
```

## Working with Binary Data

### From byte array

```cpp
byte data[] = {0xDE, 0xAD, 0xBE, 0xEF};
std::string hexOutput;

StringSource(data, sizeof(data), true,
    new HexEncoder(new StringSink(hexOutput))
);
// hexOutput = "DEADBEEF"
```

### From SecByteBlock

```cpp
SecByteBlock key(32);
rng.GenerateBlock(key, key.size());

std::string hexKey;
StringSource(key.data(), key.size(), true,
    new HexEncoder(new StringSink(hexKey))
);
```

### To byte array (via StringSink + copy)

```cpp
std::string decoded;
StringSource(hexInput, true,
    new HexDecoder(new StringSink(decoded))
);

// Copy to byte array
std::vector<byte> bytes(decoded.begin(), decoded.end());

// Or to SecByteBlock
SecByteBlock key((const byte*)decoded.data(), decoded.size());
```

## ArraySink Alternative

For direct output to byte arrays, use `ArraySink`:

```cpp
byte output[32];
ArraySink sink(output, sizeof(output));

StringSource(input, true,
    new HashFilter(SHA256(), new Redirector(sink))
);
```

## Performance Considerations

### String Pre-allocation

```cpp
std::string output;
output.reserve(expectedSize);  // Reduce reallocations

StringSource(input, true,
    new SomeFilter(new StringSink(output))
);
```

### Large Data

For large data, consider `FileSource`/`FileSink` or process in chunks:

```cpp
// For very large strings, process incrementally
StringSource ss(largeData, false, new HexEncoder(new StringSink(output)));

while (ss.Pump(64 * 1024)) {  // 64KB chunks
    // Optional: show progress
}
ss.PumpAll();  // Finish remaining
```

## Common Patterns

### Hash and Encode in One Pipeline

```cpp
std::string hexHash;
StringSource(message, true,
    new HashFilter(SHA256(),
        new HexEncoder(new StringSink(hexHash))
    )
);
```

### Decode and Decrypt in One Pipeline

```cpp
std::string plaintext;
StringSource(base64Ciphertext, true,
    new Base64Decoder(
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(plaintext)
        )
    )
);
```

### Redirect to Multiple Outputs

```cpp
std::string output1, output2;

StringSource(data, true,
    new Tee(
        new HexEncoder(new StringSink(output1)),
        new Base64Encoder(new StringSink(output2))
    )
);
// Both output1 (hex) and output2 (base64) are populated
```

## Error Handling

```cpp
try {
    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(plaintext)
        )
    );
} catch (const HashVerificationFilter::HashVerificationFailed& e) {
    // Authentication failed - data was tampered with
    std::cerr << "Decryption failed: data integrity check failed" << std::endl;
} catch (const Exception& e) {
    std::cerr << "Crypto++ error: " << e.what() << std::endl;
}
```

## Thread Safety

StringSource and StringSink are **not thread-safe**. Create separate instances per thread:

```cpp
// WRONG - shared across threads
std::string output;
// Multiple threads writing to same StringSink

// CORRECT - per-thread instances
void processInThread(const std::string& input) {
    std::string output;  // Thread-local
    StringSource(input, true,
        new HexEncoder(new StringSink(output))
    );
}
```

## See Also

- [FileSource / FileSink](/docs/api/utilities/filesource/) - File-based I/O
- [ArraySource / ArraySink](/docs/api/utilities/arraysource/) - Byte array I/O
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation filter
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Encryption/decryption filter
- [HexEncoder](/docs/api/utilities/hexencoder/) - Hex encoding
- [Base64Encoder](/docs/api/utilities/base64encoder/) - Base64 encoding
