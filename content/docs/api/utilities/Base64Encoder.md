---
title: Base64Encoder
description: Base64 encoding and decoding API reference
weight: 4
---

**Header:** `#include <cryptopp/base64.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

Base64Encoder and Base64Decoder convert binary data to/from Base64 string representation. Base64 is the standard encoding for transmitting binary data over text-based protocols (email, JSON, XML, URLs) with only 33% size overhead compared to 100% for hex encoding.

## Quick Example

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Encode binary to Base64
    byte data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    std::string encoded;

    StringSource(data, sizeof(data), true,
        new Base64Encoder(
            new StringSink(encoded),
            false  // no line breaks
        )
    );

    std::cout << "Base64: " << encoded << std::endl;
    // Output: 3q2+78r+

    // Decode Base64 to binary
    std::string decoded;
    StringSource(encoded, true,
        new Base64Decoder(
            new StringSink(decoded)
        )
    );

    std::cout << "Decoded " << decoded.size() << " bytes" << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use Base64 for transmitting binary data over text protocols
- Use for email attachments, JSON/XML data embedding
- Use Base64URL variant for URLs and filenames
- Disable line breaks for JSON/URLs (insertLineBreaks = false)

**Avoid:**
- Using Base64 for cryptographic key display (use hex instead)
- Using standard Base64 in URLs (use Base64URL instead)
- Base64 for large file storage (use binary format)
{{< /callout >}}

## Class: Base64Encoder

Convert binary data to Base64 string.

### Constructors

#### Default Constructor

```cpp
Base64Encoder(BufferedTransformation* attachment = nullptr,
              bool insertLineBreaks = true,
              int maxLineLength = 72);
```

Create Base64 encoder.

**Parameters:**
- `attachment` - Output sink (can be NULL)
- `insertLineBreaks` - Insert line breaks for readability
- `maxLineLength` - Maximum line length (default: 72, RFC 2045)

**Example:**

```cpp
// With line breaks (email format, RFC 2045)
Base64Encoder encoder(new StringSink(output), true, 72);

// Without line breaks (JSON, URLs)
Base64Encoder encoder(new StringSink(output), false);

// Custom line length
Base64Encoder encoder(new StringSink(output), true, 64);
```

## Class: Base64Decoder

Convert Base64 string to binary data.

### Constructors

#### Default Constructor

```cpp
Base64Decoder(BufferedTransformation* attachment = nullptr);
```

Create Base64 decoder.

**Example:**

```cpp
std::string decoded;
Base64Decoder decoder(new StringSink(decoded));
```

## Class: Base64URLEncoder

Base64 encoding with URL-safe alphabet (RFC 4648).

### Constructors

```cpp
Base64URLEncoder(BufferedTransformation* attachment = nullptr,
                 bool insertLineBreaks = false);
```

**URL-Safe Alphabet:**
- `+` replaced with `-`
- `/` replaced with `_`
- Padding (`=`) optional

**Example:**

```cpp
std::string urlSafe;
Base64URLEncoder encoder(new StringSink(urlSafe), false);
// Output: 3q2-78r_  (URL-safe characters)
```

## Class: Base64URLDecoder

Decode Base64URL strings.

```cpp
Base64URLDecoder(BufferedTransformation* attachment = nullptr);
```

## Complete Example: Binary Data in JSON

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <sstream>

using namespace CryptoPP;

std::string toJSON(const std::string& name,
                   const SecByteBlock& data) {
    // Encode binary data to Base64 (no line breaks for JSON)
    std::string encoded;
    StringSource(data, data.size(), true,
        new Base64Encoder(
            new StringSink(encoded),
            false  // no line breaks
        )
    );

    // Build JSON
    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << name << "\",\n";
    json << "  \"data\": \"" << encoded << "\",\n";
    json << "  \"size\": " << data.size() << "\n";
    json << "}";

    return json.str();
}

SecByteBlock fromJSON(const std::string& base64Data) {
    // Decode Base64 from JSON
    std::string decoded;
    StringSource(base64Data, true,
        new Base64Decoder(
            new StringSink(decoded)
        )
    );

    return SecByteBlock((const byte*)decoded.data(), decoded.size());
}

int main() {
    AutoSeededRandomPool rng;

    // Generate random key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Encode to JSON
    std::string json = toJSON("encryption_key", key);
    std::cout << "JSON:\n" << json << std::endl;

    // In real JSON, extract the base64 string
    // For demo, we'll just re-encode
    std::string encoded;
    StringSource(key, key.size(), true,
        new Base64Encoder(new StringSink(encoded), false)
    );

    // Decode from JSON
    SecByteBlock recovered = fromJSON(encoded);

    std::cout << "\nOriginal size: " << key.size() << " bytes" << std::endl;
    std::cout << "Recovered size: " << recovered.size() << " bytes" << std::endl;

    bool match = std::memcmp(key.data(), recovered.data(), key.size()) == 0;
    std::cout << "Match: " << (match ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Complete Example: Email Attachment Encoding

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;

void encodeForEmail(const std::string& filename,
                    const std::string& outputFile) {
    // Read binary file and encode to Base64 with line breaks
    FileSource(filename.c_str(), true,
        new Base64Encoder(
            new FileSink(outputFile.c_str()),
            true,  // insert line breaks
            76     // max line length (RFC 2045)
        )
    );

    std::cout << "Encoded " << filename << " -> " << outputFile << std::endl;
    std::cout << "Format: MIME Base64 (RFC 2045)" << std::endl;
}

void decodeFromEmail(const std::string& encodedFile,
                     const std::string& outputFile) {
    // Decode Base64 (line breaks handled automatically)
    FileSource(encodedFile.c_str(), true,
        new Base64Decoder(
            new FileSink(outputFile.c_str())
        )
    );

    std::cout << "Decoded " << encodedFile << " -> " << outputFile << std::endl;
}

int main() {
    // Encode image for email
    encodeForEmail("photo.jpg", "photo.jpg.b64");

    // Decode back to binary
    decodeFromEmail("photo.jpg.b64", "photo_recovered.jpg");

    return 0;
}
```

## Complete Example: URL-Safe Token Generation

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

std::string generateToken(size_t bytes = 32) {
    AutoSeededRandomPool rng;

    // Generate random token
    SecByteBlock token(bytes);
    rng.GenerateBlock(token, token.size());

    // Encode to URL-safe Base64
    std::string encoded;
    StringSource(token, token.size(), true,
        new Base64URLEncoder(
            new StringSink(encoded),
            false  // no line breaks
        )
    );

    // Remove padding (optional for URLs)
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }

    return encoded;
}

int main() {
    // Generate authentication token
    std::string token = generateToken(32);
    std::cout << "Token: " << token << std::endl;
    std::cout << "Length: " << token.size() << " chars" << std::endl;
    std::cout << "URL-safe: YES (no +, /, or =)" << std::endl;

    // Use in URL
    std::cout << "\nExample URL:" << std::endl;
    std::cout << "https://example.com/api/reset?token=" << token << std::endl;

    return 0;
}
```

## Line Break Handling

### With Line Breaks (Email, PEM format)

```cpp
std::string output;
Base64Encoder encoder(new StringSink(output), true, 64);

// Output:
// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
// ...
```

### Without Line Breaks (JSON, XML, URLs)

```cpp
std::string output;
Base64Encoder encoder(new StringSink(output), false);

// Output: AAAAAAAAAA...BBBBBBBBB (single line)
```

## Performance

### Encoding Speed

| Operation | Speed (MB/s) | Size Overhead |
|-----------|--------------|---------------|
| Base64 encode | 400-800 | +33% |
| Base64 decode | 300-600 | -25% |
| Hex encode | 300-600 | +100% |
| Hex decode | 200-400 | -50% |

**Base64 is 25% more efficient than hex encoding.**

### Size Comparison

```cpp
// Binary: 24 bytes
byte data[24] = {...};

// Hex: 48 characters (2x size)
std::string hex;        // "DEADBEEF..." (48 chars)

// Base64: 32 characters (1.33x size)
std::string base64;     // "3q2+78r+..." (32 chars)

// Base64 is 33% smaller than hex
```

## Standard Base64 vs Base64URL

### Standard Base64 (RFC 2045)

**Alphabet:** `A-Z`, `a-z`, `0-9`, `+`, `/`, `=` (padding)

**Use cases:**
- Email (MIME)
- PEM files
- XML/JSON data

```cpp
Base64Encoder encoder(new StringSink(output), false);
// Output: 3q2+78r+  (uses + and /)
```

### Base64URL (RFC 4648)

**Alphabet:** `A-Z`, `a-z`, `0-9`, `-`, `_`, `=` (optional padding)

**Use cases:**
- URLs
- Filenames
- JWT tokens
- No escaping needed

```cpp
Base64URLEncoder encoder(new StringSink(output), false);
// Output: 3q2-78r_  (URL-safe: - and _)
```

**Comparison:**

| Character | Standard | URL-Safe |
|-----------|----------|----------|
| 62nd char | `+` | `-` |
| 63rd char | `/` | `_` |
| Padding | Required `=` | Optional |

## Padding Behaviour

Base64 uses `=` for padding to align output to 4-character boundaries:

```cpp
// 1 byte: AA==
// 2 bytes: AAA=
// 3 bytes: AAAA (no padding)
// 4 bytes: AAAAAA==
// 5 bytes: AAAAAAA=
// 6 bytes: AAAAAAAA (no padding)
```

**Remove padding for URLs:**

```cpp
std::string encoded;
Base64URLEncoder encoder(new StringSink(encoded), false);
// ... encode ...

// Remove padding
while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
}
```

## Decoder Flexibility

Base64Decoder handles:
- Line breaks (CRLF, LF, CR)
- Whitespace (spaces, tabs)
- Missing padding
- Both standard and URL-safe alphabets

```cpp
std::string decoded;

// All these decode successfully:

// Standard
StringSource("3q2+78r+", true, new Base64Decoder(new StringSink(decoded)));

// URL-safe
StringSource("3q2-78r_", true, new Base64Decoder(new StringSink(decoded)));

// With line breaks
StringSource("3q2+\n78r+", true, new Base64Decoder(new StringSink(decoded)));

// With padding
StringSource("3q2+78r+==", true, new Base64Decoder(new StringSink(decoded)));

// Without padding
StringSource("3q2+78r+", true, new Base64Decoder(new StringSink(decoded)));
```

## Use Cases

### ✅ Good Uses for Base64:

1. **Email Attachments** (MIME)
   ```cpp
   Base64Encoder encoder(new FileSink("attachment.b64"), true, 76);
   ```

2. **JSON/XML Binary Data**
   ```cpp
   Base64Encoder encoder(new StringSink(json), false);
   ```

3. **URL Tokens** (use Base64URL)
   ```cpp
   Base64URLEncoder encoder(new StringSink(token), false);
   ```

4. **PEM Files** (keys, certificates)
   ```cpp
   // -----BEGIN PUBLIC KEY-----
   // Base64 encoded data...
   // -----END PUBLIC KEY-----
   ```

5. **Data URLs**
   ```html
   <img src="data:image/png;base64,iVBORw0KG..." />
   ```

### ❌ Poor Uses for Base64:

1. **Large File Storage** - Use binary format
2. **Cryptographic Hashes Display** - Use hex (standard convention)
3. **Database Binary Columns** - Use binary type (BLOB)

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## Common Patterns

### Pattern 1: Binary to Base64

```cpp
std::string binaryToBase64(const byte* data, size_t size) {
    std::string encoded;
    StringSource(data, size, true,
        new Base64Encoder(
            new StringSink(encoded),
            false  // no line breaks
        )
    );
    return encoded;
}
```

### Pattern 2: Base64 to Binary

```cpp
std::string base64ToBinary(const std::string& base64) {
    std::string decoded;
    StringSource(base64, true,
        new Base64Decoder(
            new StringSink(decoded)
        )
    );
    return decoded;
}
```

### Pattern 3: URL-Safe Token

```cpp
std::string createURLSafeToken(const SecByteBlock& data) {
    std::string encoded;
    StringSource(data, data.size(), true,
        new Base64URLEncoder(
            new StringSink(encoded),
            false
        )
    );

    // Remove padding for URLs
    encoded.erase(std::find(encoded.begin(), encoded.end(), '='),
                  encoded.end());

    return encoded;
}
```

## Exceptions

- `InvalidDataFormat` - Invalid Base64 characters in decoder input

## See Also

- [HexEncoder](/docs/api/utilities/hexencoder/) - Alternative encoding (less efficient)
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Binary data container
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Generate random data for tokens
