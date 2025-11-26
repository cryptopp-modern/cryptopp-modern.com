---
title: HexEncoder
description: Hexadecimal encoding and decoding API reference
weight: 3
---

**Header:** `#include <cryptopp/hex.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

HexEncoder and HexDecoder convert binary data to/from hexadecimal (base-16) string representation. Commonly used for displaying hash digests, keys, and binary data in human-readable format.

## Quick Example

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Encode binary to hex
    byte data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    std::string hexOutput;

    StringSource(data, sizeof(data), true,
        new HexEncoder(
            new StringSink(hexOutput)
        )
    );

    std::cout << "Hex: " << hexOutput << std::endl;
    // Output: DEADBEEFCAFE

    // Decode hex to binary
    std::string decoded;
    StringSource(hexOutput, true,
        new HexDecoder(
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
- Use HexEncoder to display hash digests, keys, and binary data
- Use uppercase for cryptographic values (default)
- Use lowercase for URLs and filenames
- Use for debugging and logging binary data

**Avoid:**
- Using hex encoding for data transmission (Base64 is more efficient)
- Manually converting bytes to hex strings (use HexEncoder)
- Case-sensitive hex comparisons (hex is case-insensitive)
{{< /callout >}}

## Class: HexEncoder

Convert binary data to hexadecimal string.

### Constructors

#### Default Constructor

```cpp
HexEncoder(BufferedTransformation* attachment = nullptr,
           bool uppercase = true,
           int groupSize = 0,
           const std::string& separator = ":",
           const std::string& terminator = "");
```

Create hexadecimal encoder.

**Parameters:**
- `attachment` - Output sink (can be NULL)
- `uppercase` - Use uppercase (true) or lowercase (false)
- `groupSize` - Number of encoded chars per group (0 = no grouping)
- `separator` - String between groups
- `terminator` - String appended at end

**Example:**

```cpp
// Uppercase (default)
HexEncoder encoder(new StringSink(output));

// Lowercase
HexEncoder encoder(new StringSink(output), false);

// Grouped with colons (MAC address format)
HexEncoder encoder(new StringSink(output), true, 2, ":");
// Output: DE:AD:BE:EF:CA:FE

// Grouped with spaces (common hash display)
HexEncoder encoder(new StringSink(output), true, 2, " ");
// Output: DE AD BE EF CA FE
```

## Class: HexDecoder

Convert hexadecimal string to binary data.

### Constructors

#### Default Constructor

```cpp
HexDecoder(BufferedTransformation* attachment = nullptr);
```

Create hexadecimal decoder.

**Example:**

```cpp
std::string decoded;
HexDecoder decoder(new StringSink(decoded));
```

## Complete Example: Hash Display

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

std::string hashToHex(const std::string& message) {
    SHA256 hash;
    std::string digest, hexDigest;

    // Compute hash
    StringSource(message, true,
        new HashFilter(hash,
            new StringSink(digest)
        )
    );

    // Convert to hex
    StringSource(digest, true,
        new HexEncoder(
            new StringSink(hexDigest)
        )
    );

    return hexDigest;
}

int main() {
    std::string message = "Hello, World!";
    std::string hex = hashToHex(message);

    std::cout << "SHA-256: " << hex << std::endl;
    // Output: DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F

    return 0;
}
```

## Complete Example: Key Storage and Loading

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <iostream>

using namespace CryptoPP;

void saveKey(const SecByteBlock& key, const std::string& filename) {
    std::string hexKey;

    // Encode key to hex
    StringSource(key, key.size(), true,
        new HexEncoder(
            new StringSink(hexKey)
        )
    );

    // Save to file
    std::ofstream file(filename);
    file << hexKey;

    std::cout << "Key saved: " << filename << std::endl;
    std::cout << "Key: " << hexKey << std::endl;
}

SecByteBlock loadKey(const std::string& filename) {
    // Read hex key from file
    std::ifstream file(filename);
    std::string hexKey;
    file >> hexKey;

    // Decode hex to binary
    std::string binaryKey;
    StringSource(hexKey, true,
        new HexDecoder(
            new StringSink(binaryKey)
        )
    );

    // Convert to SecByteBlock
    SecByteBlock key((const byte*)binaryKey.data(), binaryKey.size());

    std::cout << "Key loaded: " << filename << std::endl;
    std::cout << "Key size: " << key.size() << " bytes" << std::endl;

    return key;
}

int main() {
    AutoSeededRandomPool rng;

    // Generate AES key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    // Save key as hex
    saveKey(key, "aes_key.txt");

    // Load key from hex
    SecByteBlock loadedKey = loadKey("aes_key.txt");

    // Verify keys match
    bool match = std::memcmp(key.data(), loadedKey.data(), key.size()) == 0;
    std::cout << "Keys match: " << (match ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Complete Example: Hex Dump Utility

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;

void hexDump(const std::string& filename) {
    std::string fileData;

    // Read file
    FileSource(filename.c_str(), true,
        new StringSink(fileData)
    );

    std::cout << "File: " << filename << std::endl;
    std::cout << "Size: " << fileData.size() << " bytes" << std::endl;
    std::cout << std::endl;

    // Display as hex (grouped by 16 bytes)
    const size_t bytesPerLine = 16;
    for (size_t i = 0; i < fileData.size(); i += bytesPerLine) {
        size_t lineSize = std::min(bytesPerLine, fileData.size() - i);

        // Offset
        printf("%08zx  ", i);

        // Hex bytes
        std::string hexLine;
        StringSource((const byte*)fileData.data() + i, lineSize, true,
            new HexEncoder(
                new StringSink(hexLine),
                false,  // lowercase
                2,      // group by 2
                " "     // space separator
            )
        );
        std::cout << hexLine;

        // Padding for incomplete lines
        for (size_t j = lineSize; j < bytesPerLine; j++) {
            std::cout << "   ";
        }

        // ASCII representation
        std::cout << "  |";
        for (size_t j = 0; j < lineSize; j++) {
            char c = fileData[i + j];
            std::cout << (isprint(c) ? c : '.');
        }
        std::cout << "|" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    try {
        hexDump(argv[1]);
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Formatting Options

### Uppercase vs Lowercase

```cpp
// Uppercase (default, cryptographic convention)
HexEncoder encoder(new StringSink(output), true);
// Output: DEADBEEF

// Lowercase (URLs, filenames)
HexEncoder encoder(new StringSink(output), false);
// Output: deadbeef
```

### Grouping and Separators

```cpp
byte data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
std::string output;

// No grouping (default)
HexEncoder enc1(new StringSink(output));
// Output: DEADBEEFCAFE

// MAC address format (2 chars, colon separator)
HexEncoder enc2(new StringSink(output), true, 2, ":");
// Output: DE:AD:BE:EF:CA:FE

// Space-separated bytes
HexEncoder enc3(new StringSink(output), true, 2, " ");
// Output: DE AD BE EF CA FE

// Grouped by 4 (word display)
HexEncoder enc4(new StringSink(output), true, 4, " ");
// Output: DEAD BEEF CAFE

// With terminator
HexEncoder enc5(new StringSink(output), true, 2, ":", "\n");
// Output: DE:AD:BE:EF:CA:FE\n
```

## Decoding Flexibility

HexDecoder is flexible with input:

```cpp
std::string decoded;

// All these decode to the same binary data:

// Uppercase
StringSource("DEADBEEF", true, new HexDecoder(new StringSink(decoded)));

// Lowercase
StringSource("deadbeef", true, new HexDecoder(new StringSink(decoded)));

// Mixed case
StringSource("DeAdBeEf", true, new HexDecoder(new StringSink(decoded)));

// With separators (ignored)
StringSource("DE:AD:BE:EF", true, new HexDecoder(new StringSink(decoded)));
StringSource("DE AD BE EF", true, new HexDecoder(new StringSink(decoded)));

// With whitespace (ignored)
StringSource("DE\nAD\tBE EF", true, new HexDecoder(new StringSink(decoded)));
```

## Performance

### Encoding Speed

| Operation | Speed (MB/s) | Notes |
|-----------|--------------|-------|
| Hex encode | 300-600 | 2x data expansion |
| Hex decode | 200-400 | Slower than encode |
| Base64 encode | 400-800 | More efficient |

**Hex doubles data size (1 byte → 2 hex chars).**

### Size Overhead

```cpp
// Binary: 16 bytes (128-bit AES key)
SecByteBlock key(16);

// Hex: 32 characters (2x size)
std::string hexKey;  // "0123456789ABCDEF..." (32 chars)

// Base64: 24 characters (1.33x size)
std::string base64Key;  // "ABCD...==" (~24 chars)
```

## Use Cases

### ✅ Good Uses for Hex Encoding:

1. **Hash Display:**
   ```cpp
   // SHA-256 output: 64 hex chars
   std::cout << "SHA-256: " << hexDigest << std::endl;
   ```

2. **Key Storage (Config Files):**
   ```cpp
   // aes_key = DEADBEEFCAFE0123...
   ```

3. **Debugging Binary Data:**
   ```cpp
   std::cout << "Ciphertext: " << hexCiphertext << std::endl;
   ```

4. **MAC Addresses, UUIDs:**
   ```cpp
   // DE:AD:BE:EF:CA:FE
   // 550e8400-e29b-41d4-a716-446655440000
   ```

### ❌ Poor Uses for Hex Encoding:

1. **Data Transmission** - Use Base64 instead (25% smaller)
2. **URLs** - Use Base64URL (URL-safe)
3. **Large Binary Data** - Use binary format

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## Common Patterns

### Pattern 1: Hash to Hex

```cpp
std::string hashToHex(const std::string& data) {
    SHA256 hash;
    std::string digest, hexDigest;

    StringSource(data, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(hexDigest)
            )
        )
    );

    return hexDigest;
}
```

### Pattern 2: Hex to Binary

```cpp
std::string hexToBytes(const std::string& hex) {
    std::string bytes;
    StringSource(hex, true,
        new HexDecoder(
            new StringSink(bytes)
        )
    );
    return bytes;
}
```

### Pattern 3: Secure Key Display (Partial)

```cpp
std::string displayKey(const SecByteBlock& key) {
    std::string hexKey;
    StringSource(key, key.size(), true,
        new HexEncoder(new StringSink(hexKey))
    );

    // Show only first 8 chars
    return hexKey.substr(0, 8) + "..." +
           hexKey.substr(hexKey.size() - 8);
    // Output: DEADBEEF...CAFE0123
}
```

## Exceptions

- `InvalidDataFormat` - Invalid hex characters in decoder input (non-hex chars)

## See Also

- [Base64Encoder](/docs/api/utilities/base64encoder/) - More efficient encoding
- [SHA-256](/docs/api/hash/sha256/) - Hash functions that output binary
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure key storage
