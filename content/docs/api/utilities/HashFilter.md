---
title: HashFilter
description: Pipeline filter for computing cryptographic hashes
weight: 8
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

HashFilter is a pipeline filter that computes cryptographic hashes (and HMACs) as data flows through. It wraps any `HashTransformation` object (SHA-256, BLAKE3, HMAC, etc.) and outputs the resulting digest.

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

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
- Use HashFilter in pipelines for clean, streaming hash computation
- Pass hash objects by value (they're copied internally)
- Chain with HexEncoder for human-readable output
- Works with any HashTransformation (SHA, BLAKE, HMAC, etc.)
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't reuse HashFilter instances (create new ones per operation)
- Don't forget HashFilter produces binary output by default
- Don't use HashFilter for password hashing (use Argon2 instead)
{{< /callout >}}

## Constructor

```cpp
HashFilter(HashTransformation& hash,
           BufferedTransformation* attachment = nullptr,
           bool putMessage = false,
           int truncatedDigestSize = -1,
           const std::string& messagePutChannel = DEFAULT_CHANNEL,
           const std::string& hashPutChannel = DEFAULT_CHANNEL);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | `HashTransformation&` | Hash algorithm to use (SHA256, BLAKE3, HMAC, etc.) |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |
| `putMessage` | `bool` | If `true`, output original message before hash (default: `false`) |
| `truncatedDigestSize` | `int` | Custom output size, or `-1` for full digest |
| `messagePutChannel` | `std::string` | Channel for message output (advanced) |
| `hashPutChannel` | `std::string` | Channel for hash output (advanced) |

## Supported Hash Types

HashFilter works with any class derived from `HashTransformation`:

| Type | Examples |
|------|----------|
| **Hash Functions** | `SHA256`, `SHA512`, `SHA3_256`, `BLAKE3`, `BLAKE2b` |
| **HMAC** | `HMAC<SHA256>`, `HMAC<BLAKE3>` |
| **Other MACs** | `CMAC<AES>`, `Poly1305` |

## Complete Examples

### Example 1: Basic SHA-256 Hash

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string message = "The quick brown fox jumps over the lazy dog";
    std::string digest, hexDigest;

    // Get raw binary hash
    StringSource(message, true,
        new HashFilter(SHA256(), new StringSink(digest))
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

### Example 2: Combined Hash and Hex in One Pipeline

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

std::string sha256Hex(const std::string& input) {
    using namespace CryptoPP;

    std::string hexDigest;

    StringSource(input, true,
        new HashFilter(SHA256(),
            new HexEncoder(new StringSink(hexDigest))
        )
    );

    return hexDigest;
}
```

### Example 3: HMAC Authentication

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

std::string computeHMAC(const std::string& message,
                        const SecByteBlock& key) {
    using namespace CryptoPP;

    HMAC<SHA256> hmac(key, key.size());
    std::string mac;

    StringSource(message, true,
        new HashFilter(hmac,
            new HexEncoder(new StringSink(mac))
        )
    );

    return mac;
}

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    std::string message = "Message to authenticate";
    std::string mac = computeHMAC(message, key);

    std::cout << "HMAC-SHA256: " << mac << std::endl;

    return 0;
}
```

### Example 4: Hash a File

```cpp
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

std::string hashFile(const std::string& filename) {
    using namespace CryptoPP;

    SHA256 hash;
    std::string hexDigest;

    FileSource(filename, true,
        new HashFilter(hash,
            new HexEncoder(new StringSink(hexDigest))
        )
    );

    return hexDigest;
}
```

### Example 5: Multiple Hash Algorithms

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <iostream>

void computeAllHashes(const std::string& input) {
    using namespace CryptoPP;

    std::string sha256, sha512, sha3, blake2;

    StringSource(input, true,
        new HashFilter(SHA256(), new HexEncoder(new StringSink(sha256)))
    );

    StringSource(input, true,
        new HashFilter(SHA512(), new HexEncoder(new StringSink(sha512)))
    );

    StringSource(input, true,
        new HashFilter(SHA3_256(), new HexEncoder(new StringSink(sha3)))
    );

    StringSource(input, true,
        new HashFilter(BLAKE2b(), new HexEncoder(new StringSink(blake2)))
    );

    std::cout << "SHA-256:  " << sha256 << std::endl;
    std::cout << "SHA-512:  " << sha512 << std::endl;
    std::cout << "SHA3-256: " << sha3 << std::endl;
    std::cout << "BLAKE2b:  " << blake2 << std::endl;
}
```

### Example 6: Truncated Hash Output

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

std::string truncatedHash(const std::string& input, int bytes) {
    using namespace CryptoPP;

    std::string hexDigest;

    // Output only first 'bytes' of hash
    StringSource(input, true,
        new HashFilter(SHA256(),
            new HexEncoder(new StringSink(hexDigest)),
            false,   // putMessage
            bytes    // truncatedDigestSize
        )
    );

    return hexDigest;
}

// Usage: Get 16-byte (128-bit) truncated hash
std::string shortHash = truncatedHash("Hello", 16);
// Returns first 32 hex characters (16 bytes)
```

### Example 7: Output Message with Hash

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

void messageWithHash(const std::string& input) {
    using namespace CryptoPP;

    std::string output;

    // putMessage = true: output contains message + hash
    StringSource(input, true,
        new HashFilter(SHA256(),
            new StringSink(output),
            true  // putMessage: include original message
        )
    );

    // output now contains: original message + 32-byte SHA-256 hash
    std::cout << "Total length: " << output.length() << std::endl;
    std::cout << "Message length: " << input.length() << std::endl;
    std::cout << "Hash length: " << SHA256::DIGESTSIZE << std::endl;
}
```

### Example 8: Hash to Fixed Array

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

void hashToArray(const byte* input, size_t inputLen,
                 byte* output, size_t outputLen) {
    using namespace CryptoPP;

    if (outputLen < SHA256::DIGESTSIZE) {
        throw std::runtime_error("Output buffer too small");
    }

    ArraySource(input, inputLen, true,
        new HashFilter(SHA256(),
            new ArraySink(output, outputLen)
        )
    );
}
```

## Using with Different Hash Algorithms

### SHA Family

```cpp
// SHA-256 (most common)
new HashFilter(SHA256(), attachment)

// SHA-512 (larger output, faster on 64-bit)
new HashFilter(SHA512(), attachment)

// SHA-384 (truncated SHA-512)
new HashFilter(SHA384(), attachment)

// SHA-1 (legacy only - not recommended)
new HashFilter(SHA1(), attachment)
```

### SHA-3 Family

```cpp
// SHA3-256
new HashFilter(SHA3_256(), attachment)

// SHA3-512
new HashFilter(SHA3_512(), attachment)

// SHAKE128 with custom output length
SHAKE128 shake;
shake.SetOutputLength(64);  // 64 bytes
new HashFilter(shake, attachment)
```

### BLAKE Family

```cpp
// BLAKE2b (default 64 bytes)
new HashFilter(BLAKE2b(), attachment)

// BLAKE2s (32 bytes, faster on 32-bit)
new HashFilter(BLAKE2s(), attachment)

// BLAKE3
new HashFilter(BLAKE3(), attachment)
```

### HMAC

```cpp
// HMAC requires a key
SecByteBlock key(32);
rng.GenerateBlock(key, key.size());

HMAC<SHA256> hmac(key, key.size());
new HashFilter(hmac, attachment)
```

## Hash Verification

HashFilter doesn't verify hashes directly. For verification, compare outputs:

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/misc.h>  // for VerifyBufsEqual

bool verifyHash(const std::string& message,
                const std::string& expectedHash) {
    using namespace CryptoPP;

    std::string computedHash;

    StringSource(message, true,
        new HashFilter(SHA256(), new StringSink(computedHash))
    );

    // Constant-time comparison (prevents timing attacks)
    if (computedHash.size() != expectedHash.size()) {
        return false;
    }

    return VerifyBufsEqual(
        reinterpret_cast<const byte*>(computedHash.data()),
        reinterpret_cast<const byte*>(expectedHash.data()),
        computedHash.size()
    );
}
```

## HashVerificationFilter

For integrated verification, use `HashVerificationFilter`:

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

bool verifyMessageWithHash(const std::string& messageAndHash) {
    using namespace CryptoPP;

    // messageAndHash contains: message || hash
    // HashVerificationFilter extracts and verifies

    bool verified = false;
    std::string recoveredMessage;

    StringSource(messageAndHash, true,
        new HashVerificationFilter(SHA256(),
            new StringSink(recoveredMessage),
            HashVerificationFilter::HASH_AT_END |
            HashVerificationFilter::PUT_MESSAGE |
            HashVerificationFilter::THROW_EXCEPTION
        )
    );

    return true;  // If we get here, verification passed
}
```

## Performance Tips

### Reuse Hash Objects

```cpp
// Efficient - hash object is copied once per pipeline
SHA256 hash;
for (const auto& msg : messages) {
    std::string digest;
    StringSource(msg, true,
        new HashFilter(hash, new StringSink(digest))
    );
    // hash is copied, not shared
}
```

### Pre-allocate Output

```cpp
std::string digest;
digest.reserve(SHA256::DIGESTSIZE);

StringSource(message, true,
    new HashFilter(SHA256(), new StringSink(digest))
);
```

### Use ArraySink for Known Sizes

```cpp
byte digest[SHA256::DIGESTSIZE];

ArraySource(data, dataLen, true,
    new HashFilter(SHA256(),
        new ArraySink(digest, sizeof(digest))
    )
);
```

## Common Patterns

### Hash Password for Storage (DON'T DO THIS)

```cpp
// WRONG - SHA-256 is NOT suitable for password hashing
std::string hash;
StringSource(password, true,
    new HashFilter(SHA256(), new HexEncoder(new StringSink(hash)))
);

// CORRECT - Use Argon2 for password hashing
Argon2 argon2;
// ... see Argon2 documentation
```

### API Request Signing

```cpp
std::string signRequest(const std::string& method,
                        const std::string& path,
                        const std::string& body,
                        const SecByteBlock& apiSecret) {
    using namespace CryptoPP;

    std::string message = method + "\n" + path + "\n" + body;
    std::string signature;

    HMAC<SHA256> hmac(apiSecret, apiSecret.size());

    StringSource(message, true,
        new HashFilter(hmac,
            new HexEncoder(new StringSink(signature))
        )
    );

    return signature;
}
```

### Content-Addressable Storage

```cpp
std::string contentHash(const std::string& content) {
    using namespace CryptoPP;

    std::string hash;

    StringSource(content, true,
        new HashFilter(SHA256(),
            new HexEncoder(new StringSink(hash), false)  // lowercase
        )
    );

    return hash;
}

// Use hash as filename
std::string filename = "objects/" + contentHash(data);
```

## Thread Safety

HashFilter is **not thread-safe**. Create separate instances per thread:

```cpp
// WRONG - shared across threads
HashFilter sharedFilter(SHA256(), ...);

// CORRECT - per-thread
void hashInThread(const std::string& data) {
    std::string digest;
    StringSource(data, true,
        new HashFilter(SHA256(), new StringSink(digest))
    );
}
```

## See Also

- [SHA-256](/docs/api/hash/sha256/) - SHA-256 hash function
- [BLAKE3](/docs/api/hash/blake3/) - BLAKE3 hash function
- [HMAC](/docs/api/mac/hmac/) - HMAC message authentication
- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File I/O
- [SignerFilter / VerifierFilter](/docs/api/utilities/signerfilter/) - Digital signatures
