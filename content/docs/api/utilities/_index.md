---
title: Utilities
description: API reference for utility classes and helpers
weight: 6
---

Essential utility classes for cryptographic operations: random number generation, secure memory management, encoding, and data transformation.

## Core Utilities

### [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) ⭐ Essential
Cryptographically secure random number generator
- Automatically seeded from OS entropy
- For generating keys, IVs, nonces, salts
- Fast (uses AES-CTR internally)
- Thread-safe when using per-thread instances

**Use AutoSeededRandomPool for:**
- Generating cryptographic keys
- Creating initialization vectors (IVs)
- Generating salts for password hashing
- Creating session tokens and API keys
- Any cryptographic random needs

### [SecByteBlock](/docs/api/utilities/secbyteblock/) ⭐ Essential
Secure memory allocation for sensitive data
- Automatically zeroes memory on destruction
- Prevents keys from lingering in RAM
- RAII-based (automatic cleanup)
- std::vector-like interface

**Use SecByteBlock for:**
- Storing cryptographic keys
- Holding passwords temporarily
- Managing shared secrets
- Any sensitive data that should be zeroed

## Encoding & Decoding

### [HexEncoder / HexDecoder](/docs/api/utilities/hexencoder/)
Convert binary data to/from hexadecimal
- Display keys and hashes
- Parse hex strings
- Debugging cryptographic operations

### [Base64Encoder / Base64Decoder](/docs/api/utilities/base64encoder/)
Convert binary data to/from Base64
- URL-safe variant available
- Transmit binary data in text protocols
- Store binary data in text files

## Data Transformation

### StringSource / StringSink (coming soon)
Input/output from std::string
- Source: Read from string
- Sink: Write to string
- Used with filters and pipelines

### FileSource / FileSink (coming soon)
Input/output from files
- Stream file data through crypto operations
- Memory-efficient for large files

### ArraySource / ArraySink (coming soon)
Input/output from byte arrays
- Work with C-style arrays
- Zero-copy operations

## Filters & Pipelines

### HashFilter (coming soon)
Compute hash through pipeline
- Combine with sources and sinks
- Stream data through hash functions

### SignerFilter / VerifierFilter (coming soon)
Sign and verify through pipeline
- Stream signature generation
- Stream signature verification

### StreamTransformationFilter (coming soon)
Apply encryption/decryption
- Encrypt/decrypt streams
- Handle padding automatically

## Quick Examples

### Generate Random Data

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

AutoSeededRandomPool rng;

// Generate 256-bit key
SecByteBlock key(32);
rng.GenerateBlock(key, key.size());

// Generate random integer
unsigned int randomNum = rng.GenerateWord32();
```

### Secure Key Storage

```cpp
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>

// CORRECT - auto-zeroed on scope exit
{
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    // ... use key ...
}  // Key automatically zeroed

// WRONG - key lingers in memory
{
    byte aesKey[16];
    // ... use key ...
}  // Key NOT zeroed, can be recovered from memory
```

### Hex Encoding

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

std::string hexOutput;
byte data[] = {0xDE, 0xAD, 0xBE, 0xEF};

StringSource(data, sizeof(data), true,
    new HexEncoder(new StringSink(hexOutput))
);

// hexOutput = "DEADBEEF"
```

### Hash with Pipeline

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>

std::string message = "Hello, World!";
std::string digest;

SHA256 hash;
StringSource(message, true,
    new HashFilter(hash,
        new StringSink(digest)
    )
);

// digest contains 32-byte SHA-256 hash
```

## Common Patterns

### Generate Keys for Encryption

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

AutoSeededRandomPool rng;

// Generate encryption key
SecByteBlock key(AES::MAX_KEYLENGTH);  // 256-bit
rng.GenerateBlock(key, key.size());

// Generate IV
byte iv[12];  // 96-bit for GCM
rng.GenerateBlock(iv, sizeof(iv));

// Use with AES-GCM
GCM<AES>::Encryption enc;
enc.SetKeyWithIV(key.data(), key.size(), iv, sizeof(iv));
```

### Display Binary Data

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

void displayBinary(const byte* data, size_t len) {
    std::string hexOutput;

    StringSource(data, len, true,
        new HexEncoder(
            new StringSink(hexOutput),
            true,  // uppercase
            2,     // group by 2
            ":"    // separator
        )
    );

    std::cout << hexOutput << std::endl;
    // Output: DE:AD:BE:EF
}
```

### Parse Hex String to Bytes

```cpp
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

SecByteBlock parseHex(const std::string& hexString) {
    std::string decoded;

    StringSource(hexString, true,
        new HexDecoder(new StringSink(decoded))
    );

    SecByteBlock result((const byte*)decoded.data(), decoded.size());
    return result;
}

// Usage
SecByteBlock key = parseHex("0123456789ABCDEF");
```

## Security Best Practices

### 1. Always Use AutoSeededRandomPool for Crypto

```cpp
// WRONG - NOT cryptographically secure
int random = std::rand();
std::mt19937 rng;

// CORRECT - cryptographically secure
AutoSeededRandomPool rng;
word32 random = rng.GenerateWord32();
```

### 2. Always Use SecByteBlock for Keys

```cpp
// WRONG - key lingers in memory
std::string key = "MySecretKey";
byte keyArray[32];

// CORRECT - auto-zeroed
SecByteBlock key(32);
```

### 3. Minimize Key Lifetime

```cpp
// CORRECT - minimal lifetime
{
    AutoSeededRandomPool rng;
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Use key immediately
    encrypt(data, key);
}  // Key zeroed as soon as possible

// WRONG - key lives too long
SecByteBlock key(32);
// ... lots of code ...
encrypt(data, key);
```

### 4. Per-Thread RNG Instances

```cpp
// CORRECT - thread-local RNG
void threadFunc() {
    AutoSeededRandomPool rng;  // Per-thread
    // ... use rng ...
}

// WRONG - shared RNG (race conditions)
AutoSeededRandomPool global_rng;
void thread1() { global_rng.GenerateBlock(...); }  // UNSAFE
void thread2() { global_rng.GenerateBlock(...); }
```

## Performance Tips

### 1. Reuse Objects

```cpp
// Efficient - reuse hash object
SHA256 hash;
for (const auto& msg : messages) {
    hash.Restart();
    hash.Update((const byte*)msg.data(), msg.size());
    byte digest[32];
    hash.Final(digest);
}

// Inefficient - recreate each time
for (const auto& msg : messages) {
    SHA256 hash;  // Unnecessary allocation
    // ...
}
```

### 2. Minimize Copies of SecByteBlock

```cpp
// Efficient - pass by reference
void encrypt(const SecByteBlock& key, const std::string& data) {
    // No copy of key
}

// Inefficient - pass by value
void encrypt(SecByteBlock key, const std::string& data) {
    // Copy of key created
}
```

### 3. Batch Random Generation

```cpp
// Efficient - generate in bulk
byte buffer[1000];
rng.GenerateBlock(buffer, sizeof(buffer));

// Inefficient - one at a time
for (int i = 0; i < 1000; i++) {
    byte b = rng.GenerateByte();  // Function call overhead
}
```

## Utility Comparison

| Utility | Purpose | Essential | Alternative |
|---------|---------|-----------|-------------|
| **AutoSeededRandomPool** | CSPRNG | ⭐ Yes | None (std::random NOT secure) |
| **SecByteBlock** | Secure memory | ⭐ Yes | std::vector<byte> (not secure) |
| HexEncoder | Display binary | ⚠️ Useful | Manual hex conversion |
| Base64Encoder | Text encoding | ⚠️ Useful | External base64 library |
| StringSource | Data pipeline | ⚠️ Useful | Direct API calls |

## Thread Safety

### AutoSeededRandomPool

**Not thread-safe.** Use per-thread instances:

```cpp
thread_local AutoSeededRandomPool rng;  // C++11
```

### SecByteBlock

**Thread-safe for const operations:**

```cpp
const SecByteBlock key(32);
// Multiple threads can read simultaneously

SecByteBlock key(32);
// Modification requires synchronization
```

### Encoders/Decoders

**Not thread-safe.** Use per-thread instances.

## See Also

- [Security Concepts](/docs/guides/security-concepts/) - Understanding random numbers and key management
- All API reference pages use AutoSeededRandomPool and SecByteBlock extensively
- [BLAKE3](/docs/api/hash/blake3/) - Example of using utilities with hash functions
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Example of using utilities with encryption
