---
title: BLAKE3
description: Fast cryptographic hash function with parallelism and tree hashing support
weight: 1
---

**Header:** `#include <cryptopp/blake3.h>` | **Namespace:** `CryptoPP`
**Since:** cryptopp-modern 2025.11.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

Fast cryptographic hash function based on Bao and BLAKE2. BLAKE3 is designed for high performance and supports parallel hashing, tree hashing, keyed hashing (MAC), and key derivation.

## Quick Example

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    BLAKE3 hash;
    std::string message = "Hello, World!";
    std::string digest, hexOutput;

    hash.Update((const byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());

    StringSource(digest, true, new HexEncoder(new StringSink(hexOutput)));
    std::cout << "BLAKE3: " << hexOutput << std::endl;
    // Expected: d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24

    return 0;
}
```

## Overview

BLAKE3 is a cryptographic hash function that is significantly faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2, while maintaining a high security margin. It can be used as a general-purpose hash function, a keyed hash (MAC), or a key derivation function (KDF).

Key features:
- **Extremely fast** - Outperforms all standard hash functions
- **Parallelizable** - Takes advantage of SIMD and multi-core processors
- **Extendable output** - Can generate hashes of any length
- **Multiple modes** - Standard hash, keyed hash (MAC), or KDF
- **No length extension** - Secure against length extension attacks

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use BLAKE3 for general-purpose hashing, file integrity, and content addressing
- Use keyed mode (MAC) for message authentication with a secret key
- Use KDF mode for deriving keys from passwords or shared secrets
- Use the same instance for multiple messages (call `Restart()` between them)
- Use hardware-accelerated builds (`AlgorithmProvider()` shows what's active)

**Avoid:**
- Using BLAKE3 KDF as a replacement for Argon2 for password hashing (use [Argon2](/docs/algorithms/argon2/) instead - it's memory-hard)
- Using keyed mode as a replacement for digital signatures (use [Ed25519](/docs/algorithms/public-key/#ed25519) instead)
- Reusing the same key for multiple purposes (use different keys or context strings)
- Using user-supplied strings directly as KDF context (use fixed, application-specific strings)
{{< /callout >}}

## Constants

- `DIGESTSIZE = 32` - Default output size in bytes
- `BLOCKSIZE = 64` - Internal block size in bytes
- `CHUNKSIZE = 1024` - Chunk size for tree hashing
- `DEFAULT_KEYLENGTH = 32` - Default key length for keyed hashing
- `MIN_KEYLENGTH = 0` - Minimum key length (0 for non-keyed hashing)
- `MAX_KEYLENGTH = 32` - Maximum key length in bytes

## Constructors

### Default Constructor
```cpp
BLAKE3(unsigned int digestSize = DIGESTSIZE)
```
Constructs a BLAKE3 hash object with specified output size. The `digestSize` can be any value (BLAKE3 supports extendable output).

**Parameters:**
- `digestSize` - Desired hash output size in bytes (default: 32)

**Exceptions:**
- None

**Example:**
```cpp
BLAKE3 hash;           // 32-byte output
BLAKE3 hash256(32);    // Explicit 32-byte output
BLAKE3 hashXOF(128);   // 128-byte extended output
```

---

### Keyed Constructor (MAC Mode)
```cpp
BLAKE3(const byte* key, size_t keyLength, unsigned int digestSize = DIGESTSIZE)
```
Constructs a BLAKE3 object for keyed hashing (MAC mode). Use this for message authentication with a secret key.

**Parameters:**
- `key` - Pointer to key bytes
- `keyLength` - Length of key in bytes (must be ≤ 32)
- `digestSize` - Desired hash output size in bytes (default: 32)

**Exceptions:**
- Throws `InvalidKeyLength` if `keyLength > MAX_KEYLENGTH`

**When to use:** Message authentication where both parties share a secret key (similar to HMAC).

**Example:**
```cpp
SecByteBlock key(32);
AutoSeededRandomPool rng;
rng.GenerateBlock(key, key.size());

BLAKE3 mac(key, key.size());  // Create MAC with 32-byte key
```

---

### KDF Constructor (Key Derivation Mode)
```cpp
BLAKE3(const char* context, unsigned int digestSize = DIGESTSIZE)
```
Constructs a BLAKE3 object for key derivation (KDF mode) with a context string for domain separation.

**Parameters:**
- `context` - Context string for domain separation (null-terminated)
- `digestSize` - Desired output size in bytes (default: 32)

**Exceptions:**
- Throws `InvalidArgument` if `context` is nullptr or empty

**When to use:** Deriving multiple keys from a single secret, or creating domain-separated hashes. The context should be a fixed, application-specific string, not user input.

**Example:**
```cpp
BLAKE3 kdf("MyApp 2025-11-25 Encryption Key", 32);
BLAKE3 kdf2("MyApp 2025-11-25 MAC Key", 32);  // Different context = different output
```

## Public Methods

### `StaticAlgorithmName()`
```cpp
static const char* StaticAlgorithmName()
```
Returns the algorithm name as a static string: `"BLAKE3"`.

**Thread Safety:** Thread-safe (static method).

---

### `AlgorithmName()`
```cpp
std::string AlgorithmName() const
```
Returns the algorithm name as a std::string: `"BLAKE3"`.

**Thread Safety:** Thread-safe (const method, read-only).

---

### `AlgorithmProvider()`
```cpp
std::string AlgorithmProvider() const
```
Returns the implementation provider, indicating if hardware acceleration is used.

**Returns:** String like `"C++"`, `"SSE4.1"`, `"AVX2"`, `"AVX-512"`, or `"NEON"`.

**Thread Safety:** Thread-safe (const method).

**Example:**
```cpp
BLAKE3 hash;
std::cout << "Using: " << hash.AlgorithmProvider() << std::endl;
// Might print "AVX2" on modern x86 CPUs
```

---

### `DigestSize()`
```cpp
unsigned int DigestSize() const
```
Returns the configured output size in bytes.

**Thread Safety:** Thread-safe (const method).

---

### `BlockSize()`
```cpp
unsigned int BlockSize() const
```
Returns the internal block size (64 bytes).

**Thread Safety:** Thread-safe (const method).

---

### `Update()`
```cpp
void Update(const byte* input, size_t length)
```
Updates the hash with additional input data. Can be called multiple times for incremental hashing.

**Parameters:**
- `input` - Pointer to input data
- `length` - Length of input data in bytes

**Exceptions:**
- None (safe to call with `length = 0`)

**Thread Safety:** Not thread-safe. Do not call from multiple threads on the same instance.

---

### `TruncatedFinal()`
```cpp
void TruncatedFinal(byte* hash, size_t size)
```
Finalizes the hash and writes the output. After calling this, the object is reset and can be reused.

**Parameters:**
- `hash` - Buffer to receive hash output (must be allocated by caller)
- `size` - Number of bytes to write (can be any size due to extendable output)

**Exceptions:**
- None (safe to call with `size = 0`, produces empty output)

**Thread Safety:** Not thread-safe.

**Note:** Calling `TruncatedFinal()` automatically calls `Restart()`, so the instance can be immediately reused.

---

### `Restart()`
```cpp
void Restart()
```
Resets the hash to its initial state, allowing reuse of the object. Preserves the mode (standard, keyed, or KDF) and configuration.

**Exceptions:** None

**Thread Safety:** Not thread-safe.

**Example:**
```cpp
BLAKE3 hash;
hash.Update(...);
hash.TruncatedFinal(...);  // Implicitly calls Restart()

// Can immediately reuse:
hash.Update(...);
hash.TruncatedFinal(...);
```

## Usage Modes

### Basic Hash Mode

**When to use:** General-purpose hashing, file integrity verification, content addressing.

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string message = "The quick brown fox jumps over the lazy dog";
    std::string digest;

    hash.Update((const CryptoPP::byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size());

    // Expected: a87e71ab2c6f926d6568cc0d70d7c0c8691ffb9567877e265f546e8f1e1ec1ca

    std::string hexOutput;
    CryptoPP::StringSource(digest, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput))
    );

    std::cout << "BLAKE3: " << hexOutput << std::endl;
    return 0;
}
```

**File hashing example:**
```cpp
BLAKE3 hash;
std::string digest;
FileSource("document.pdf", true,
    new HashFilter(hash,
        new StringSink(digest)
    )
);
// digest now contains the BLAKE3 hash of the file
```

---

### Keyed Hash Mode (MAC)

**When to use:** Message authentication when both parties share a secret key.

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Generate a random 32-byte key (do this once, store securely)
    AutoSeededRandomPool rng;
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Create keyed BLAKE3 (MAC)
    BLAKE3 mac(key, key.size());
    std::string message = "Authenticate this message";
    std::string tag;

    mac.Update((const byte*)message.data(), message.size());
    tag.resize(mac.DigestSize());
    mac.TruncatedFinal((byte*)&tag[0], tag.size());

    // Send message + tag to recipient
    // Recipient verifies by recomputing MAC with same key

    std::string hexTag;
    StringSource(tag, true, new HexEncoder(new StringSink(hexTag)));
    std::cout << "MAC: " << hexTag << std::endl;

    return 0;
}
```

**Verification example:**
```cpp
// Receiver side:
BLAKE3 verifyMac(key, key.size());
verifyMac.Update((const byte*)receivedMessage.data(), receivedMessage.size());
std::string computedTag(32, '\0');
verifyMac.TruncatedFinal((byte*)&computedTag[0], 32);

// Use constant-time comparison for MACs
if (VerifyBufsEqual(
        reinterpret_cast<const byte*>(computedTag.data()),
        reinterpret_cast<const byte*>(receivedTag.data()),
        32))
{
    std::cout << "Message is authentic!" << std::endl;
} else {
    std::cout << "WARNING: Message has been tampered with!" << std::endl;
}
```

---

### Key Derivation Mode (KDF)

**When to use:** Deriving multiple keys from a single secret, creating domain-separated keys.

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Derive different keys from the same input material
    std::string inputKeyMaterial = "shared_secret_or_password";

    // Derive encryption key
    BLAKE3 kdfEncrypt("MyApplication 2025-11-25 Encryption Key", 32);
    kdfEncrypt.Update((const byte*)inputKeyMaterial.data(), inputKeyMaterial.size());
    std::string encryptionKey(32, '\0');
    kdfEncrypt.TruncatedFinal((byte*)&encryptionKey[0], 32);

    // Derive MAC key (different context = different output)
    BLAKE3 kdfMac("MyApplication 2025-11-25 MAC Key", 32);
    kdfMac.Update((const byte*)inputKeyMaterial.data(), inputKeyMaterial.size());
    std::string macKey(32, '\0');
    kdfMac.TruncatedFinal((byte*)&macKey[0], 32);

    // encryptionKey and macKey are now independent, derived keys
    std::cout << "Derived two independent keys from one secret" << std::endl;

    return 0;
}
```

{{< callout type="warning" >}}
**For password hashing, use [Argon2](/docs/algorithms/argon2/) instead!**

BLAKE3 KDF is fast, which is good for key derivation but bad for password hashing. Argon2 is deliberately memory-hard and slow, making it resistant to brute-force attacks.
{{< /callout >}}

---

### Extendable Output (XOF)

**When to use:** Need arbitrary-length output for specific protocols or applications.

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    BLAKE3 hash;
    std::string message = "Generate arbitrary length output";
    std::string output;

    hash.Update((const byte*)message.data(), message.size());

    // Generate 128 bytes of output (or any size you need)
    output.resize(128);
    hash.TruncatedFinal((byte*)&output[0], output.size());

    std::cout << "Generated " << output.size() << "-byte hash output" << std::endl;

    // Can also generate different lengths from the same hash state:
    hash.Restart();
    hash.Update((const byte*)message.data(), message.size());
    std::string short16(16, '\0');
    hash.TruncatedFinal((byte*)&short16[0], 16);

    return 0;
}
```

## Performance

BLAKE3 is one of the fastest cryptographic hash functions available:

- **Significantly faster than [SHA-256](/docs/api/hash/SHA256/)** - Around 10× faster on modern CPUs; often ~2×+ faster than BLAKE2b
- **Hardware acceleration** - Uses SSE4.1, AVX2, AVX-512, and NEON when available
- **Parallelizable** - Scales with multiple cores for large inputs
- **Constant-time** - No data-dependent branches (resistant to timing attacks)

Use `AlgorithmProvider()` to check which hardware acceleration is being used.

**Benchmark (approximate, single-threaded on modern x86):**
- BLAKE3: ~3-4 GB/s
- BLAKE2b: ~1.5 GB/s
- SHA-256: ~300 MB/s
- SHA-512: ~500 MB/s

## Security

**Security properties**

- **Classical security (≥ 32-byte output):** BLAKE3 targets ~128-bit security for all standard hash goals (preimage, second-preimage, collision), as per the BLAKE3 specification.
- **Output length:** The default 32-byte (256-bit) output is recommended for general use. Longer outputs are deterministic extensions of the same root value and *do not* increase the underlying security level beyond ~128 bits.
- **Length-extension resistance:** Tree-based construction; not vulnerable to classic SHA-2 style length-extension attacks.
- **Keyed mode (MAC / PRF):** With a 32-byte secret key, BLAKE3 behaves as a secure PRF/MAC with ~128-bit security, and can act as a drop-in replacement for many HMAC-SHA-256 uses.
- **KDF mode:** With a fixed, application-specific context string and high-entropy key material, BLAKE3 provides a secure KDF for deriving multiple, domain-separated keys.
- **Side-channel behaviour:** The compression function is designed without secret-dependent branches or table lookups, and the cryptopp-modern implementation aims to be constant-time for secret inputs (subject to usual platform and compiler caveats).

**Security notes**

- Use at least 32 bytes of output for cryptographic purposes. Shorter digests (e.g. 16 bytes) are fine for non-critical identifiers but reduce the security margin.
- BLAKE3's *classical* security level is ~128 bits. Under generic quantum attacks (e.g. Grover's algorithm), effective preimage security is roughly ~64 bits, so treat it like any other 128-bit symmetric primitive in post-quantum planning.
- Do **not** use BLAKE3 directly for password hashing or deriving keys from low-entropy passwords. Use Argon2 for password hashing, and treat BLAKE3 KDF as a fast, follow-on KDF once you already have high-entropy key material.
- In keyed mode, treat BLAKE3 as a MAC/PRF, not as a digital signature. Use Ed25519/RSA/etc. where you need non-repudiation.
- When deriving multiple keys from the same input (e.g. encryption key + MAC key), always use distinct, fixed context strings to enforce domain separation between outputs.

## Thread Safety

- **Per-instance:** Not thread-safe. Do not use the same `BLAKE3` instance from multiple threads simultaneously.
- **Multi-instance:** Thread-safe. You can safely use different `BLAKE3` instances in different threads.
- **Static methods:** Thread-safe (`StaticAlgorithmName()`).

**Example (safe):**
```cpp
// Each thread has its own instance
void workerThread(const std::vector<std::string>& messages) {
    BLAKE3 hash;  // Thread-local instance
    for (const auto& msg : messages) {
        hash.Update(...);
        hash.TruncatedFinal(...);
        hash.Restart();
    }
}
```

## Use Cases

- **File integrity** - Checksums and file verification (faster than SHA-256)
- **Digital signatures** - Hash messages before signing with [Ed25519](/docs/algorithms/public-key/#ed25519)
- **Content addressing** - IPFS and similar systems
- **Deduplication** - Fast hash for identifying duplicate data
- **Message authentication** - Use keyed mode for MAC
- **Key derivation** - Derive multiple keys from one secret (use KDF mode)
- **Hash tables** - Fast non-cryptographic hashing (use basic mode)

## Test Vectors

Use these to verify your BLAKE3 implementation:

| Mode | Input | Key/Context | Output (first 32 bytes, hex) |
|------|-------|-------------|------------------------------|
| Basic | `""` (empty) | - | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` |
| Basic | `"Hello, World!"` | - | `d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24` |
| Basic | `"The quick brown fox jumps over the lazy dog"` | - | `a87e71ab2c6f926d6568cc0d70d7c0c8691ffb9567877e265f546e8f1e1ec1ca` |
| Keyed | `"message"` | 32-byte zero key | `03bf25008eb0c585f9ad2d89621b7e3d1f5b5b40e46fca0e4920f3d02e00ef97` |
| KDF | `"input"` | Context: `"test"` | `ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad618a1ea7a851e9d21` |

**Note:** These are BLAKE3 reference vectors. Your output should match exactly if your build is correct.

## See Also

- [BLAKE3 Guide](/docs/algorithms/blake3/) - Detailed guide with more examples
- [Hash Functions Guide](/docs/algorithms/hashing/) - Overview of all hash functions
- [Algorithm Reference](/docs/algorithms/reference/) - Complete algorithm catalog
- [Argon2](/docs/algorithms/argon2/) - Use this for password hashing, not BLAKE3
- [HMAC](/docs/api/mac/HMAC/) - Alternative MAC construction
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) - Official specification
