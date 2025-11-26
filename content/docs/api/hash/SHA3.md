---
title: SHA-3
description: SHA-3 (Keccak) cryptographic hash function API reference
weight: 4
---

**Header:** `#include <cryptopp/sha3.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.6.2
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

SHA-3 (originally known as Keccak) is a cryptographic hash function family standardized by NIST in FIPS 202. It uses a completely different internal design (sponge construction) than SHA-2, providing algorithmic diversity.

## Quick Example

```cpp
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    SHA3_256 hash;
    std::string message = "Hello, World!";
    std::string digest, hexOutput;

    StringSource(message, true,
        new HashFilter(hash,
            new StringSink(digest)
        )
    );

    StringSource(digest, true,
        new HexEncoder(new StringSink(hexOutput))
    );

    std::cout << "SHA3-256: " << hexOutput << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use SHA-3 for algorithmic diversity (backup to SHA-2)
- Use when NIST/FIPS compliance specifically requires SHA-3
- Use for new protocols when you want algorithmic diversity alongside SHA-2, including in post-quantum planning (different design, similar security levels)
- Use extendable output functions (SHAKE128/SHAKE256) when needed

**Avoid:**
- Using SHA-3 instead of BLAKE3 for performance (BLAKE3 is faster)
- Mixing up SHA-3 with SHA-2 (completely different algorithms)
- Using Keccak (pre-FIPS) when you need SHA-3 (FIPS 202)
{{< /callout >}}

## Available Variants

### SHA3_256

Most commonly used SHA-3 variant.

```cpp
SHA3_256 hash;
static const int DIGESTSIZE = 32;  // 256 bits
static const int BLOCKSIZE = 136;  // Rate: 1088 bits
```

### SHA3_512

Highest security SHA-3 variant.

```cpp
SHA3_512 hash;
static const int DIGESTSIZE = 64;  // 512 bits
static const int BLOCKSIZE = 72;   // Rate: 576 bits
```

### SHA3_224

```cpp
SHA3_224 hash;
static const int DIGESTSIZE = 28;  // 224 bits
static const int BLOCKSIZE = 144;  // Rate: 1152 bits
```

### SHA3_384

```cpp
SHA3_384 hash;
static const int DIGESTSIZE = 48;  // 384 bits
static const int BLOCKSIZE = 104;  // Rate: 832 bits
```

## Methods

### Update()

```cpp
void Update(const byte* input, size_t length);
```

Add data to the hash computation.

### Final()

```cpp
void Final(byte* digest);
```

Finalize and get digest.

### TruncatedFinal()

```cpp
void TruncatedFinal(byte* digest, size_t size);
```

Get truncated hash.

### Restart()

```cpp
void Restart();
```

Reset to initial state.

### CalculateDigest() - Static

```cpp
static void CalculateDigest(byte* digest,
                            const byte* input,
                            size_t length);
```

One-shot hashing.

### VerifyDigest() - Static

```cpp
static bool VerifyDigest(const byte* digest,
                         const byte* input,
                         size_t length);
```

Verify hash (constant-time).

## Complete Example: File Integrity with SHA3-256

```cpp
#include <cryptopp/sha3.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

std::string sha3File(const std::string& filename) {
    SHA3_256 hash;
    std::string digest, hexDigest;

    FileSource(filename.c_str(), true,
        new HashFilter(hash,
            new StringSink(digest)
        )
    );

    StringSource(digest, true,
        new HexEncoder(new StringSink(hexDigest))
    );

    return hexDigest;
}

int main() {
    std::string hash = sha3File("firmware.bin");
    std::cout << "SHA3-256: " << hash << std::endl;
    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Algorithm | Speed (MB/s) | Notes |
|-----------|--------------|-------|
| BLAKE3 | 3000-6000 | Fastest |
| SHA-256 (SHA-NI) | 800-1500 | Hardware accelerated |
| SHA-512 | 600-1200 | Fast on 64-bit |
| **SHA3-256** | 300-600 | Software only |
| SHA3-512 | 200-400 | Lower rate than SHA3-256 |

**Key Points:**
- SHA-3 is slower than SHA-2 and BLAKE3
- No widespread hardware acceleration (yet)
- SHA3-256 is generally faster than SHA3-512 for long messages (higher rate: 1088 bits vs 576 bits)
- Trade speed for algorithmic diversity

## Security

### Security Properties

| Variant | Output | Collision | Preimage | Capacity |
|---------|--------|-----------|----------|----------|
| SHA3-224 | 224-bit | 112-bit | 224-bit | 448-bit |
| SHA3-256 | 256-bit | 128-bit | 256-bit | 512-bit |
| SHA3-384 | 384-bit | 192-bit | 384-bit | 768-bit |
| SHA3-512 | 512-bit | 256-bit | 512-bit | 1024-bit |

### Sponge Construction

SHA-3 uses a **sponge construction** with:
- **Rate (r):** Bits processed per round
- **Capacity (c):** Security parameter (c = 2 × output size)
- **Permutation:** Keccak-f[1600]

**Standard:** FIPS 202

### Test Vectors (NIST)

```cpp
// SHA3-256(""): empty string
// a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

SHA3_256 hash;
byte digest[32];
hash.Final(digest);

byte expected[] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

assert(std::memcmp(digest, expected, 32) == 0);
```

## SHA-3 vs SHA-2

| Feature | SHA-2 | SHA-3 |
|---------|-------|-------|
| Design | Merkle-Damgård | Sponge |
| Speed | Fast (with SHA-NI) | Moderate |
| Hardware | SHA-NI, ARMv8 | Limited |
| Security | Proven | Proven (different) |
| Standard | FIPS 180-4 | FIPS 202 |
| Use Case | General purpose | Diversity |

**When to use SHA-3:**
- Regulatory requirement for SHA-3
- Algorithmic diversity (backup to SHA-2)
- New protocols (future-proofing)
- Research and academia

**When to use SHA-2/BLAKE3:**
- Performance matters
- Hardware acceleration available
- Industry standard sufficient

## SHA-3 vs Keccak

**Important:** SHA-3 (FIPS 202) and Keccak (original) are **different**:

```cpp
// SHA-3 (FIPS 202) - Use this for standards compliance
SHA3_256 sha3;  // Domain separation: 0x06

// Keccak (original) - Pre-standardization version
Keccak_256 keccak;  // Domain separation: 0x01
```

**Use SHA-3** unless you specifically need Keccak for compatibility with pre-FIPS implementations (like Ethereum).

## Thread Safety

**Not thread-safe.** Use separate instances per thread.

## When to Use SHA-3

### ✅ Use SHA-3 for:

1. **Algorithmic Diversity** - Backup to SHA-2 family
2. **Compliance** - FIPS 202 requirements
3. **New Protocols** - Future-proofing
4. **Cryptographic Portfolio / PQ Planning** - Different structure from SHA-2, useful as a second independent hash family
5. **Research** - Academic projects

### ❌ Don't use SHA-3 for:

1. **Performance** - BLAKE3 or SHA-256 (with SHA-NI) are faster
2. **Ethereum** - Use Keccak, not SHA-3
3. **General Purpose** - SHA-256 is more widely supported

## Exceptions

None thrown under normal operation.

## See Also

- [SHA-256](/docs/api/hash/sha256/) - Faster SHA-2 variant
- [SHA-512](/docs/api/hash/sha512/) - SHA-2 with higher security
- [BLAKE3](/docs/api/hash/blake3/) - Fastest modern hash
- [Hash Functions Guide](/docs/algorithms/hashing/) - Conceptual overview
