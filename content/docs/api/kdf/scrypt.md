---
title: scrypt
description: scrypt memory-hard key derivation function API reference
weight: 4
---

**Header:** `#include <cryptopp/scrypt.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 7.0
**Thread Safety:** Thread-safe (stateless operation)

scrypt is a memory-hard password-based key derivation function designed by Colin Percival. It's specifically designed to make brute-force attacks expensive by requiring large amounts of memory, making it resistant to hardware-based attacks using GPUs, FPGAs, and ASICs.

## Quick Example

```cpp
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Password and salt
    std::string password = "correct horse battery staple";

    // Generate random salt (16 bytes minimum recommended)
    AutoSeededRandomPool rng;
    SecByteBlock salt(16);
    rng.GenerateBlock(salt, salt.size());

    // Derive 32-byte key using scrypt
    Scrypt scrypt;
    SecByteBlock derived(32);

    // Parameters: N=16384, r=8, p=1 (interactive login)
    scrypt.DeriveKey(
        derived, derived.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        16384,  // cost (N) - must be power of 2
        8,      // blockSize (r)
        1       // parallelization (p)
    );

    // Display result
    std::string hexOutput;
    StringSource(derived, derived.size(), true,
        new HexEncoder(new StringSink(hexOutput))
    );
    std::cout << "Derived key: " << hexOutput << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use scrypt for password hashing and key derivation
- Generate random salts (16+ bytes) for each password
- Choose parameters based on your security/performance requirements
- Store salt and parameters alongside the derived key
- Consider Argon2id for new applications (winner of Password Hashing Competition)

**Avoid:**
- Using cost (N) values that aren't powers of 2
- Using the same salt for multiple passwords
- Hardcoding parameters without considering target hardware
- Using scrypt for non-password key derivation (use HKDF instead)
{{< /callout >}}

## Class: Scrypt

Memory-hard key derivation function based on RFC 7914.

### Methods

#### DeriveKey()

```cpp
size_t DeriveKey(byte* derived, size_t derivedLen,
                 const byte* secret, size_t secretLen,
                 const byte* salt, size_t saltLen,
                 word64 cost = 2,
                 word64 blockSize = 8,
                 word64 parallelization = 1) const;
```

Derive a key from a password.

**Parameters:**
- `derived` - Output buffer for derived key
- `derivedLen` - Length of derived key in bytes
- `secret` - Password/passphrase
- `secretLen` - Length of password
- `salt` - Random salt (should be unique per password)
- `saltLen` - Length of salt
- `cost` - CPU/memory cost factor N (must be power of 2, > 1)
- `blockSize` - Block size r (default: 8)
- `parallelization` - Parallelization factor p (default: 1)

**Returns:** Always returns 1 (number of iterations)

**Memory Usage:** Approximately `128 * N * r` bytes

**Example:**

```cpp
Scrypt scrypt;
SecByteBlock derived(32);

// Interactive login: N=16384, r=8, p=1 (~16 MB memory)
scrypt.DeriveKey(
    derived, derived.size(),
    (const byte*)password.data(), password.size(),
    salt, salt.size(),
    16384, 8, 1
);
```

#### DeriveKey() with NameValuePairs

```cpp
size_t DeriveKey(byte* derived, size_t derivedLen,
                 const byte* secret, size_t secretLen,
                 const NameValuePairs& params) const;
```

Alternative interface using named parameters.

**Parameters via NameValuePairs:**
- `"Salt"` - Salt value
- `"Cost"` - CPU/memory cost (N)
- `"BlockSize"` - Block size (r)
- `"Parallelization"` - Parallelization factor (p)

#### MaxDerivedKeyLength()

```cpp
size_t MaxDerivedKeyLength() const;
```

**Returns:** Maximum derived key length (`SIZE_MAX`)

#### AlgorithmName()

```cpp
std::string AlgorithmName() const;
```

**Returns:** `"scrypt"`

## Parameter Selection

### Understanding scrypt Parameters

| Parameter | Symbol | Description | Effect |
|-----------|--------|-------------|--------|
| **Cost** | N | CPU/memory cost | Memory = 128 × N × r bytes |
| **BlockSize** | r | Block size | Increases memory per block |
| **Parallelization** | p | Parallel lanes | CPU parallelism |

### Recommended Parameters

| Use Case | N | r | p | Memory | Time |
|----------|---|---|---|--------|------|
| Interactive login | 16384 | 8 | 1 | ~16 MB | ~100ms |
| Sensitive storage | 1048576 | 8 | 1 | ~1 GB | ~5s |
| File encryption | 131072 | 8 | 1 | ~128 MB | ~500ms |
| Minimum security | 16384 | 8 | 1 | ~16 MB | ~100ms |

**Memory Formula:** `Memory ≈ 128 × N × r` bytes

### Parameter Constraints

```cpp
// N (cost) must be:
// - Greater than 1
// - A power of 2
// - Less than 2^(128 * r / 8)

// p (parallelization) must be:
// - A positive integer
// - Less than or equal to ((2^32 - 1) * 32) / (128 * r)
```

## Complete Example: Password Storage

```cpp
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/misc.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

struct StoredPassword {
    std::string salt;       // Hex-encoded salt
    std::string hash;       // Hex-encoded derived key
    word64 cost;            // N parameter
    word64 blockSize;       // r parameter
    word64 parallelization; // p parameter
};

// Hash a password for storage
StoredPassword hashPassword(const std::string& password) {
    AutoSeededRandomPool rng;

    // Generate random salt
    SecByteBlock salt(16);
    rng.GenerateBlock(salt, salt.size());

    // scrypt parameters for interactive login
    word64 N = 16384;   // Cost
    word64 r = 8;       // Block size
    word64 p = 1;       // Parallelization

    // Derive key
    Scrypt scrypt;
    SecByteBlock derived(32);
    scrypt.DeriveKey(
        derived, derived.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        N, r, p
    );

    // Encode for storage
    StoredPassword stored;
    stored.cost = N;
    stored.blockSize = r;
    stored.parallelization = p;

    StringSource(salt, salt.size(), true,
        new HexEncoder(new StringSink(stored.salt)));
    StringSource(derived, derived.size(), true,
        new HexEncoder(new StringSink(stored.hash)));

    return stored;
}

// Verify a password against stored hash
bool verifyPassword(const std::string& password,
                    const StoredPassword& stored) {
    // Decode salt
    SecByteBlock salt(stored.salt.size() / 2);
    StringSource(stored.salt, true,
        new HexDecoder(new ArraySink(salt, salt.size())));

    // Derive key with same parameters
    Scrypt scrypt;
    SecByteBlock derived(32);
    scrypt.DeriveKey(
        derived, derived.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        stored.cost, stored.blockSize, stored.parallelization
    );

    // Decode stored hash
    SecByteBlock storedHash(stored.hash.size() / 2);
    StringSource(stored.hash, true,
        new HexDecoder(new ArraySink(storedHash, storedHash.size())));

    // Constant-time comparison
    return VerifyBufsEqual(derived, storedHash, derived.size());
}

int main() {
    // Hash password
    StoredPassword stored = hashPassword("my_secure_password");

    std::cout << "Salt: " << stored.salt << std::endl;
    std::cout << "Hash: " << stored.hash << std::endl;
    std::cout << "N=" << stored.cost
              << ", r=" << stored.blockSize
              << ", p=" << stored.parallelization << std::endl;

    // Verify correct password
    if (verifyPassword("my_secure_password", stored)) {
        std::cout << "Password verified!" << std::endl;
    }

    // Verify wrong password
    if (!verifyPassword("wrong_password", stored)) {
        std::cout << "Wrong password rejected." << std::endl;
    }

    return 0;
}
```

## Complete Example: Encryption Key Derivation

```cpp
#include <cryptopp/scrypt.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

// Derive encryption key from password
SecByteBlock deriveEncryptionKey(const std::string& password,
                                  const SecByteBlock& salt) {
    Scrypt scrypt;
    SecByteBlock key(32);  // AES-256 key

    // Higher cost for file encryption
    scrypt.DeriveKey(
        key, key.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        131072,  // N = 2^17 (~128 MB memory)
        8,       // r = 8
        1        // p = 1
    );

    return key;
}

std::string encryptWithPassword(const std::string& plaintext,
                                 const std::string& password) {
    AutoSeededRandomPool rng;

    // Generate salt and IV
    SecByteBlock salt(16);
    byte iv[12];
    rng.GenerateBlock(salt, salt.size());
    rng.GenerateBlock(iv, sizeof(iv));

    // Derive key
    SecByteBlock key = deriveEncryptionKey(password, salt);

    // Encrypt with AES-GCM
    std::string ciphertext;
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Prepend salt and IV to ciphertext
    std::string result;
    result.append((const char*)salt.data(), salt.size());
    result.append((const char*)iv, sizeof(iv));
    result.append(ciphertext);

    return result;
}

int main() {
    std::string message = "Secret message to encrypt";
    std::string password = "user_password";

    std::string encrypted = encryptWithPassword(message, password);

    std::cout << "Encrypted " << message.size() << " bytes -> "
              << encrypted.size() << " bytes" << std::endl;

    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Parameters | Memory | Time | Use Case |
|------------|--------|------|----------|
| N=16384, r=8, p=1 | 16 MB | ~100 ms | Interactive |
| N=65536, r=8, p=1 | 64 MB | ~400 ms | Background |
| N=131072, r=8, p=1 | 128 MB | ~800 ms | File encryption |
| N=1048576, r=8, p=1 | 1 GB | ~5 s | High security |

**Platform:** Modern x86-64 CPU, single-threaded

### scrypt vs Other KDFs

| KDF | Memory-Hard | GPU Resistant | Winner of PHC |
|-----|-------------|---------------|---------------|
| **scrypt** | ✅ Yes | ✅ Good | ❌ No |
| Argon2id | ✅ Yes | ✅ Better | ✅ Yes |
| PBKDF2 | ❌ No | ❌ Poor | ❌ No |
| bcrypt | ⚠️ Limited | ⚠️ Moderate | ❌ No |

## Security

### Security Properties

- **Memory-hard:** Requires large amounts of memory, making parallel attacks expensive
- **Sequential memory access:** Designed to thwart time-memory trade-offs
- **Based on Salsa20/8:** Uses well-analyzed cryptographic primitives
- **Standard:** RFC 7914

### Security Notes

- **Salt uniqueness:** Always use a unique random salt per password
- **Parameter storage:** Store N, r, p alongside the hash for verification
- **Constant-time comparison:** Use `VerifyBufsEqual()` to prevent timing attacks
- **Consider Argon2id:** For new applications, Argon2id is recommended as the Password Hashing Competition winner

### Memory Requirements

```
Memory ≈ 128 × N × r bytes

Examples:
- N=16384,  r=8: 128 × 16384 × 8  = 16,777,216 bytes (~16 MB)
- N=131072, r=8: 128 × 131072 × 8 = 134,217,728 bytes (~128 MB)
- N=1048576, r=8: 128 × 1048576 × 8 = 1,073,741,824 bytes (~1 GB)
```

## scrypt vs Argon2

| Feature | scrypt | Argon2id |
|---------|--------|----------|
| Memory-hard | ✅ Yes | ✅ Yes |
| GPU resistance | ✅ Good | ✅ Better |
| Side-channel resistance | ⚠️ Moderate | ✅ Better |
| Standardization | RFC 7914 | RFC 9106 |
| PHC Winner | ❌ No | ✅ Yes |
| Recommendation | Legacy/compatibility | New applications |

**Recommendation:** Use Argon2id for new applications. Use scrypt for compatibility with existing systems (e.g., cryptocurrency wallets, Tarsnap).

## When to Use scrypt

### ✅ Use scrypt for:

1. **Compatibility** - Systems requiring scrypt (Tarsnap, some cryptocurrencies)
2. **Password Storage** - When Argon2 is not available
3. **Key Derivation** - Deriving encryption keys from passwords
4. **Existing Systems** - Maintaining compatibility with scrypt-based systems

### ❌ Don't use scrypt for:

1. **New Applications** - Prefer Argon2id
2. **Non-password KDF** - Use HKDF for key expansion
3. **Fast Operations** - scrypt is intentionally slow
4. **Memory-constrained** - Requires significant memory

## Exceptions

- `InvalidDerivedKeyLength` - Invalid output length
- `InvalidArgument` - Invalid parameters (N not power of 2, etc.)

## See Also

- [Argon2](/docs/api/kdf/argon2/) - Recommended password hashing (PHC winner)
- [PBKDF2](/docs/api/kdf/pbkdf2/) - Simpler but less secure KDF
- [HKDF](/docs/api/kdf/hkdf/) - Key expansion (not for passwords)
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption
