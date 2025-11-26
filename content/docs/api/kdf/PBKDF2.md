---
title: PKCS5_PBKDF2_HMAC
description: Password-Based Key Derivation Function 2 API reference
weight: 3
---

**Header:** `#include <cryptopp/pwdbased.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.0
**Thread Safety:** Thread-safe (stateless)

PKCS5_PBKDF2_HMAC is a key derivation function that derives cryptographic keys from passwords. It applies a pseudorandom function (HMAC) repeatedly to make brute-force attacks computationally expensive.

{{< callout type="warning" >}}
**For new applications, use [Argon2](/docs/api/kdf/argon2/) instead.** PBKDF2 lacks memory-hardness, making it vulnerable to GPU/ASIC attacks. PBKDF2 remains appropriate for compatibility with existing systems, FIPS compliance, or when Argon2 is not available.
{{< /callout >}}

## Quick Example

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string password = "user_password";

// Generate random salt
AutoSeededRandomPool rng;
byte salt[16];
rng.GenerateBlock(salt, sizeof(salt));

// Derive 32-byte key
byte derivedKey[32];
unsigned int iterations = 600000;  // OWASP 2023 recommendation

PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
pbkdf2.DeriveKey(derivedKey, sizeof(derivedKey),
                 0,  // purpose byte (unused, set to 0)
                 (const byte*)password.data(), password.size(),
                 salt, sizeof(salt),
                 iterations);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use at least 600,000 iterations for SHA-256 (OWASP 2023)
- Use at least 16 bytes of random salt per password
- Store salt alongside the derived key/hash
- Use constant-time comparison for password verification
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use fewer than 310,000 iterations (absolute minimum)
- Don't use MD5 or SHA-1 (use SHA-256 or SHA-512)
- Don't reuse salts across different passwords
- Don't use for new systems if Argon2 is available
{{< /callout >}}

## Constructor

```cpp
PKCS5_PBKDF2_HMAC<HashFunction>();
```

The hash function is specified as a template parameter:

```cpp
PKCS5_PBKDF2_HMAC<SHA256> pbkdf2_sha256;
PKCS5_PBKDF2_HMAC<SHA512> pbkdf2_sha512;
PKCS5_PBKDF2_HMAC<SHA1> pbkdf2_sha1;  // Legacy only
```

## Methods

### DeriveKey

```cpp
size_t DeriveKey(byte* derived, size_t derivedLen,
                 byte purpose,
                 const byte* password, size_t passwordLen,
                 const byte* salt, size_t saltLen,
                 unsigned int iterations,
                 double timeInSeconds = 0) const;
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `derived` | `byte*` | Output buffer for derived key |
| `derivedLen` | `size_t` | Length of derived key (bytes) |
| `purpose` | `byte` | Purpose byte (unused, set to 0) |
| `password` | `const byte*` | Password bytes |
| `passwordLen` | `size_t` | Password length |
| `salt` | `const byte*` | Salt bytes |
| `saltLen` | `size_t` | Salt length (min 16 bytes recommended) |
| `iterations` | `unsigned int` | Number of iterations |
| `timeInSeconds` | `double` | Alternative: target time (if > 0, overrides iterations) |

### Return Value

Returns the number of iterations performed (useful when using `timeInSeconds`).

### MaxDerivedKeyLength

```cpp
size_t MaxDerivedKeyLength() const;
```

Returns maximum derived key length: `(2^32 - 1) * hash_output_size`

## Complete Examples

### Example 1: Password Hashing for Storage

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

struct PasswordHash {
    std::string salt;      // Hex-encoded
    std::string hash;      // Hex-encoded
    unsigned int iterations;
};

PasswordHash hashPassword(const std::string& password) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate 16-byte random salt
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // OWASP 2023 recommendation for SHA-256
    unsigned int iterations = 600000;

    // Derive 32-byte hash
    byte hash[32];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(hash, sizeof(hash),
                     0,
                     (const byte*)password.data(), password.size(),
                     salt, sizeof(salt),
                     iterations);

    // Encode for storage
    PasswordHash result;
    result.iterations = iterations;

    StringSource(salt, sizeof(salt), true,
        new HexEncoder(new StringSink(result.salt)));

    StringSource(hash, sizeof(hash), true,
        new HexEncoder(new StringSink(result.hash)));

    return result;
}

bool verifyPassword(const std::string& password, const PasswordHash& stored) {
    using namespace CryptoPP;

    // Decode salt
    std::string saltBytes;
    StringSource(stored.salt, true,
        new HexDecoder(new StringSink(saltBytes)));

    // Derive hash with same parameters
    byte computedHash[32];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(computedHash, sizeof(computedHash),
                     0,
                     (const byte*)password.data(), password.size(),
                     (const byte*)saltBytes.data(), saltBytes.size(),
                     stored.iterations);

    // Decode stored hash
    std::string storedHashBytes;
    StringSource(stored.hash, true,
        new HexDecoder(new StringSink(storedHashBytes)));

    // Constant-time comparison
    return storedHashBytes.size() == sizeof(computedHash) &&
           VerifyBufsEqual((const byte*)storedHashBytes.data(),
                          computedHash, sizeof(computedHash));
}

int main() {
    std::string password = "MySecurePassword123!";

    // Hash password
    PasswordHash stored = hashPassword(password);

    std::cout << "Salt: " << stored.salt << std::endl;
    std::cout << "Hash: " << stored.hash << std::endl;
    std::cout << "Iterations: " << stored.iterations << std::endl;

    // Verify correct password
    if (verifyPassword(password, stored)) {
        std::cout << "Password verified!" << std::endl;
    }

    // Verify wrong password
    if (!verifyPassword("WrongPassword", stored)) {
        std::cout << "Wrong password rejected!" << std::endl;
    }

    return 0;
}
```

### Example 2: Key Derivation for Encryption

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

std::string encryptWithPassword(const std::string& password,
                                 const std::string& plaintext) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate salt for key derivation
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // Derive 32-byte key for AES-256
    byte key[32];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, sizeof(key),
                     0,
                     (const byte*)password.data(), password.size(),
                     salt, sizeof(salt),
                     600000);

    // Generate IV for GCM
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv);

    std::string ciphertext;
    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // Format: salt || iv || ciphertext
    std::string result;
    result.assign((const char*)salt, sizeof(salt));
    result.append((const char*)iv, sizeof(iv));
    result.append(ciphertext);

    return result;
}

std::string decryptWithPassword(const std::string& password,
                                 const std::string& encrypted) {
    using namespace CryptoPP;

    if (encrypted.size() < 16 + 12 + 16) {  // salt + iv + min ciphertext
        throw std::runtime_error("Encrypted data too short");
    }

    // Extract components
    const byte* salt = (const byte*)encrypted.data();
    const byte* iv = (const byte*)encrypted.data() + 16;
    std::string ciphertext = encrypted.substr(16 + 12);

    // Derive key
    byte key[32];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, sizeof(key),
                     0,
                     (const byte*)password.data(), password.size(),
                     salt, 16,
                     600000);

    // Decrypt
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, 12);

    std::string plaintext;
    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(plaintext)
        )
    );

    return plaintext;
}

int main() {
    std::string password = "encryption_password";
    std::string message = "Secret document contents";

    std::string encrypted = encryptWithPassword(password, message);
    std::cout << "Encrypted size: " << encrypted.size() << std::endl;

    std::string decrypted = decryptWithPassword(password, encrypted);
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```

### Example 3: Time-Based Iterations

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    std::string password = "test_password";
    byte key[32];

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;

    // Use time target instead of fixed iterations
    // Will iterate until ~1 second has passed
    unsigned int actualIterations = pbkdf2.DeriveKey(
        key, sizeof(key),
        0,
        (const byte*)password.data(), password.size(),
        salt, sizeof(salt),
        0,      // iterations (0 when using time)
        1.0     // target time in seconds
    );

    std::cout << "Iterations performed: " << actualIterations << std::endl;
    std::cout << "This gives you a baseline for your hardware" << std::endl;

    return 0;
}
```

### Example 4: PBKDF2 with SHA-512

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    std::string password = "secure_password";

    // SHA-512 version - OWASP recommends 210,000 iterations
    byte key[64];
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf2;
    pbkdf2.DeriveKey(key, sizeof(key),
                     0,
                     (const byte*)password.data(), password.size(),
                     salt, sizeof(salt),
                     210000);  // OWASP 2023 for SHA-512

    std::string hexKey;
    StringSource(key, sizeof(key), true,
        new HexEncoder(new StringSink(hexKey)));

    std::cout << "PBKDF2-SHA512 key: " << hexKey << std::endl;

    return 0;
}
```

### Example 5: Deriving Multiple Keys

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <cstring>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    std::string password = "master_password";

    // Derive enough material for multiple keys
    // 32 bytes for encryption key + 32 bytes for MAC key
    byte keyMaterial[64];

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(keyMaterial, sizeof(keyMaterial),
                     0,
                     (const byte*)password.data(), password.size(),
                     salt, sizeof(salt),
                     600000);

    // Split into separate keys
    byte encryptionKey[32];
    byte macKey[32];

    memcpy(encryptionKey, keyMaterial, 32);
    memcpy(macKey, keyMaterial + 32, 32);

    std::cout << "Derived encryption key (32 bytes) and MAC key (32 bytes)" << std::endl;

    // Securely clear key material
    memset(keyMaterial, 0, sizeof(keyMaterial));

    return 0;
}
```

### Example 6: WPA2 Key Derivation (Compatibility)

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

// WPA2 uses PBKDF2-SHA1 with 4096 iterations
std::string deriveWPA2Key(const std::string& password,
                           const std::string& ssid) {
    using namespace CryptoPP;

    // WPA2 spec: PBKDF2-SHA1, 4096 iterations, 32-byte output
    byte psk[32];

    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    pbkdf2.DeriveKey(psk, sizeof(psk),
                     0,
                     (const byte*)password.data(), password.size(),
                     (const byte*)ssid.data(), ssid.size(),
                     4096);

    std::string hexKey;
    StringSource(psk, sizeof(psk), true,
        new HexEncoder(new StringSink(hexKey)));

    return hexKey;
}

int main() {
    // Example: derive WPA2 PSK
    std::string password = "myWiFiPassword";
    std::string ssid = "MyNetwork";

    std::string psk = deriveWPA2Key(password, ssid);
    std::cout << "WPA2 PSK: " << psk << std::endl;

    return 0;
}
```

## Iteration Count Recommendations

### OWASP 2023 Recommendations

| Hash Function | Minimum Iterations |
|---------------|-------------------|
| SHA-256 | 600,000 |
| SHA-512 | 210,000 |
| SHA-1 | 1,300,000 (legacy only) |

### Choosing Iterations

```cpp
// Measure on your target hardware
PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
byte key[32], salt[16];

// Find iterations that take ~1 second
unsigned int iterations = pbkdf2.DeriveKey(
    key, sizeof(key), 0,
    (const byte*)"test", 4,
    salt, sizeof(salt),
    0,    // iterations
    1.0   // target 1 second
);

std::cout << "Recommended iterations for 1s: " << iterations << std::endl;
```

## PBKDF2 vs Argon2

| Feature | PBKDF2 | Argon2 |
|---------|--------|--------|
| **Memory hardness** | No | Yes |
| **GPU resistance** | Low | High |
| **ASIC resistance** | Low | High |
| **Standards** | RFC 2898, FIPS | RFC 9106, PHC winner |
| **Recommended for** | Legacy, FIPS | New applications |

### When to Use PBKDF2

- FIPS 140-2/140-3 compliance required
- Compatibility with existing systems
- Argon2 not available on platform
- Interoperability with other systems using PBKDF2

### When to Use Argon2

- New application development
- Maximum security against GPU/ASIC attacks
- No FIPS compliance requirement

## Security Properties

| Property | Value |
|----------|-------|
| **Security level** | Depends on iterations |
| **Salt size** | Minimum 16 bytes |
| **Output size** | Up to (2³² - 1) × hash_size |
| **Time complexity** | O(iterations) |
| **Memory complexity** | O(1) |

## Error Handling

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <iostream>

void safeDeriveKey(const std::string& password) {
    using namespace CryptoPP;

    try {
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;

        byte salt[16] = {0};  // Should be random in practice
        byte key[32];

        // Minimum iterations check
        unsigned int iterations = 600000;

        pbkdf2.DeriveKey(key, sizeof(key),
                         0,
                         (const byte*)password.data(), password.size(),
                         salt, sizeof(salt),
                         iterations);

        // Use key...

    } catch (const Exception& e) {
        std::cerr << "PBKDF2 error: " << e.what() << std::endl;
    }
}
```

## Thread Safety

PBKDF2 is stateless and thread-safe:

```cpp
// SAFE - multiple threads can use same template
PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;

void deriveInThread(const std::string& password,
                    const byte* salt,
                    byte* output) {
    pbkdf2.DeriveKey(output, 32, 0,
                     (const byte*)password.data(), password.size(),
                     salt, 16,
                     600000);
}
```

## See Also

- [Argon2](/docs/api/kdf/argon2/) - Recommended password hashing (memory-hard)
- [HKDF](/docs/api/kdf/hkdf/) - Key derivation from secrets (not passwords)
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Salt generation
- [Security Concepts](/docs/guides/security-concepts/) - Password security
