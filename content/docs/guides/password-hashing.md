---
title: Password Hashing Best Practices
description: Complete guide to secure password hashing with Argon2, scrypt, and PBKDF2. Learn how to protect user credentials against brute-force, GPU, and offline attacks.
weight: 50
---

This guide covers secure password storage - one of the most critical security tasks in application development. Poor password hashing is responsible for countless data breaches.

## The Golden Rules

{{< callout type="error" title="Never Do This" >}}
- **Never store passwords in plain text**
- **Never use MD5 or SHA-1 for passwords**
- **Never use fast hash functions (SHA-256, BLAKE3) alone for passwords**
- **Never use the same salt for all users**
- **Never write your own password hashing scheme**
{{< /callout >}}

{{< callout type="info" title="Always Do This" >}}
- **Use Argon2id** (recommended) or scrypt/bcrypt
- **Generate a unique random salt per password**
- **Use appropriate cost parameters** (tune for ~100ms-500ms)
- **Use constant-time comparison** when verifying
- **Upgrade hashing on user login** as hardware improves
{{< /callout >}}

## Why Password Hashing is Different

Regular hash functions (SHA-256, BLAKE3) are designed to be **fast**. That's terrible for passwords because:

```
SHA-256: ~10 million hashes/second on a CPU
         ~10 billion hashes/second on a GPU

Argon2id: ~10 hashes/second (with proper parameters)
```

*(Numbers are order-of-magnitude examples; real values depend on hardware, drivers, and implementation.)*

An attacker with a stolen database can try billions of password guesses per second with fast hashes, but only a handful with Argon2.

### The Attack Scenario

1. Attacker steals your user database
2. Database contains password hashes
3. Attacker runs offline brute-force attack
4. No rate limiting, no account lockouts - just raw computing power

**Your defense:** Make each password guess computationally expensive.

## Algorithm Comparison

| Algorithm | Memory-Hard | Recommended | Notes |
|-----------|-------------|-------------|-------|
| **Argon2id** | ✅ Yes | ✅ **Best choice** | RFC 9106, PHC winner |
| **scrypt** | ✅ Yes | ✅ Good | RFC 7914, proven |
| **bcrypt** | ⚠️ Limited | ⚠️ Acceptable | 72-byte password limit |
| **PBKDF2** | ❌ No | ⚠️ Legacy only | FIPS compliant, GPU-friendly |
| **SHA-256** | ❌ No | ❌ Never | Too fast |
| **MD5** | ❌ No | ❌ Never | Broken and too fast |

## Argon2id (Recommended)

Argon2 won the Password Hashing Competition (2015) and is standardized in RFC 9106. Use **Argon2id** which combines:
- Argon2i's side-channel resistance
- Argon2d's GPU/ASIC resistance

### Basic Password Hashing

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

struct PasswordHash {
    SecByteBlock salt;
    SecByteBlock hash;

    // Parameters (store these with the hash!)
    uint32_t iterations;
    uint32_t memory;      // KB
    uint32_t parallelism;
};

PasswordHash hashPassword(const std::string& password) {
    AutoSeededRandomPool rng;
    PasswordHash result;

    // Generate random 16-byte salt
    result.salt.resize(16);
    rng.GenerateBlock(result.salt, result.salt.size());

    // Argon2id parameters (tune for your hardware!)
    result.iterations = 3;       // Time cost
    result.memory = 65536;       // 64 MB memory
    result.parallelism = 4;      // 4 threads

    // Derive 32-byte hash
    result.hash.resize(32);

    Argon2id argon2;
    argon2.DeriveKey(
        result.hash, result.hash.size(),
        (const byte*)password.data(), password.size(),
        result.salt, result.salt.size(),
        result.iterations,
        result.memory,
        result.parallelism
    );

    return result;
}

bool verifyPassword(const std::string& password, const PasswordHash& stored) {
    // Re-derive hash with same parameters
    SecByteBlock computed(stored.hash.size());

    Argon2id argon2;
    argon2.DeriveKey(
        computed, computed.size(),
        (const byte*)password.data(), password.size(),
        stored.salt, stored.salt.size(),
        stored.iterations,
        stored.memory,
        stored.parallelism
    );

    // CRITICAL: Use constant-time comparison!
    return VerifyBufsEqual(computed, stored.hash, stored.hash.size());
}

int main() {
    std::string password = "correct horse battery staple";

    // Hash password (during registration)
    PasswordHash stored = hashPassword(password);

    // Verify password (during login)
    bool valid = verifyPassword(password, stored);
    std::cout << "Password valid: " << (valid ? "YES" : "NO") << std::endl;

    // Wrong password
    bool invalid = verifyPassword("wrong password", stored);
    std::cout << "Wrong password: " << (invalid ? "YES" : "NO") << std::endl;

    return 0;
}
```

### Parameter Selection

Choose parameters based on your security requirements and hardware:

#### Interactive Logins (Web/Mobile)

Target: **100-500ms** response time

```cpp
// Moderate security - interactive logins
uint32_t iterations = 3;
uint32_t memory = 65536;      // 64 MB
uint32_t parallelism = 4;
```

#### High Security (Encryption Keys, Sensitive Data)

Target: **500ms-1000ms** response time

```cpp
// High security - disk encryption, sensitive data
uint32_t iterations = 4;
uint32_t memory = 131072;     // 128 MB
uint32_t parallelism = 4;
```

#### Resource-Constrained (Mobile, Embedded)

Target: **100-250ms** on limited hardware

```cpp
// Resource-constrained environments
uint32_t iterations = 3;
uint32_t memory = 16384;      // 16 MB
uint32_t parallelism = 2;
```

### Tuning Parameters

**Always benchmark on your target hardware:**

```cpp
#include <chrono>

void tuneArgon2Parameters() {
    AutoSeededRandomPool rng;
    SecByteBlock salt(16), hash(32);
    rng.GenerateBlock(salt, salt.size());

    std::string testPassword = "benchmark_password";

    // Test different memory values
    for (uint32_t memory : {16384, 32768, 65536, 131072}) {
        auto start = std::chrono::high_resolution_clock::now();

        Argon2id argon2;
        argon2.DeriveKey(
            hash, hash.size(),
            (const byte*)testPassword.data(), testPassword.size(),
            salt, salt.size(),
            3,        // iterations
            memory,   // memory in KB
            4         // parallelism
        );

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "Memory: " << memory << " KB, Time: "
                  << duration.count() << " ms" << std::endl;
    }
}
```

## scrypt Alternative

If you can't use Argon2, scrypt (RFC 7914) is a good alternative:

```cpp
#include <cryptopp/scrypt.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

SecByteBlock hashWithScrypt(const std::string& password,
                            const SecByteBlock& salt) {
    SecByteBlock derived(32);

    Scrypt scrypt;
    scrypt.DeriveKey(
        derived, derived.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        1 << 15,    // N = 32768 (CPU/memory cost)
        8,          // r = 8 (block size)
        1           // p = 1 (parallelization)
    );

    return derived;
}
```

### scrypt Parameters

| Parameter | Meaning | Typical Value |
|-----------|---------|---------------|
| N | CPU/memory cost (power of 2) | 2^14 to 2^20 |
| r | Block size | 8 |
| p | Parallelization | 1 |

**Memory usage:** `128 * N * r` bytes

## PBKDF2 (Legacy Only)

Only use PBKDF2 when required for FIPS compliance or legacy compatibility:

```cpp
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

SecByteBlock hashWithPBKDF2(const std::string& password,
                            const SecByteBlock& salt) {
    SecByteBlock derived(32);

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(
        derived, derived.size(),
        0,  // purpose byte (unused)
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        600000  // iterations - OWASP 2023 recommendation
    );

    return derived;
}
```

{{< callout type="warning" >}}
**PBKDF2 Limitations:**
- Not memory-hard (GPU attacks effective)
- Requires very high iteration counts (600,000+ for SHA-256)
- Each doubling of iterations only adds 1 bit of security
- **Use Argon2 for new applications**
{{< /callout >}}

## Storage Format

Store everything needed to verify the password:

```cpp
#include <sstream>
#include <iomanip>

// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
std::string formatForStorage(const PasswordHash& ph) {
    std::ostringstream oss;
    oss << "$argon2id$v=19"
        << "$m=" << ph.memory
        << ",t=" << ph.iterations
        << ",p=" << ph.parallelism
        << "$";

    // Encode salt as hex
    std::string saltHex;
    StringSource(ph.salt, ph.salt.size(), true,
        new HexEncoder(new StringSink(saltHex)));
    oss << saltHex << "$";

    // Encode hash as hex
    std::string hashHex;
    StringSource(ph.hash, ph.hash.size(), true,
        new HexEncoder(new StringSink(hashHex)));
    oss << hashHex;

    return oss.str();
}

// Example output:
// $argon2id$v=19$m=65536,t=3,p=4$A1B2C3D4E5F6...$9F8E7D6C5B4A...
```

**Why this format:**
- Self-describing (algorithm, version, parameters)
- Can upgrade parameters without breaking existing hashes
- Industry standard format

## Security Considerations

### 1. Constant-Time Comparison

**Always** use constant-time comparison to prevent timing attacks:

```cpp
// WRONG - timing attack vulnerability
bool badVerify(const SecByteBlock& a, const SecByteBlock& b) {
    return a == b;  // Short-circuits on first difference!
}

// CORRECT - constant time comparison for equal-length buffers
bool goodVerify(const SecByteBlock& a, const SecByteBlock& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return VerifyBufsEqual(a, b, a.size());
}
```

### 2. Salt Requirements

- **Unique per password** - Never reuse salts
- **Random** - Use cryptographic RNG
- **Sufficient length** - 16 bytes minimum
- **Stored with hash** - Salt is not secret

```cpp
// WRONG - same salt for everyone
static byte globalSalt[16] = {...};  // Rainbow table attack!

// WRONG - predictable salt
std::string salt = username;  // Attackers can precompute

// CORRECT - random per password
AutoSeededRandomPool rng;
SecByteBlock salt(16);
rng.GenerateBlock(salt, salt.size());
```

### 3. Pepper (Optional Extra Security)

A pepper is a secret key stored separately from the database:

```cpp
// Pepper: secret key NOT stored in database
// Store in environment variable, HSM, or secure config
SecByteBlock pepper = getSecretPepper();  // 32 bytes

// Combine password with pepper before hashing
HMAC<SHA256> hmac(pepper, pepper.size());
SecByteBlock pepperedPassword(SHA256::DIGESTSIZE);
hmac.CalculateDigest(pepperedPassword,
    (const byte*)password.data(), password.size());

// Then hash the peppered password with Argon2
argon2.DeriveKey(hash, hashLen,
    pepperedPassword, pepperedPassword.size(),
    salt, saltLen, ...);
```

**Pepper benefits:**
- Database breach alone isn't enough
- Attacker needs both database AND pepper
- Can rotate pepper (re-hash on next login)

### 4. Password Requirements

Enforce reasonable password policies:

```cpp
bool validatePassword(const std::string& password) {
    // Minimum length (NIST recommends 8+)
    if (password.length() < 8) return false;

    // Maximum length (prevent DoS)
    if (password.length() > 128) return false;

    // Check against common passwords (have-i-been-pwned API)
    if (isCommonPassword(password)) return false;

    return true;
}
```

**Modern recommendations (NIST SP 800-63B):**
- Minimum 8 characters
- No complexity requirements (they don't help)
- Check against breached password lists
- Allow paste (password managers!)
- No periodic forced changes

## Upgrading Hashes

As hardware improves, upgrade parameters on user login:

```cpp
bool loginAndUpgrade(const std::string& username,
                     const std::string& password) {
    PasswordHash stored = loadFromDatabase(username);

    if (!verifyPassword(password, stored)) {
        return false;  // Wrong password
    }

    // Check if hash needs upgrading
    if (stored.memory < CURRENT_MEMORY_TARGET ||
        stored.iterations < CURRENT_ITERATION_TARGET) {

        // Re-hash with stronger parameters
        PasswordHash upgraded = hashPassword(password);
        saveToDatabase(username, upgraded);

        logSecurityEvent("Password hash upgraded for " + username);
    }

    return true;
}
```

## Complete Example: User Registration & Login

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <string>
#include <map>
#include <cstring>

using namespace CryptoPP;

// Simulated user database
struct UserRecord {
    SecByteBlock salt;
    SecByteBlock hash;
    uint32_t iterations = 3;
    uint32_t memory = 65536;
    uint32_t parallelism = 4;
};

std::map<std::string, UserRecord> database;

bool registerUser(const std::string& username,
                  const std::string& password) {
    // Check if user exists
    if (database.find(username) != database.end()) {
        std::cerr << "User already exists" << std::endl;
        return false;
    }

    // Validate password
    if (password.length() < 8) {
        std::cerr << "Password too short" << std::endl;
        return false;
    }

    AutoSeededRandomPool rng;
    UserRecord user;

    // Generate salt
    user.salt.resize(16);
    rng.GenerateBlock(user.salt, user.salt.size());

    // Hash password
    user.hash.resize(32);
    Argon2id argon2;
    argon2.DeriveKey(
        user.hash, user.hash.size(),
        (const byte*)password.data(), password.size(),
        user.salt, user.salt.size(),
        user.iterations, user.memory, user.parallelism
    );

    database[username] = user;
    std::cout << "User registered: " << username << std::endl;
    return true;
}

bool loginUser(const std::string& username,
               const std::string& password) {
    // Find user
    auto it = database.find(username);
    if (it == database.end()) {
        // Don't reveal whether user exists!
        // Still do a hash to prevent timing attacks
        SecByteBlock dummy(32), dummySalt(16);
        std::memset(dummySalt.BytePtr(), 0, dummySalt.size());
        Argon2id argon2;
        argon2.DeriveKey(dummy, dummy.size(),
            (const byte*)password.data(), password.size(),
            dummySalt, dummySalt.size(), 3, 65536, 4);
        return false;
    }

    const UserRecord& user = it->second;

    // Verify password
    SecByteBlock computed(user.hash.size());
    Argon2id argon2;
    argon2.DeriveKey(
        computed, computed.size(),
        (const byte*)password.data(), password.size(),
        user.salt, user.salt.size(),
        user.iterations, user.memory, user.parallelism
    );

    // Constant-time comparison
    if (!VerifyBufsEqual(computed, user.hash, user.hash.size())) {
        return false;
    }

    std::cout << "Login successful: " << username << std::endl;
    return true;
}

int main() {
    // Register users
    registerUser("alice", "secure_password_123");
    registerUser("bob", "another_secure_pwd!");

    // Login attempts
    loginUser("alice", "secure_password_123");  // Success
    loginUser("alice", "wrong_password");       // Fail
    loginUser("eve", "doesnt_exist");           // Fail (user doesn't exist)

    return 0;
}
```

## Common Mistakes

### Mistake 1: Using Fast Hashes

```cpp
// WRONG - SHA-256 is too fast!
SHA256 hash;
hash.Update((byte*)password.data(), password.size());
hash.Update(salt, saltLen);
hash.Final(digest);  // Billions of attempts per second possible
```

### Mistake 2: Reusing Salts

```cpp
// WRONG - same salt for all users
const byte GLOBAL_SALT[] = "my_application_salt";

// Attacker can build one rainbow table for all users
```

### Mistake 3: Non-Constant-Time Comparison

```cpp
// WRONG - leaks timing information
if (computedHash == storedHash) {  // Timing attack!
    return true;
}
```

### Mistake 4: Insufficient Parameters

```cpp
// WRONG - parameters too low
argon2.DeriveKey(hash, 32, password, pwLen, salt, 16,
    1,      // 1 iteration - way too low!
    1024,   // 1 MB - way too low!
    1);
```

### Mistake 5: Truncating Password

```cpp
// WRONG - limiting password length incorrectly
std::string truncated = password.substr(0, 20);  // Reduces entropy!

// CORRECT - allow long passwords, Argon2 handles them
// Just set a reasonable max (128-256 chars) to prevent DoS
```

## Performance Comparison

Approximate hashing times with recommended parameters:

| Algorithm | Parameters | Time | GPU Resistance |
|-----------|------------|------|----------------|
| Argon2id | 64MB, t=3, p=4 | ~300ms | Excellent |
| scrypt | N=2^15, r=8, p=1 | ~250ms | Good |
| bcrypt | cost=12 | ~250ms | Moderate |
| PBKDF2-SHA256 | 600,000 iterations | ~200ms | Poor |
| SHA-256 | 1 iteration | ~0.001ms | None |

## See Also

- [Argon2 API Reference](/docs/api/kdf/argon2/) - Detailed Argon2 documentation
- [scrypt API Reference](/docs/api/kdf/scrypt/) - scrypt documentation
- [PBKDF2 API Reference](/docs/api/kdf/pbkdf2/) - Legacy PBKDF2 documentation
- [Security Concepts](/docs/guides/security-concepts/) - Constant-time operations, secure memory
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Generating random salts
