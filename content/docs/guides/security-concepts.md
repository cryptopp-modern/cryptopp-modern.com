---
title: Security Concepts
weight: 40
description: "Essential security concepts for cryptopp-modern: SecByteBlock memory protection, constant-time operations, nonce management, key separation, and secure random number generation."
---

Understanding key security concepts helps you use cryptography correctly and avoid common vulnerabilities.

## Table of Contents

- [SecByteBlock: Secure Memory Management](#secbyteblock-secure-memory-management)
- [Constant-Time Operations](#constant-time-operations)
- [Nonce and IV Management](#nonce-and-iv-management)
- [Key Separation](#key-separation)
- [Authenticate Then Decrypt](#authenticate-then-decrypt)
- [Secure Random Numbers](#secure-random-numbers)
- [Key Storage](#key-storage)
- [Compression Oracles](#compression-oracles)

---

## SecByteBlock: Secure Memory Management

### What Is It?

`SecByteBlock` is cryptopp's secure memory container for storing sensitive cryptographic data. Unlike `std::string` or raw byte arrays, `SecByteBlock` provides automatic memory wiping and protection against common security vulnerabilities.

### The Problem: Memory Leakage

When you store sensitive data in regular containers, that data can persist in memory long after you're done with it:

```cpp
// ❌ INSECURE: Sensitive data lingers in memory
void unsafeExample() {
    std::string password = "MySecretPassword";
    std::string encryptionKey = "0123456789abcdef";

    // Use the data...

    // Problem: Even after these variables go out of scope,
    // the actual password and key data may still exist in RAM!
    // - Memory is not immediately overwritten
    // - Strings may have been copied during resize
    // - Data could be paged to disk (swap space)
    // - An attacker with memory access could recover it
}
```

**Real-world risks:**
- **Memory dumps**: Crash dumps or debugging snapshots can contain secrets
- **Swap/hibernation files**: OS may write memory to disk
- **Cold boot attacks**: RAM retains data briefly after power loss
- **Process memory scanning**: Malware or debuggers can read process memory
- **Memory allocator reuse**: Freed memory with secrets might be reused

### The Solution: SecByteBlock

```cpp
#include <cryptopp/secblock.h>

// ✅ SECURE: Automatic memory wiping
void secureExample() {
    CryptoPP::SecByteBlock key(32);  // 32-byte encryption key

    // Generate random key
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());

    // Use the key...

    // When SecByteBlock goes out of scope:
    // - Memory is automatically zeroed (overwritten with zeros)
    // - No sensitive data remains in RAM
    // - Reduces risk of key recovery
}
```

### How SecByteBlock Protects You

**1. Automatic Memory Wiping**
```cpp
{
    CryptoPP::SecByteBlock secret(16);
    // Use secret...

    // Destructor automatically zeros all 16 bytes
} // ← Memory is wiped here!
```

**2. No Paging (Platform-Dependent)**
```cpp
// On some platforms, SecByteBlock attempts to lock memory
// to prevent it from being paged to disk
CryptoPP::SecByteBlock key(32);
// OS will try to keep this in physical RAM, not swap
```

**3. Secure Allocation**
```cpp
// SecByteBlock uses secure allocators that:
// - Wipe memory on deallocation
// - Avoid leaving copies in memory
// - Minimize fragmentation of sensitive data
```

### When to Use SecByteBlock

✅ **ALWAYS use `SecByteBlock` for:**

| Data Type | Why | Example |
|-----------|-----|---------|
| Encryption keys | Core secret | `CryptoPP::SecByteBlock aesKey(32);` |
| Decryption keys | Core secret | `CryptoPP::SecByteBlock privateKey(256);` |
| Password hashes | Before encoding for storage | `CryptoPP::SecByteBlock hash(32);` |
| Derived keys | From KDF/HKDF/Argon2 | `CryptoPP::SecByteBlock derived(32);` |
| Random salts | During generation | `CryptoPP::SecByteBlock salt(16);` |
| Nonces/IVs | During generation | `CryptoPP::SecByteBlock nonce(12);` |
| Authentication tags | Before verification | `CryptoPP::SecByteBlock tag(16);` |
| Session keys | Temporary secrets | `CryptoPP::SecByteBlock sessionKey(32);` |
| HMAC keys | Authentication secrets | `CryptoPP::SecByteBlock hmacKey(32);` |

❌ **`std::string` is acceptable for:**

| Data Type | Why | Example |
|-----------|-----|---------|
| User input passwords | Already in std::string from UI | `std::string password;` |
| Hex-encoded output | Meant for storage/transmission | `std::string keyHex;` |
| Base64-encoded data | Meant for storage/transmission | `std::string encoded;` |
| Ciphertext | Not secret (only confidential) | `std::string ciphertext;` |
| Public data | No confidentiality needed | `std::string plaintext;` |

### Practical Examples

#### Password Hashing

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

std::string hashPassword(const std::string& password) {
    CryptoPP::AutoSeededRandomPool prng;

    // ✅ SecByteBlock for salt (sensitive during generation)
    CryptoPP::SecByteBlock salt(16);
    prng.GenerateBlock(salt, salt.size());

    // ✅ SecByteBlock for hash (sensitive until encoded)
    CryptoPP::SecByteBlock hash(32);

    CryptoPP::Argon2id argon2;
    argon2.DeriveKey(
        hash, hash.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0, nullptr, 0,
        2, 65536
    );

    // ❌ std::string for hex output (meant for database storage)
    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(salt, salt.size());
    encoder.Put(hash, hash.size());
    encoder.MessageEnd();

    return result;
    // ← salt and hash SecByteBlocks are wiped here
}
```

#### Key Generation

```cpp
#include <cryptopp/osrng.h>

CryptoPP::SecByteBlock generateAESKey() {
    CryptoPP::AutoSeededRandomPool prng;

    // ✅ SecByteBlock for encryption key
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    return key;
    // Key data is moved (not copied), remains secure
}
```

#### Encryption with GCM

```cpp
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>

std::string encryptGCM(const std::string& plaintext) {
    CryptoPP::AutoSeededRandomPool prng;

    // ✅ SecByteBlock for key and nonce
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock nonce(12);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(nonce, nonce.size());

    // ❌ std::string for ciphertext (not secret, only confidential)
    std::string ciphertext;

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::AuthenticatedEncryptionFilter(enc,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Prepend nonce to ciphertext for storage
    std::string result(nonce.begin(), nonce.end());
    result += ciphertext;

    return result;
    // ← key and nonce are wiped here
}
```

#### Key Derivation

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

void deriveKeys(const CryptoPP::SecByteBlock& masterKey,
                CryptoPP::SecByteBlock& encKey,
                CryptoPP::SecByteBlock& macKey) {
    // ✅ All parameters are SecByteBlock (all are keys)

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

    encKey.resize(32);
    macKey.resize(32);

    hkdf.DeriveKey(
        encKey, encKey.size(),
        masterKey, masterKey.size(),
        nullptr, 0,
        (const CryptoPP::byte*)"encryption", 10
    );

    hkdf.DeriveKey(
        macKey, macKey.size(),
        masterKey, masterKey.size(),
        nullptr, 0,
        (const CryptoPP::byte*)"mac", 3
    );

    // All keys remain secure in SecByteBlocks
}
```

### Working with SecByteBlock

#### Creating and Sizing

```cpp
// Create with specific size
CryptoPP::SecByteBlock key(32);  // 32 bytes, uninitialized

// Create empty, resize later
CryptoPP::SecByteBlock buffer;
buffer.resize(16);

// Create and initialize
CryptoPP::SecByteBlock data(16);
std::memset(data, 0, data.size());
```

#### Accessing Data

```cpp
CryptoPP::SecByteBlock key(32);

// Get pointer to data (for C APIs)
CryptoPP::byte* ptr = key.data();
const CryptoPP::byte* constPtr = key.data();

// Get size
size_t size = key.size();

// Access individual bytes
key[0] = 0xFF;
CryptoPP::byte firstByte = key[0];

// Iterators
for (auto byte : key) {
    // Process byte
}
```

#### Converting to/from Strings

```cpp
// SecByteBlock → std::string (for storage/transmission)
CryptoPP::SecByteBlock key(16);
std::string keyHex;

CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(keyHex));
encoder.Put(key, key.size());
encoder.MessageEnd();

// std::string → SecByteBlock (loading from storage)
std::string keyHex = "0123456789abcdef...";
CryptoPP::SecByteBlock key;

CryptoPP::HexDecoder decoder(new CryptoPP::ArraySink(key, 16));
decoder.Put((const CryptoPP::byte*)keyHex.data(), keyHex.size());
decoder.MessageEnd();
```

### Common Mistakes

#### Mistake 1: Using std::string for Keys

```cpp
// ❌ BAD: Key data lingers in memory
std::string encryptionKey = "0123456789abcdef";

// ✅ GOOD: Key is wiped automatically
CryptoPP::SecByteBlock encryptionKey(16);
prng.GenerateBlock(encryptionKey, encryptionKey.size());
```

#### Mistake 2: Copying to Unsafe Containers

```cpp
CryptoPP::SecByteBlock key(32);
prng.GenerateBlock(key, key.size());

// ❌ BAD: Copying SecByteBlock data to std::string
std::string keyCopy(key.begin(), key.end());  // Now in TWO places!

// ✅ GOOD: Keep in SecByteBlock
// Use key.data() to pass pointer when needed
```

#### Mistake 3: Not Using for Intermediate Values

```cpp
// ❌ BAD: Derived key in std::string
std::string derivedKey;
CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
// derivedKey will contain sensitive data!

// ✅ GOOD: Derived key in SecByteBlock
CryptoPP::SecByteBlock derivedKey(32);
hkdf.DeriveKey(derivedKey, derivedKey.size(), ...);
```

### Performance Considerations

**Memory Wiping Cost:**
- Wiping memory on destruction has minimal performance impact
- Far outweighed by security benefits
- Only affects object destruction, not usage

**Memory Locking:**
- Attempted on some platforms (may fail without privileges)
- Prevents paging to swap, but uses physical RAM
- Use judiciously for truly sensitive data

**When Performance Matters:**
- For high-throughput data processing, consider if data is truly secret
- Ciphertext and public data don't need SecByteBlock
- Keys, salts, and derived secrets do need protection

### Summary: SecByteBlock

**Key Points:**
- `SecByteBlock` automatically wipes memory containing sensitive data
- Use it for all cryptographic keys, salts, hashes, and nonces
- Use `std::string` for encoded output meant for storage/transmission
- Prevents secrets from lingering in RAM after use
- Essential defense against memory dump attacks

**Rule of Thumb:** If the data is meant to remain secret and exists only in memory (not for storage/transmission), use `SecByteBlock`.

---

## Constant-Time Operations

### What Is It?

A **constant-time operation** takes the same amount of time to execute regardless of the input values. This prevents **timing attacks** where an attacker measures how long operations take to extract secret information.

### The Problem: Timing Attacks

Consider this simple password comparison:

```cpp
// VULNERABLE: Timing attack possible!
bool comparePasswords(const std::string& input, const std::string& correct) {
    if (input.length() != correct.length()) {
        return false;
    }

    for (size_t i = 0; i < input.length(); i++) {
        if (input[i] != correct[i]) {
            return false;  // ⚠️ Returns immediately on first mismatch!
        }
    }
    return true;
}
```

**What's wrong?**

This function returns as soon as it finds a mismatching character. An attacker can:
1. Try password `"a"` - fails quickly (wrong at position 0)
2. Try password `"b"` - fails quickly (wrong at position 0)
3. Try password `"p"` - takes slightly longer! (maybe correct at position 0)
4. Continue guessing character by character

The attacker can measure timing differences to figure out the correct password one character at a time!

### Real-World Timing Attack Example

```cpp
#include <iostream>
#include <string>
#include <chrono>

bool vulnerableCompare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    for (size_t i = 0; i < a.length(); i++) {
        if (a[i] != b[i]) return false;  // Early exit
    }
    return true;
}

int main() {
    std::string secret = "SECRET_PASSWORD_123";

    // Attacker tries different guesses
    std::string guess1 = "AAAAAAAAAAAAAAAAAAA";  // Wrong at position 0
    std::string guess2 = "SAAAAAAAAAAAAAAAAAA";  // Right at position 0, wrong at 1

    // Measure timing
    auto start = std::chrono::high_resolution_clock::now();
    vulnerableCompare(guess1, secret);
    auto end = std::chrono::high_resolution_clock::now();
    auto time1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    vulnerableCompare(guess2, secret);
    end = std::chrono::high_resolution_clock::now();
    auto time2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    std::cout << "Guess 'AAA...' took: " << time1 << "ns" << std::endl;
    std::cout << "Guess 'SAA...' took: " << time2 << "ns" << std::endl;
    std::cout << "Difference: " << (time2 - time1) << "ns" << std::endl;

    // Even tiny differences reveal information!
    if (time2 > time1) {
        std::cout << "⚠️ First character might be 'S'!" << std::endl;
    }

    return 0;
}
```

### The Solution: Constant-Time Comparison

**Good:** Use cryptopp's constant-time comparison

```cpp
#include <cryptopp/misc.h>

bool secureCompare(const CryptoPP::byte* a,
                   const CryptoPP::byte* b,
                   size_t length) {
    // Always compares ALL bytes, regardless of differences
    return CryptoPP::VerifyBufsEqual(a, b, length);
}
```

**How it works:**

```cpp
// Simplified illustration (actual implementation is more complex)
bool constantTimeCompare(const byte* a, const byte* b, size_t len) {
    byte result = 0;

    // ALWAYS checks every byte
    for (size_t i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]);  // Accumulate differences
    }

    // Returns at the END, after checking everything
    return result == 0;
}
```

### When to Use Constant-Time Operations

✅ **ALWAYS use for:**
- Password verification
- HMAC verification
- Authentication tag comparison
- Any comparison involving secrets

❌ **Not necessary for:**
- Public data comparison
- Non-security-sensitive operations

### Examples in cryptopp-modern

#### Password Hash Verification

```cpp
#include <cryptopp/argon2.h>

bool verifyPassword(const std::string& password,
                   const CryptoPP::SecByteBlock& storedHash,
                   const CryptoPP::SecByteBlock& salt) {
    CryptoPP::SecByteBlock computedHash(32);
    CryptoPP::Argon2id argon2;

    argon2.DeriveKey(
        computedHash, computedHash.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0, nullptr, 0,
        3, 65536
    );

    // ✅ GOOD: Constant-time comparison
    return CryptoPP::VerifyBufsEqual(
        computedHash, storedHash, 32
    );

    // ❌ BAD: Timing attack vulnerable
    // return memcmp(computedHash, storedHash, 32) == 0;
    // return computedHash == storedHash;
}
```

#### HMAC Verification

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

bool verifyHMAC(const std::string& message,
                const std::string& receivedMAC,
                const CryptoPP::SecByteBlock& key) {
    // Compute expected MAC
    std::string computedMAC;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::StringSink(computedMAC)
        )
    );

    // ✅ GOOD: Constant-time comparison
    if (computedMAC.size() != receivedMAC.size()) {
        return false;
    }

    return CryptoPP::VerifyBufsEqual(
        (const CryptoPP::byte*)computedMAC.data(),
        (const CryptoPP::byte*)receivedMAC.data(),
        computedMAC.size()
    );

    // ❌ BAD: Timing attack vulnerable
    // return computedMAC == receivedMAC;
}
```

#### GCM Authentication Tag Verification

```cpp
// Good news: GCM's AuthenticatedDecryptionFilter already uses
// constant-time comparison internally!

try {
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::AuthenticatedDecryptionFilter(dec,
            new CryptoPP::StringSink(plaintext)
        )  // ✅ Internally uses constant-time verification
    );
}
catch (const CryptoPP::Exception&) {
    // Authentication failed
}
```

### Summary: Constant-Time Operations

**Key Points:**
- Variable-time comparisons leak information through timing
- Attackers can measure timing differences to extract secrets
- Always use `CryptoPP::VerifyBufsEqual()` for secret comparisons
- Never use `memcmp()`, `==`, or manual loops for secrets

**Remember:** If a comparison involves a secret (password, key, MAC, auth tag), use constant-time comparison!

---

## Nonce and IV Management

### What Is It?

A **nonce** (number used once) or **IV** (initialization vector) is a value used to ensure that encrypting the same message twice produces different ciphertexts.

### The Critical Rule

**Never reuse a nonce with the same key!**

Different modes have different severity:

- **GCM**: Nonce reuse is **catastrophic** - completely breaks security, can leak keys
- **CBC**: Nonce reuse leaks information about plaintext
- **CTR**: Nonce reuse allows attacker to decrypt messages

### GCM Nonce Reuse: Catastrophic Failure

```cpp
// ⚠️ CATASTROPHIC FAILURE EXAMPLE - DO NOT DO THIS!
CryptoPP::SecByteBlock key(16);
CryptoPP::SecByteBlock nonce(12);
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(nonce, nonce.size());  // Generated ONCE

CryptoPP::GCM<CryptoPP::AES>::Encryption enc;

// First message - OK
enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
std::string ciphertext1 = encryptMessage(message1);

// Second message - CATASTROPHIC!
enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());  // SAME NONCE!
std::string ciphertext2 = encryptMessage(message2);

// Security is now completely broken:
// - Attacker can XOR ciphertexts to get keystream
// - Authentication key is exposed
// - Attacker can forge messages
// - Entire key must be considered compromised
```

### Correct Nonce Management

**Option 1: Random Nonces (Most Common)**

```cpp
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock key(16);
prng.GenerateBlock(key, key.size());

for (const auto& message : messages) {
    // Generate NEW nonce for EACH encryption
    CryptoPP::SecByteBlock nonce(12);
    prng.GenerateBlock(nonce, nonce.size());  // ✅ NEW every time!

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    // Encrypt and store: nonce || ciphertext
}
```

**Limitation:** With 96-bit random nonces, risk of collision after ~2^32 encryptions.

**Option 2: Counter-Based Nonces (High Volume)**

```cpp
class SafeGCMEncryption {
private:
    CryptoPP::SecByteBlock key;
    std::atomic<uint64_t> counter;

public:
    SafeGCMEncryption() : key(16), counter(0) {
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
    }

    std::string encrypt(const std::string& plaintext) {
        uint64_t count = counter.fetch_add(1);

        if (count >= (1ULL << 48)) {
            throw std::runtime_error("Nonce exhausted - rotate key!");
        }

        // Build nonce from counter
        CryptoPP::SecByteBlock nonce(12);
        memset(nonce, 0, 4);
        memcpy(nonce + 4, &count, 8);

        // Encrypt...
    }
};
```

### IV Storage

**Important:** IVs/nonces are NOT secret! Store them with the ciphertext.

```cpp
// Typical storage format
std::string encryptedData = nonce + ciphertext + authTag;

// When decrypting, extract the nonce first
std::string nonceStr = encryptedData.substr(0, 12);
std::string ciphertext = encryptedData.substr(12);
```

### Summary: Nonce/IV Management

**Key Points:**
- Generate a new nonce for every encryption
- Never reuse a nonce with the same key (especially GCM!)
- Nonces are not secret - store with ciphertext
- Use random nonces (2^32 limit) or counter-based (2^48+ limit)
- Rotate keys before exhausting nonce space

---

## Key Separation

### What Is It?

**Key separation** means using different cryptographic keys for different purposes, even if they're related operations.

### The Problem

```cpp
// ❌ BAD: Using same key for encryption and authentication
CryptoPP::SecByteBlock masterKey(32);
prng.GenerateBlock(masterKey, masterKey.size());

// Encrypt with AES-CBC using masterKey
CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
enc.SetKeyWithIV(masterKey, 16, iv);  // Uses first 16 bytes
// ...

// Authenticate with HMAC using same masterKey
CryptoPP::HMAC<CryptoPP::SHA256> hmac(masterKey, 32);  // Uses all 32 bytes
// ...

// ⚠️ Cryptographic key reuse can lead to vulnerabilities!
```

### The Solution: Separate Keys

```cpp
// ✅ GOOD: Separate keys for encryption and authentication
CryptoPP::SecByteBlock encryptionKey(16);  // For AES
CryptoPP::SecByteBlock macKey(32);         // For HMAC

CryptoPP::AutoSeededRandomPool prng;
prng.GenerateBlock(encryptionKey, encryptionKey.size());
prng.GenerateBlock(macKey, macKey.size());

// Encrypt
CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
enc.SetKeyWithIV(encryptionKey, encryptionKey.size(), iv);

// Authenticate
CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());
```

### Key Derivation for Separation

If you have one master key, derive separate keys:

```cpp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

// Derive separate keys from master key
CryptoPP::SecByteBlock masterKey(32);
prng.GenerateBlock(masterKey, masterKey.size());

CryptoPP::SecByteBlock encryptionKey(16);
CryptoPP::SecByteBlock macKey(32);

CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

// Derive encryption key
hkdf.DeriveKey(
    encryptionKey, encryptionKey.size(),
    masterKey, masterKey.size(),
    nullptr, 0,  // No salt
    (const CryptoPP::byte*)"encryption", 10  // Context string
);

// Derive MAC key
hkdf.DeriveKey(
    macKey, macKey.size(),
    masterKey, masterKey.size(),
    nullptr, 0,
    (const CryptoPP::byte*)"authentication", 14  // Different context
);
```

### When to Separate Keys

✅ **Always separate keys for:**
- Encryption vs. authentication
- Different users/sessions
- Different purposes (signing vs. encryption)
- Different algorithms

❌ **Exception:**
- Authenticated encryption modes (GCM, ChaCha20-Poly1305) handle this internally

### Summary: Key Separation

**Key Points:**
- Never use the same key for different cryptographic operations
- Use key derivation if you need multiple keys from one master key
- Different purposes = different keys
- GCM/ChaCha20-Poly1305 handle this automatically

---

## Authenticate Then Decrypt

### What Is It?

**Authenticate-then-decrypt** means verifying the authenticity of data BEFORE attempting to decrypt it.

### The Problem: Decrypt-then-Authenticate

```cpp
// ❌ BAD: Decrypt untrusted data first
try {
    // Decrypt first
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    std::string plaintext;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(dec,
            new CryptoPP::StringSink(plaintext)
        )
    );

    // Then verify HMAC
    if (!verifyHMAC(plaintext, receivedMAC)) {
        // Too late! Already processed untrusted data
        return false;
    }
}
catch (...) {
    // Decryption exceptions can leak information (padding oracle)
}
```

**Vulnerabilities:**
- **Padding oracle attacks** - Decryption errors leak information
- **Resource exhaustion** - Processing untrusted data wastes resources
- **Side channels** - Decryption timing can leak information

### The Solution

```cpp
// ✅ GOOD: Verify HMAC BEFORE decrypting
bool decryptMessage(const std::string& encrypted,
                   const CryptoPP::SecByteBlock& encKey,
                   const CryptoPP::SecByteBlock& macKey,
                   std::string& plaintext) {
    // Extract components
    std::string iv = encrypted.substr(0, 16);
    std::string ciphertext = encrypted.substr(16, encrypted.size() - 16 - 32);
    std::string receivedMAC = encrypted.substr(encrypted.size() - 32);

    // Step 1: VERIFY HMAC FIRST
    std::string computedMAC;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, macKey.size());

    std::string authData = iv + ciphertext;
    CryptoPP::StringSource(authData, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::StringSink(computedMAC)
        )
    );

    // Constant-time comparison
    if (!CryptoPP::VerifyBufsEqual(
            (const CryptoPP::byte*)computedMAC.data(),
            (const CryptoPP::byte*)receivedMAC.data(),
            32)) {
        // Authentication failed - don't decrypt!
        return false;
    }

    // Step 2: ONLY decrypt if authenticated
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(encKey, encKey.size(),
            (const CryptoPP::byte*)iv.data());

        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(plaintext)
            )
        );

        return true;
    }
    catch (const CryptoPP::Exception&) {
        return false;
    }
}
```

### Authenticated Encryption (Easier)

Use modes that handle this automatically:

```cpp
// ✅ GCM automatically authenticates before decrypting
try {
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

    std::string plaintext;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::AuthenticatedDecryptionFilter(dec,
            new CryptoPP::StringSink(plaintext)
        )  // Verifies auth tag BEFORE decrypting
    );

    // Only reaches here if authentication succeeded
}
catch (const CryptoPP::Exception&) {
    // Authentication failed - nothing was decrypted
}
```

### Summary: Authenticate Then Decrypt

**Key Points:**
- Always verify authentication tags/MACs before decrypting
- Use authenticated encryption modes (GCM, ChaCha20-Poly1305)
- If using CBC+HMAC, verify HMAC first
- Never process unauthenticated data

---

## Secure Random Numbers

### What Is It?

Cryptographically secure random number generation provides unpredictable, unbiased random values suitable for cryptographic use.

### The Problem: Weak RNGs

```cpp
// ❌ NEVER do this for cryptography!
#include <cstdlib>
#include <ctime>

srand(time(NULL));  // Predictable seed
int key = rand();   // Predictable output

// Attackers can:
// - Predict future outputs
// - Reconstruct past outputs
// - Brute-force the seed space (very small)
```

### The Solution: AutoSeededRandomPool

```cpp
#include <cryptopp/osrng.h>

// ✅ GOOD: Cryptographically secure RNG
CryptoPP::AutoSeededRandomPool prng;

// Generate random bytes
CryptoPP::SecByteBlock key(32);
prng.GenerateBlock(key, key.size());

// Generate random integer
unsigned int randomValue;
prng.GenerateBlock((CryptoPP::byte*)&randomValue, sizeof(randomValue));
```

### What Makes It Secure?

`AutoSeededRandomPool`:
- Uses OS entropy sources (/dev/urandom, CryptGenRandom, etc.)
- Automatically seeds from multiple sources
- Provides cryptographic-quality randomness
- Unpredictable even to attackers with partial information

### Examples

#### Generate Encryption Key

```cpp
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock aesKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
prng.GenerateBlock(aesKey, aesKey.size());
```

#### Generate Session Token

```cpp
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock token(32);  // 256-bit token
prng.GenerateBlock(token, token.size());

// Convert to hex for transmission
std::string tokenHex;
CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(tokenHex));
encoder.Put(token, token.size());
encoder.MessageEnd();
```

#### Generate Salt

```cpp
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock salt(16);
prng.GenerateBlock(salt, salt.size());

// Use with password hashing
CryptoPP::Argon2id argon2;
argon2.DeriveKey(hash, hashSize, password, passwordSize,
                 salt, salt.size(), ...);
```

### Summary: Secure Random Numbers

**Key Points:**
- Never use `rand()`, `srand()`, or `random()` for cryptography
- Always use `CryptoPP::AutoSeededRandomPool`
- Generate new random values for each use (keys, nonces, salts, tokens)
- Secure RNG is essential for all cryptographic operations

---

## Key Storage

### What Is It?

Securely storing cryptographic keys so they remain confidential even if other data is compromised.

### The Problem

```cpp
// ❌ NEVER hard-code keys in source code!
const std::string ENCRYPTION_KEY = "1234567890abcdef";  // Visible in binary!

// ❌ NEVER store keys in plain text files
std::ofstream keyFile("my_secret_key.txt");
keyFile << keyHex;  // Anyone can read this!

// ❌ NEVER commit keys to version control
// encryption_key=abc123def456  <-- in config.ini in git repo
```

### Solutions by Platform

#### Environment Variables (Basic)

```cpp
// Better than hard-coding, but not ideal
#include <cstdlib>

const char* keyHex = std::getenv("ENCRYPTION_KEY");
if (!keyHex) {
    std::cerr << "ENCRYPTION_KEY not set!" << std::endl;
    return 1;
}

// Decode and use key
```

**Pros:** Not in source code or version control
**Cons:** Visible in process listings, environment dumps

#### OS Key Storage (Recommended)

**Windows - DPAPI:**
```cpp
// Use Windows Data Protection API
// Keys encrypted with user/machine credentials
// See: CryptProtectData / CryptUnprotectData
```

**macOS - Keychain:**
```cpp
// Use macOS Keychain Services
// Requires Security framework
```

**Linux - libsecret / gnome-keyring:**
```cpp
// Use libsecret for encrypted key storage
// Integration with desktop keyring
```

#### Hardware Security Modules (Enterprise)

For high-security applications:
- HSM (Hardware Security Module)
- TPM (Trusted Platform Module)
- Cloud KMS (AWS KMS, Azure Key Vault, Google Cloud KMS)

### Password-Derived Keys

For user-specific encryption:

```cpp
// Derive encryption key from user password
CryptoPP::SecByteBlock deriveKeyFromPassword(
    const std::string& password,
    const CryptoPP::SecByteBlock& salt) {

    CryptoPP::SecByteBlock key(32);
    CryptoPP::Argon2id argon2;

    argon2.DeriveKey(
        key, key.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0, nullptr, 0,
        3, 65536
    );

    return key;
}

// Store only the salt (not the key!)
// Key is derived from password each time
```

### Key Rotation

Periodically change keys:

```cpp
class KeyManager {
private:
    std::map<int, CryptoPP::SecByteBlock> keys;
    int currentKeyVersion;

public:
    void rotateKey() {
        currentKeyVersion++;

        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock newKey(32);
        prng.GenerateBlock(newKey, newKey.size());

        keys[currentKeyVersion] = newKey;

        // Re-encrypt data with new key
        // Keep old keys for decrypting old data
    }

    CryptoPP::SecByteBlock getCurrentKey() {
        return keys[currentKeyVersion];
    }

    CryptoPP::SecByteBlock getKey(int version) {
        return keys[version];
    }
};
```

### Summary: Key Storage

**Key Points:**
- Never hard-code keys in source code
- Never commit keys to version control
- Use OS-specific secure storage (DPAPI, Keychain, libsecret)
- For user-specific data, derive keys from passwords
- Implement key rotation for long-lived systems
- Consider HSM/KMS for high-security requirements

---

## Quick Reference

| Concept | Rule | Use |
|---------|------|-----|
| Constant-Time | Always for secrets | `CryptoPP::VerifyBufsEqual()` |
| Nonce/IV | Never reuse with same key | New random nonce each encryption |
| Key Separation | Different keys for different purposes | Generate or derive separate keys |
| Auth Then Decrypt | Verify before decrypting | Use GCM or verify HMAC first |
| Secure Random | Never use `rand()` | `CryptoPP::AutoSeededRandomPool` |
| Key Storage | Never hard-code or commit | Use OS key storage or derive from password |
| Compression | Never compress attacker-influenced data before encryption | Compress only fully-controlled data |

Following these principles will help you avoid the most common cryptographic vulnerabilities!

---

## Compression Oracles

### What Is It?

A **compression oracle** attack exploits the fact that compression algorithms produce smaller output when there's repetition in the input. When an attacker can:

1. Inject data that gets compressed alongside a secret
2. Observe the resulting compressed (or encrypted) size

...they can learn information about the secret by measuring how well their injected data compresses with it.

### Famous Attacks

- **CRIME** (2012) - Attacked TLS compression, recovered session cookies
- **BREACH** (2013) - Attacked HTTP compression, recovered CSRF tokens
- **TIME** (2013) - Timing-based variant of CRIME

These attacks led to TLS compression being disabled by default in all major browsers and servers.

### How It Works

```
Secret token: "token=ABC123"
Attacker tries: "token=A" - compresses WELL with secret (shares "token=A")
Attacker tries: "token=X" - compresses POORLY (no common substring)

By observing output sizes:
- Smaller output → attacker's guess matches part of secret
- Character by character, attacker recovers entire secret
```

### Vulnerable Pattern

```cpp
// ❌ VULNERABLE: Attacker controls part of plaintext
std::string buildRequest(const std::string& userInput,
                          const std::string& secretToken) {
    return "User-Agent: " + userInput +
           "\r\nAuthorization: Bearer " + secretToken;
}

void sendEncrypted(const std::string& userInput,
                   const std::string& secretToken,
                   const CryptoPP::SecByteBlock& key) {
    std::string request = buildRequest(userInput, secretToken);

    // Step 1: Compress (DANGEROUS!)
    std::string compressed;
    CryptoPP::ZlibCompressor compressor(
        new CryptoPP::StringSink(compressed)
    );
    CryptoPP::StringSource(request, true,
        new CryptoPP::Redirector(compressor)
    );
    compressor.MessageEnd();

    // Step 2: Encrypt
    std::string ciphertext;
    // ... encryption ...

    // Attacker observes ciphertext.size() and learns about secretToken!
}
```

**Attack in practice:**

1. Attacker sends request with `userInput = "Authorization: Bearer A"`
2. If secret starts with "A", compression finds repetition → smaller size
3. Attacker sends `userInput = "Authorization: Bearer B"`
4. Larger size → secret doesn't start with "B"
5. Repeat to extract entire token character by character

### Safe Patterns

#### Pattern 1: Don't Compress User-Controlled Data

```cpp
// ✅ SAFE: Only compress application-controlled data
void safeEncrypt(const std::string& internalData,
                 const CryptoPP::SecByteBlock& key) {
    // No user input mixed with secrets - safe to compress
    std::string compressed;
    CryptoPP::ZlibCompressor compressor(
        new CryptoPP::StringSink(compressed)
    );
    CryptoPP::StringSource(internalData, true,
        new CryptoPP::Redirector(compressor)
    );
    compressor.MessageEnd();

    // Encrypt compressed data
    // ...
}
```

#### Pattern 2: Separate Secret from User Data

```cpp
// ✅ SAFE: Compress and encrypt separately
void safeSeparate(const std::string& userInput,
                  const std::string& secretToken,
                  const CryptoPP::SecByteBlock& key) {
    // Compress user data only (no secret)
    std::string compressedUserData;
    CryptoPP::ZlibCompressor compressor(
        new CryptoPP::StringSink(compressedUserData)
    );
    CryptoPP::StringSource(userInput, true,
        new CryptoPP::Redirector(compressor)
    );
    compressor.MessageEnd();

    // Encrypt user data
    std::string encryptedUserData = encrypt(compressedUserData, key);

    // Encrypt secret separately (no compression)
    std::string encryptedToken = encrypt(secretToken, key);

    // Attacker can't correlate sizes
}
```

#### Pattern 3: Pad to Fixed Size

```cpp
// ✅ SAFE: Hide compression ratio with padding
void safePadded(const std::string& data,
                const CryptoPP::SecByteBlock& key) {
    // Compress
    std::string compressed;
    CryptoPP::ZlibCompressor compressor(
        new CryptoPP::StringSink(compressed)
    );
    CryptoPP::StringSource(data, true,
        new CryptoPP::Redirector(compressor)
    );
    compressor.MessageEnd();

    // Pad to fixed block size (e.g., 4KB)
    const size_t BLOCK_SIZE = 4096;
    size_t paddedSize = ((compressed.size() / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    compressed.resize(paddedSize, '\0');

    // Encrypt - all outputs are multiple of 4KB
    std::string ciphertext = encrypt(compressed, key);

    // Attacker sees same size for many different inputs
}
```

#### Pattern 4: Don't Compress at All

```cpp
// ✅ SAFEST: Skip compression when secrets involved
void safestNoCompression(const std::string& userInput,
                          const std::string& secretToken,
                          const CryptoPP::SecByteBlock& key) {
    std::string combined = userInput + secretToken;

    // Encrypt directly - no compression oracle possible
    std::string ciphertext = encrypt(combined, key);
}
```

### When Compression Is Safe

✅ **Safe to compress then encrypt:**

| Scenario | Why Safe |
|----------|----------|
| Backup archives | Attacker can't inject content or observe sizes |
| Application logs (internal) | No user-controlled content mixed with secrets |
| Static assets | No secrets in data |
| Fully-controlled protocols | Both parties trusted, no injection point |

❌ **Dangerous to compress then encrypt:**

| Scenario | Why Dangerous |
|----------|---------------|
| HTTP responses with cookies | User input + secret in same response |
| API requests with tokens | Headers/body may contain secrets + user data |
| Web forms with CSRF tokens | Attacker can craft requests to test |
| Any protocol with reflection | User data echoed alongside secrets |

### TLS and HTTP Compression

**TLS compression:** Disabled by default since ~2012. Don't enable it.

**HTTP compression (gzip):** Still used, but:
- Never compress responses containing secrets AND user-reflected content
- Use `SameSite` cookies and other mitigations
- Consider per-request CSRF tokens that are single-use

### Summary: Compression Oracles

**Key Points:**
- Compression + encryption + attacker-controlled input = information leak
- CRIME/BREACH showed this is practical (cookie theft in seconds)
- Never compress data where attacker controls part and you have secrets
- Safe options: separate data, pad to fixed size, or skip compression
- TLS compression should remain disabled

**Rule of Thumb:** If an attacker can influence any part of data that will be compressed alongside a secret, and they can observe the output size, don't compress.
