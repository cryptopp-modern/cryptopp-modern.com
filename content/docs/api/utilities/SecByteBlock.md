---
title: SecByteBlock
description: Secure memory allocation for cryptographic keys API reference
weight: 2
---

**Header:** `#include <cryptopp/secblock.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0

SecByteBlock is a secure memory container for storing sensitive data like cryptographic keys, passwords, and secrets. It automatically zeroes memory on destruction, preventing keys from lingering in RAM after use.

## Quick Example

```cpp
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Create secure storage for AES-256 key
    SecByteBlock key(AES::MAX_KEYLENGTH);  // 32 bytes, auto-zeroed

    // Generate random key
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, key.size());

    std::cout << "Key size: " << key.size() << " bytes" << std::endl;

    // Use key for encryption...

    // Key is automatically zeroed when SecByteBlock goes out of scope
    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use SecByteBlock for all cryptographic keys and secrets
- Allocate once and reuse (avoids leaving copies in memory)
- Pass by reference to avoid copies
- Use `.data()` or `.BytePtr()` to get raw pointer
- Let SecByteBlock manage lifetime (automatic zeroing)

**Avoid:**
- Using std::string or std::vector for keys (NOT auto-zeroed)
- Using raw byte arrays for keys (NOT auto-zeroed)
- Making unnecessary copies
- Storing keys longer than needed
{{< /callout >}}

## Class: SecByteBlock

Secure dynamically-allocated byte array with automatic zeroing.

**Template Definition:**
```cpp
typedef SecBlock<byte, AllocatorWithCleanup<byte, true>> SecByteBlock;
```

**Type Alias:** SecByteBlock is a `std::vector<byte>`-like container with secure cleanup.

### Constructors

#### Default Constructor

```cpp
SecByteBlock();
```

Create empty SecByteBlock (0 bytes).

**Example:**

```cpp
SecByteBlock key;  // Empty, size = 0
```

#### Constructor with Size

```cpp
SecByteBlock(size_t size);
```

Create SecByteBlock with specified size. Memory is **not** initialised.

**Parameters:**
- `size` - Size in bytes

**Example:**

```cpp
SecByteBlock key(32);  // 32 bytes, uninitialised
```

#### Constructor with Size and Value

```cpp
SecByteBlock(size_t size, byte value);
```

Create SecByteBlock and initialise all bytes to a value.

**Parameters:**
- `size` - Size in bytes
- `value` - Value to fill (0-255)

**Example:**

```cpp
SecByteBlock key(32, 0);  // 32 bytes, all zeroed
```

#### Constructor from Byte Array

```cpp
SecByteBlock(const byte* ptr, size_t size);
```

Create SecByteBlock and copy data from byte array.

**Parameters:**
- `ptr` - Source byte array
- `size` - Number of bytes to copy

**Example:**

```cpp
byte rawKey[32] = { /* ... */ };
SecByteBlock key(rawKey, sizeof(rawKey));  // Copy into secure memory
```

#### Copy Constructor

```cpp
SecByteBlock(const SecByteBlock& other);
```

Create SecByteBlock by copying another.

**Note:** Creates a copy. For passing to functions, use reference instead.

**Example:**

```cpp
SecByteBlock key1(32);
SecByteBlock key2(key1);  // Copy key1 to key2
```

## Methods

### size()

```cpp
size_t size() const;
```

Get size in bytes.

**Returns:** Size in bytes

**Example:**

```cpp
SecByteBlock key(32);
std::cout << "Size: " << key.size() << " bytes" << std::endl;  // 32
```

### empty()

```cpp
bool empty() const;
```

Check if SecByteBlock is empty.

**Returns:** `true` if size is 0

**Example:**

```cpp
SecByteBlock key;
if (key.empty()) {
    std::cout << "Key is empty" << std::endl;
}
```

### data() / BytePtr()

```cpp
byte* data();
const byte* data() const;

// Aliases
byte* BytePtr();
const byte* BytePtr() const;
```

Get pointer to underlying byte array.

**Returns:** Pointer to byte array

**Example:**

```cpp
SecByteBlock key(32);

// Use with cryptographic functions
AES::Encryption enc;
enc.SetKey(key.data(), key.size());

// Or use BytePtr() (same thing)
enc.SetKey(key.BytePtr(), key.size());
```

### operator[]

```cpp
byte& operator[](size_t index);
const byte& operator[](size_t index) const;
```

Access byte at index.

**Parameters:**
- `index` - Index (0 to size-1)

**Returns:** Reference to byte

**Note:** No bounds checking. Use `.at()` for checked access.

**Example:**

```cpp
SecByteBlock key(32);
key[0] = 0xFF;  // Set first byte
byte first = key[0];  // Read first byte
```

### at()

```cpp
byte& at(size_t index);
const byte& at(size_t index) const;
```

Access byte at index with bounds checking.

**Parameters:**
- `index` - Index (0 to size-1)

**Returns:** Reference to byte

**Throws:** `std::out_of_range` if index >= size

**Example:**

```cpp
SecByteBlock key(32);
try {
    key.at(100) = 0xFF;  // Throws - out of bounds
} catch (std::out_of_range& e) {
    std::cerr << "Index out of range" << std::endl;
}
```

### resize()

```cpp
void resize(size_t newSize);
```

Change size of SecByteBlock.

**Parameters:**
- `newSize` - New size in bytes

**Note:** If shrinking, removed bytes are zeroed. If growing, new bytes are uninitialised.

**Example:**

```cpp
SecByteBlock key(16);  // 16 bytes
key.resize(32);        // Now 32 bytes
```

### Assign()

```cpp
void Assign(const byte* ptr, size_t size);
```

Replace contents with data from byte array.

**Parameters:**
- `ptr` - Source byte array
- `size` - Number of bytes

**Note:** Resizes if necessary. Old contents are zeroed.

**Example:**

```cpp
SecByteBlock key;
byte rawKey[32] = { /* ... */ };
key.Assign(rawKey, sizeof(rawKey));
```

### CleanNew()

```cpp
void CleanNew(size_t size);
```

Resize and zero all bytes.

**Parameters:**
- `size` - New size in bytes

**Example:**

```cpp
SecByteBlock key;
key.CleanNew(32);  // 32 bytes, all zeroed
```

### CleanGrow()

```cpp
void CleanGrow(size_t newSize);
```

Grow SecByteBlock without losing existing data. New bytes are zeroed.

**Parameters:**
- `newSize` - New size (must be >= current size)

**Example:**

```cpp
SecByteBlock key(16);
// ... fill key[0-15] ...
key.CleanGrow(32);  // Now 32 bytes, key[16-31] are zeroed
```

### swap()

```cpp
void swap(SecByteBlock& other);
```

Swap contents with another SecByteBlock.

**Parameters:**
- `other` - SecByteBlock to swap with

**Example:**

```cpp
SecByteBlock key1(32);
SecByteBlock key2(64);
key1.swap(key2);  // Now key1 is 64 bytes, key2 is 32 bytes
```

### begin() / end()

```cpp
byte* begin();
byte* end();
const byte* begin() const;
const byte* end() const;
```

Get iterator-style pointers for range-based for loops.

**Returns:** Pointers to beginning and end

**Example:**

```cpp
SecByteBlock key(32);

// Range-based for loop
for (byte& b : key) {
    b = 0xFF;  // Set all bytes to 0xFF
}

// Or with std algorithms
std::fill(key.begin(), key.end(), 0x00);
```

## Complete Example: Key Management

```cpp
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

class SecureEncryptor {
private:
    SecByteBlock encryptionKey;
    SecByteBlock macKey;

public:
    SecureEncryptor() {
        // Initialize with secure, auto-zeroing keys
        encryptionKey.CleanNew(32);  // 256-bit
        macKey.CleanNew(32);

        // Generate random keys
        AutoSeededRandomPool rng;
        rng.GenerateBlock(encryptionKey, encryptionKey.size());
        rng.GenerateBlock(macKey, macKey.size());
    }

    // Keys automatically zeroed when object is destroyed
    ~SecureEncryptor() {
        // SecByteBlock handles zeroing automatically
    }

    std::string encrypt(const std::string& plaintext) {
        AutoSeededRandomPool rng;
        byte iv[12];
        rng.GenerateBlock(iv, sizeof(iv));

        std::string ciphertext;
        GCM<AES>::Encryption enc;

        // Use SecByteBlock directly
        enc.SetKeyWithIV(encryptionKey.data(), encryptionKey.size(),
                        iv, sizeof(iv));

        StringSource(plaintext, true,
            new AuthenticatedEncryptionFilter(enc,
                new StringSink(ciphertext)
            )
        );

        // Prepend IV
        std::string result;
        result.append((const char*)iv, sizeof(iv));
        result.append(ciphertext);

        return result;
    }
};

int main() {
    SecureEncryptor enc;

    std::string plaintext = "Secret message";
    std::string ciphertext = enc.encrypt(plaintext);

    std::cout << "Encrypted: " << ciphertext.size() << " bytes" << std::endl;

    // Keys automatically zeroed when enc goes out of scope
    return 0;
}
```

## Complete Example: Password Storage

```cpp
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/argon2.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

// Secure password-based key derivation
SecByteBlock deriveKeyFromPassword(const std::string& password) {
    // Generate random salt
    AutoSeededRandomPool rng;
    SecByteBlock salt(16);
    rng.GenerateBlock(salt, salt.size());

    // Derive key using Argon2
    SecByteBlock key(32);  // 256-bit key
    Argon2id argon2;

    argon2.DeriveKey(
        key, key.size(),
        (const byte*)password.data(), password.size(),
        salt, salt.size(),
        3,      // t_cost (iterations)
        65536,  // m_cost (memory in KB)
        4       // parallelism
    );

    // salt should be stored alongside derived key hash
    // (not shown for brevity)

    return key;  // Secure copy, original is zeroed
}

int main() {
    std::string password = "MySecurePassword123!";

    // Derive encryption key from password
    SecByteBlock key = deriveKeyFromPassword(password);

    std::cout << "Derived key: " << key.size() << " bytes" << std::endl;

    // Use key for encryption...

    // Key automatically zeroed when out of scope
    return 0;
}
```

## Complete Example: Passing Keys Safely

```cpp
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <iostream>

using namespace CryptoPP;

// CORRECT - pass by const reference (no copy)
void encryptData(const SecByteBlock& key, const std::string& data) {
    if (key.size() != AES::DEFAULT_KEYLENGTH) {
        throw std::invalid_argument("Invalid key size");
    }

    AES::Encryption enc;
    enc.SetKey(key.data(), key.size());

    // ... encrypt data ...
    std::cout << "Encrypting with " << key.size() << "-byte key" << std::endl;
}

// WRONG - pass by value (creates copy in memory!)
void badFunction(SecByteBlock key) {  // DON'T DO THIS
    // Key copied - leaves duplicate in memory
}

// CORRECT - return SecByteBlock (move semantics, no copy)
SecByteBlock generateKey(size_t size) {
    AutoSeededRandomPool rng;
    SecByteBlock key(size);
    rng.GenerateBlock(key, key.size());
    return key;  // Move semantics (C++11), no copy
}

int main() {
    // Generate key
    SecByteBlock key = generateKey(16);  // Move, not copy

    // Pass to functions
    std::string data = "Secret data";
    encryptData(key, data);  // Pass by reference, no copy

    return 0;
}
```

## Memory Security

### Why SecByteBlock?

**Problem with std::string and std::vector:**

```cpp
// WRONG - key lingers in memory after destruction
{
    std::string key = "MySecretKey";
    // ... use key ...
}  // key destroyed, but "MySecretKey" still in RAM!
// Can be recovered by memory dump or swap file
```

**Solution with SecByteBlock:**

```cpp
// CORRECT - key zeroed on destruction
{
    SecByteBlock key(32);
    // ... use key ...
}  // key destroyed AND memory zeroed (can't be recovered)
```

### Memory Zeroing

SecByteBlock automatically zeroes memory:

- **On destruction:** When SecByteBlock goes out of scope
- **On resize:** When shrinking, removed bytes are zeroed
- **On Assign:** Old contents are zeroed before new assignment

**Implementation:**
```cpp
~SecByteBlock() {
    // Memory is overwritten with zeros before deallocation
    // Uses secure memset that can't be optimised away
}
```

### Additional Security

For maximum security, consider:

1. **Lock memory pages** (prevent swapping to disk):
   ```cpp
   // Platform-specific: mlock() on Unix, VirtualLock() on Windows
   // Not built into SecByteBlock, but can be added
   ```

2. **Disable core dumps:**
   ```cpp
   #include <sys/resource.h>
   struct rlimit rl = {0, 0};
   setrlimit(RLIMIT_CORE, &rl);  // Unix
   ```

3. **Clear stack:**
   ```cpp
   void processKey() {
       SecByteBlock key(32);
       // ... use key ...
       // key zeroed automatically
   }
   // Stack variables (like temporary byte arrays) may still exist
   ```

## Performance

### Benchmarks (Approximate)

| Operation | Time | Notes |
|-----------|------|-------|
| Construction | <1 µs | Fast allocation |
| Destruction | <1 µs | Includes zeroing |
| resize() | <1 µs | Zeroing included |
| Copy | O(n) | Memcpy + zeroing |

**Note:** Zeroing overhead is negligible for typical key sizes (16-64 bytes).

### Memory Overhead

- **Storage:** Same as std::vector<byte>
- **Allocator:** Slightly more than std::allocator due to zeroing
- **Total overhead:** ~24 bytes (pointer + size + capacity) on 64-bit systems

## Security Best Practices

### 1. Always Use SecByteBlock for Keys

```cpp
// WRONG
std::string aesKey = "0123456789ABCDEF";  // Lingers in memory
byte hmacKey[32];  // Not zeroed on scope exit

// CORRECT
SecByteBlock aesKey(16);  // Auto-zeroed
SecByteBlock hmacKey(32);  // Auto-zeroed
```

### 2. Pass by Reference

```cpp
// WRONG - creates copy in memory
void encrypt(SecByteBlock key) { /* ... */ }

// CORRECT - no copy
void encrypt(const SecByteBlock& key) { /* ... */ }
```

### 3. Minimize Lifetime

```cpp
// CORRECT - minimal lifetime
{
    SecByteBlock key(32);
    generateKey(key);
    encrypt(data, key);
}  // Key zeroed immediately after use

// WRONG - key lives longer than needed
SecByteBlock key(32);
generateKey(key);
// ... lots of other code ...
encrypt(data, key);
```

### 4. Don't Convert to std::string

```cpp
// WRONG - defeats purpose of SecByteBlock
SecByteBlock key(32);
std::string keyStr((const char*)key.data(), key.size());  // BAD!

// CORRECT - use SecByteBlock directly
SecByteBlock key(32);
enc.SetKey(key.data(), key.size());
```

## SecByteBlock vs Alternatives

| Type | Auto-Zero | RAII | Type-Safe | Use Case |
|------|-----------|------|-----------|----------|
| **SecByteBlock** | ✅ Yes | ✅ Yes | ✅ Yes | Keys ⭐ |
| std::vector<byte> | ❌ No | ✅ Yes | ✅ Yes | Non-sensitive |
| std::string | ❌ No | ✅ Yes | ⚠️ No | Text only |
| byte[] | ❌ No | ❌ No | ⚠️ No | Legacy C |
| SecBlock<word32> | ✅ Yes | ✅ Yes | ✅ Yes | 32-bit keys |

## Related Types

### SecBlock<T>

SecByteBlock is a typedef of `SecBlock<byte>`. You can use SecBlock for other types:

```cpp
// For 32-bit words
SecBlock<word32> key32(8);  // 8 * 32-bit = 256 bits

// For 64-bit words
SecBlock<word64> key64(4);  // 4 * 64-bit = 256 bits
```

### Other Secure Containers

```cpp
// Secure string (auto-zeroed)
typedef SecBlock<char, AllocatorWithCleanup<char, true>> SecString;

// Secure word block
typedef SecBlock<word32, AllocatorWithCleanup<word32, true>> SecWordBlock;
```

## Thread Safety

**Thread-safe for const operations** after construction. Modification requires synchronization.

```cpp
// Safe - read-only access
const SecByteBlock key(32);

void thread1() { enc1.SetKey(key.data(), key.size()); }  // OK
void thread2() { enc2.SetKey(key.data(), key.size()); }  // OK

// Unsafe - writing without synchronization
SecByteBlock key(32);
void thread1() { key[0] = 0xFF; }  // RACE CONDITION
void thread2() { key[1] = 0xAA; }
```

## Exceptions

- `std::bad_alloc` - Memory allocation failed
- `std::out_of_range` - `.at()` index out of bounds
- `InvalidArgument` - Invalid size (too large)

## When to Use SecByteBlock

### ✅ Use SecByteBlock for:

1. **Cryptographic Keys** - AES, HMAC, RSA, etc.
2. **Passwords** - Before hashing
3. **Shared Secrets** - From key exchange (X25519, DH)
4. **Private Keys** - RSA, Ed25519, etc.
5. **Derived Keys** - From HKDF, PBKDF2, Argon2
6. **Any Sensitive Data** - That should be zeroed after use

### ❌ Don't use SecByteBlock for:

1. **Public Keys** - Not secret, use std::vector
2. **Ciphertext** - Not secret, use std::string
3. **Hashes** - Not secret, use std::string
4. **Random IVs** - Not secret (but keys are!)
5. **Large Data** - Zeroing overhead matters for MB+ sizes

**Rule:** If it's secret and small (< 1KB), use SecByteBlock.

## See Also

- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Generate random keys
- [Security Concepts](/docs/guides/security-concepts/) - Understanding key management
- All algorithm APIs accept SecByteBlock for key parameters
