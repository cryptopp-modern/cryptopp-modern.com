---
title: AutoSeededRandomPool
description: Cryptographically secure random number generator API reference
weight: 1
---

**Header:** `#include <cryptopp/osrng.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.0

AutoSeededRandomPool is a cryptographically secure random number generator (CSPRNG) that automatically seeds itself from the operating system's entropy source. It's the primary RNG you should use for generating keys, IVs, salts, and nonces.

## Quick Example

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate random bytes
    byte key[32];
    rng.GenerateBlock(key, sizeof(key));

    // Generate random integer
    unsigned int randomNum = rng.GenerateWord32();

    // Display as hex
    std::string hexOutput;
    HexEncoder encoder(new StringSink(hexOutput));
    encoder.Put(key, sizeof(key));
    encoder.MessageEnd();

    std::cout << "Random key: " << hexOutput << std::endl;
    std::cout << "Random int: " << randomNum << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use AutoSeededRandomPool for all cryptographic random needs
- Create one instance per thread (or use mutex protection)
- Generate keys, IVs, salts, and nonces with GenerateBlock()
- Reseed after fork() in multi-process applications
- Store in secure memory if RNG state is sensitive

**Avoid:**
- Using std::rand() or std::mt19937 for cryptography (NOT secure)
- Sharing RNG instance across threads without synchronization
- Manual seeding (automatic seeding is cryptographically secure)
- Using for non-cryptographic purposes (overkill, use `<random>` e.g. `std::mt19937` instead)
{{< /callout >}}

## Class: AutoSeededRandomPool

Cryptographically secure random number generator with automatic OS seeding.

### Constructors

#### Default Constructor

```cpp
AutoSeededRandomPool(bool blocking = false, unsigned int seedSize = 32);
```

Create and automatically seed a random pool.

**Parameters:**
- `blocking` - Use blocking entropy source (default: false)
  - `false` = Use `/dev/urandom` (Linux/Mac) or `CryptGenRandom` (Windows) - non-blocking
  - `true` = Use `/dev/random` (Linux) - may block if entropy is low
- `seedSize` - Seed size in bytes (default: 32 = 256 bits)

**Note:** Non-blocking (default) is recommended for almost all use cases.

**Example:**

```cpp
AutoSeededRandomPool rng;  // Non-blocking, 256-bit seed

// For applications requiring blocking entropy (rare):
AutoSeededRandomPool blocking_rng(true, 32);
```

## Methods

### GenerateBlock()

```cpp
void GenerateBlock(byte* output, size_t size);
```

Generate a block of random bytes.

**Parameters:**
- `output` - Output buffer
- `size` - Number of bytes to generate

**Thread Safety:** Not thread-safe. Use separate RNG per thread or mutex.

**Example:**

```cpp
AutoSeededRandomPool rng;

// Generate AES-256 key
byte aesKey[32];
rng.GenerateBlock(aesKey, sizeof(aesKey));

// Generate IV
byte iv[16];
rng.GenerateBlock(iv, sizeof(iv));

// Generate salt
byte salt[32];
rng.GenerateBlock(salt, sizeof(salt));
```

### GenerateByte()

```cpp
byte GenerateByte();
```

Generate a single random byte.

**Returns:** Random byte (0-255)

**Example:**

```cpp
AutoSeededRandomPool rng;
byte randomByte = rng.GenerateByte();
```

### GenerateWord32()

```cpp
word32 GenerateWord32(word32 min = 0, word32 max = 0xFFFFFFFFUL);
```

Generate a random 32-bit integer.

**Parameters:**
- `min` - Minimum value (inclusive, default: 0)
- `max` - Maximum value (inclusive, default: max uint32)

**Returns:** Random integer in range [min, max]

**Example:**

```cpp
AutoSeededRandomPool rng;

// Generate random uint32
word32 random = rng.GenerateWord32();

// Generate random integer in range [1, 100]
word32 dice = rng.GenerateWord32(1, 100);

// Generate random boolean
bool coinFlip = rng.GenerateWord32(0, 1);
```

### Reseed()

```cpp
void Reseed(bool blocking = false, unsigned int seedSize = 32);
```

Reseed the RNG from OS entropy source.

**Parameters:**
- `blocking` - Use blocking entropy (default: false)
- `seedSize` - Seed size in bytes (default: 32)

**When to reseed:**
- After `fork()` in Unix (avoid duplicate RNG state in child process)
- Paranoid applications (not normally necessary)

**Example:**

```cpp
AutoSeededRandomPool rng;

// Generate some random data...

// Reseed (rarely needed)
rng.Reseed();

// After fork() - IMPORTANT
pid_t pid = fork();
if (pid == 0) {
    // Child process
    rng.Reseed();  // Avoid same RNG state as parent
    // ... use rng ...
}
```

### IncorporateEntropy()

```cpp
void IncorporateEntropy(const byte* input, size_t length);
```

Mix additional entropy into the RNG.

**Parameters:**
- `input` - Additional entropy bytes
- `length` - Length of input

**Use case:** Adding external entropy sources (usually not needed).

**Example:**

```cpp
AutoSeededRandomPool rng;

// Add extra entropy from external source
byte extraEntropy[32];
// ... get from hardware RNG, timing, etc. ...
rng.IncorporateEntropy(extraEntropy, sizeof(extraEntropy));
```

## Complete Example: Key Generation

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

void generateKeys() {
    AutoSeededRandomPool rng;

    // Generate AES-256 key
    SecByteBlock aesKey(32);
    rng.GenerateBlock(aesKey, aesKey.size());

    // Generate HMAC key
    SecByteBlock hmacKey(32);
    rng.GenerateBlock(hmacKey, hmacKey.size());

    // Generate salt for password hashing
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));

    // Generate IV for AES-GCM
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Display keys (in real app, use securely!)
    std::string hexKey;
    StringSource(aesKey, aesKey.size(), true,
        new HexEncoder(new StringSink(hexKey))
    );

    std::cout << "AES-256 Key: " << hexKey << std::endl;
    std::cout << "Key size: " << aesKey.size() << " bytes" << std::endl;
}

int main() {
    generateKeys();
    return 0;
}
```

## Complete Example: Random Token Generation

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

// Generate URL-safe random token (for session IDs, API keys, etc.)
std::string generateToken(size_t bytes = 32) {
    AutoSeededRandomPool rng;

    byte buffer[64];  // Max 64 bytes
    if (bytes > sizeof(buffer)) bytes = sizeof(buffer);

    rng.GenerateBlock(buffer, bytes);

    // Encode as URL-safe base64
    std::string token;
    Base64URLEncoder encoder(new StringSink(token), false);
    encoder.Put(buffer, bytes);
    encoder.MessageEnd();

    return token;
}

int main() {
    // Generate session ID (128-bit)
    std::string sessionId = generateToken(16);
    std::cout << "Session ID: " << sessionId << std::endl;

    // Generate API key (256-bit)
    std::string apiKey = generateToken(32);
    std::cout << "API Key: " << apiKey << std::endl;

    // Generate CSRF token (128-bit)
    std::string csrfToken = generateToken(16);
    std::cout << "CSRF Token: " << csrfToken << std::endl;

    return 0;
}
```

## Complete Example: Thread-Safe Usage

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <thread>
#include <vector>
#include <iostream>

using namespace CryptoPP;

// CORRECT - each thread has its own RNG
void workerThread(int threadId) {
    AutoSeededRandomPool rng;  // Thread-local RNG

    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    std::cout << "Thread " << threadId << " generated key" << std::endl;
}

int main() {
    std::vector<std::thread> threads;

    // Spawn 4 threads, each with own RNG
    for (int i = 0; i < 4; i++) {
        threads.emplace_back(workerThread, i);
    }

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
```

## Entropy Sources

AutoSeededRandomPool uses the best available OS entropy source:

| Platform | Entropy Source | Notes |
|----------|---------------|-------|
| **Windows** | BCryptGenRandom / CryptGenRandom | CNG API (Win Vista+) or CryptoAPI |
| **Linux** | /dev/urandom | Non-blocking, cryptographically secure |
| **macOS** | /dev/urandom | Non-blocking, cryptographically secure |
| **FreeBSD** | /dev/urandom | Non-blocking |
| **Other Unix** | /dev/urandom or /dev/random | Falls back to available source |

### Blocking vs Non-Blocking

```cpp
// Non-blocking (RECOMMENDED for almost all uses)
AutoSeededRandomPool rng(false);  // Uses /dev/urandom
// - Always returns immediately
// - Cryptographically secure
// - Used by SSH, TLS, GPG, etc.

// Blocking (rarely needed)
AutoSeededRandomPool rng(true);   // Uses /dev/random
// - May block if entropy is low
// - Only needed for:
//   * Long-term key generation
//   * High-security environments
//   * Compliance requirements
```

## Performance

### Benchmarks (Approximate)

| Operation | Speed | Notes |
|-----------|-------|-------|
| GenerateBlock() | 100-500 MB/s | Uses AES-CTR internally |
| GenerateWord32() | ~25 million/sec | Single 32-bit ints |
| Initialization | <1 ms | Automatic OS seeding |
| Reseed() | <1 ms | Re-seed from OS |

**Note:** Much faster than directly calling OS RNG due to internal buffering.

## Security

### Security Properties

- **Cryptographically secure CSPRNG** – Designed for key/IV/salt/token generation and built on the same random-pool design used by upstream Crypto++.
- **Unpredictable outputs** – Given current public knowledge, predicting future outputs from past outputs should be computationally infeasible for an attacker without access to the internal state.
- **State mixing and diffusion** – New entropy is mixed into an internal pool before output is generated, helping to limit the impact of partial state exposure.
- **OS-backed seeding** – Initial seeding (and any explicit reseeding) comes from the operating system's cryptographic RNG, rather than from user-supplied seeds.

### Security Best Practices

1. **Don't Use std::rand():**
   ```cpp
   // WRONG - NOT cryptographically secure
   int random = std::rand();

   // CORRECT
   AutoSeededRandomPool rng;
   word32 random = rng.GenerateWord32();
   ```

2. **Thread Safety:**
   ```cpp
   // WRONG - shared across threads
   AutoSeededRandomPool global_rng;

   void thread1() { global_rng.GenerateBlock(...); }  // RACE CONDITION
   void thread2() { global_rng.GenerateBlock(...); }

   // CORRECT - thread-local
   void thread1() {
       AutoSeededRandomPool rng;  // Per-thread
       rng.GenerateBlock(...);
   }
   ```

3. **Fork() Safety:**
   ```cpp
   AutoSeededRandomPool rng;

   pid_t pid = fork();
   if (pid == 0) {
       // IMPORTANT: Reseed in child process
       rng.Reseed();
       // Now child has different RNG state than parent
   }
   ```

4. **Seed Size:**
   ```cpp
   // Default 256-bit seed is sufficient for all uses
   AutoSeededRandomPool rng;  // 256-bit seed

   // Larger seeds don't improve security
   // (internal state is already well-seeded)
   ```

## When to Use AutoSeededRandomPool

### ✅ Use AutoSeededRandomPool for:

1. **Key Generation** - AES, HMAC, RSA, etc.
2. **IV/Nonce Generation** - For encryption algorithms
3. **Salt Generation** - For password hashing
4. **Token Generation** - Session IDs, CSRF tokens, API keys
5. **Challenge Generation** - For authentication protocols
6. **Any Cryptographic Random Needs**

### ❌ Don't use AutoSeededRandomPool for:

1. **Simulations** - Use `std::mt19937` (repeatable, faster)
2. **Games** - Use `std::random_device` + `std::mt19937` (faster)
3. **Monte Carlo** - Use `std::mt19937` (faster, reproducible)
4. **Shuffling non-sensitive data** - Use `std::shuffle` (faster)

**Rule:** Use AutoSeededRandomPool if security matters, otherwise use `<random>` (e.g. `std::mt19937`).

## RNG Comparison

| RNG | Speed | Cryptographic | Reproducible | Use Case |
|-----|-------|---------------|--------------|----------|
| **AutoSeededRandomPool** | Fast | ✅ Yes | ❌ No | Cryptography ⭐ |
| std::rand() | Fast | ❌ NO | ✅ Yes | Toys only |
| std::mt19937 | Very Fast | ❌ NO | ✅ Yes | Simulations |
| std::random_device | Slow | ✅ Yes | ❌ No | Seeding only |
| NonblockingRng | Medium | ✅ Yes | ❌ No | Direct OS access |

## Thread Safety

**Not thread-safe.** Use one of these approaches:

### Option 1: Thread-Local RNG (Recommended)

```cpp
void threadFunc() {
    AutoSeededRandomPool rng;  // Each thread has own RNG
    // ... use rng ...
}
```

### Option 2: Thread-Local Storage

```cpp
thread_local AutoSeededRandomPool rng;  // C++11
```

### Option 3: Mutex Protection

```cpp
std::mutex rng_mutex;
AutoSeededRandomPool global_rng;

void generateKey(byte* key, size_t len) {
    std::lock_guard<std::mutex> lock(rng_mutex);
    global_rng.GenerateBlock(key, len);
}
```

## Exceptions

- `OS_RNG_Err` - Unable to access OS entropy source (rare)

## Implementation Details

- **Design:** AutoSeededRandomPool wraps Crypto++'s random-pool generator (a PGP-style design) and seeds it from the operating system's CSPRNG.
- **Core primitive:** The underlying pool uses AES-256 to generate a stream of pseudo-random bytes, with entropy stirred in using SHA-256 (per upstream `RandomPool` design).
- **Seeding:** On construction (and when `Reseed()` is called), the pool is initialised from the OS RNG (for example `/dev/urandom` on Unix-like systems or the Windows CNG/CryptoAPI RNG on Windows).
- **Internal state:** The generator keeps an internal pool of bytes that it refills from its own cipher state; the exact size and layout of this pool are an implementation detail and may change between versions.
- **FIPS note:** cryptopp-modern is **not** a FIPS-validated module. If you require formal FIPS 140-2/140-3 validation, you must use a separately validated cryptographic module.

## See Also

- [Security Concepts](/docs/guides/security-concepts/) - Understanding random number generation
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure memory for keys
- [HKDF](/docs/api/kdf/hkdf/) - Derive keys from random seeds (coming soon)
- Examples on this site use `AutoSeededRandomPool` for key generation, but any suitable CSPRNG with comparable security is acceptable
