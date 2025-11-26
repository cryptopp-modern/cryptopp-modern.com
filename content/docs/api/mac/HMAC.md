---
title: HMAC
description: HMAC message authentication code API reference
weight: 1
---

**Header:** `#include <cryptopp/hmac.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 2.1

HMAC (Hash-based Message Authentication Code) provides message authentication using a cryptographic hash function and a secret key. It ensures both data integrity and authenticity - verifying that a message came from a legitimate sender and hasn't been tampered with.

## Quick Example

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Secret key (in real code, generate randomly and keep secure)
    byte key[] = "secret-key-2025";
    std::string message = "Hello, World!";
    std::string mac, hexOutput;

    // Create HMAC-SHA256
    HMAC<SHA256> hmac(key, sizeof(key) - 1);

    StringSource(message, true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );

    // Display as hex
    StringSource(mac, true,
        new HexEncoder(new StringSink(hexOutput))
    );

    std::cout << "HMAC-SHA256: " << hexOutput << std::endl;
    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use HMAC for message authentication (verify sender + detect tampering)
- Use SHA-256 or better (HMAC-SHA256, HMAC-SHA512, HMAC-BLAKE3)
- Generate random keys using `AutoSeededRandomPool`
- Use at least 128-bit (16 byte) keys
- Use constant-time comparison for MAC verification
- Store keys securely using `SecByteBlock`

**Avoid:**
- Using HMAC-SHA1 or HMAC-MD5 for new systems (use SHA-256+)
- Short keys (< 16 bytes) - weakens security
- Using HMAC for password hashing (use Argon2 instead)
- String comparison for MAC verification (timing attacks)
- Hardcoded keys (shown in examples for clarity only)
{{< /callout >}}

## Template Class: HMAC<T>

Template class for creating HMAC with different hash functions.

**Template Parameter:**
- `T` - Hash function class (e.g., `SHA256`, `SHA512`, `BLAKE3`)

**Common Instantiations:**
- `HMAC<SHA256>` - HMAC-SHA256 (recommended)
- `HMAC<SHA512>` - HMAC-SHA512 (recommended)
- `HMAC<BLAKE3>` - HMAC-BLAKE3 (fastest)
- `HMAC<SHA3_256>` - HMAC-SHA3-256
- `HMAC<SHA1>` - HMAC-SHA1 (legacy only)

### Constants

```cpp
// For HMAC<SHA256>
static const int DIGESTSIZE = 32;    // MAC output size (32 bytes for SHA256)
static const int BLOCKSIZE = 64;     // Internal block size (64 bytes for SHA256)
static const int DEFAULT_KEYLENGTH = 16;  // Minimum recommended key size
```

### Constructors

#### Default Constructor

```cpp
HMAC();
```

Create an HMAC object. Must call `SetKey()` before use.

**Example:**

```cpp
HMAC<SHA256> hmac;
byte key[32];  // 256-bit key
// ... generate key ...
hmac.SetKey(key, sizeof(key));
```

#### Constructor with Key

```cpp
HMAC(const byte* key, size_t length);
```

Create and initialize HMAC with a key.

**Parameters:**
- `key` - Secret key for HMAC
- `length` - Key length in bytes (default: 16, recommended: 32+)

**Example:**

```cpp
byte key[32];
AutoSeededRandomPool rng;
rng.GenerateBlock(key, sizeof(key));

HMAC<SHA256> hmac(key, sizeof(key));
```

## Methods

### SetKey()

```cpp
void SetKey(const byte* key, size_t length,
            const NameValuePairs& params = g_nullNameValuePairs);
```

Set or change the HMAC key.

**Parameters:**
- `key` - Secret key
- `length` - Key length (recommended: 32+ bytes)
- `params` - Optional parameters (usually unused)

**Thread Safety:** Not thread-safe. Don't call while computing MAC.

**Example:**

```cpp
HMAC<SHA256> hmac;
byte key[32];
// ... initialize key ...
hmac.SetKey(key, sizeof(key));
```

### Update()

```cpp
void Update(const byte* input, size_t length);
```

Add data to the MAC computation.

**Parameters:**
- `input` - Data to authenticate
- `length` - Length of data in bytes

**Can be called multiple times** to process data in chunks.

**Example:**

```cpp
HMAC<SHA256> hmac(key, keyLen);
hmac.Update((const byte*)"Part 1", 6);
hmac.Update((const byte*)"Part 2", 6);
// Equivalent to: hmac.Update((const byte*)"Part 1Part 2", 12);
```

### Final()

```cpp
void Final(byte* mac);
```

Finalize MAC computation and get result.

**Parameters:**
- `mac` - Output buffer (size: `DigestSize()` bytes)

**Note:** Automatically calls `Restart()` after completion.

**Example:**

```cpp
HMAC<SHA256> hmac(key, keyLen);
hmac.Update((const byte*)message.data(), message.size());

byte mac[HMAC<SHA256>::DIGESTSIZE];
hmac.Final(mac);
```

### TruncatedFinal()

```cpp
void TruncatedFinal(byte* mac, size_t size);
```

Get a truncated MAC (first `size` bytes).

**Parameters:**
- `mac` - Output buffer
- `size` - Number of bytes to output (≤ DigestSize())

**Use case:** Some protocols require shorter MACs (e.g., 128-bit instead of 256-bit).

**Example:**

```cpp
HMAC<SHA256> hmac(key, keyLen);
hmac.Update((const byte*)data, dataLen);

byte mac[16];  // Truncated to 128 bits
hmac.TruncatedFinal(mac, 16);
```

### Restart()

```cpp
void Restart();
```

Reset MAC computation to initial state. Keeps the same key.

**Example:**

```cpp
HMAC<SHA256> hmac(key, keyLen);

// Compute MAC for message 1
hmac.Update((const byte*)msg1.data(), msg1.size());
byte mac1[32];
hmac.Final(mac1);

// Reuse same HMAC object for message 2
hmac.Update((const byte*)msg2.data(), msg2.size());
byte mac2[32];
hmac.Final(mac2);
```

### VerifyMAC() - Static

```cpp
bool VerifyMAC(const byte* mac, size_t macLength,
               const byte* input, size_t inputLength,
               const byte* key, size_t keyLength);
```

One-shot verification helper (uses constant-time comparison).

**Parameters:**
- `mac` - MAC to verify
- `macLength` - MAC length
- `input` - Original message
- `inputLength` - Message length
- `key` - Secret key
- `keyLength` - Key length

**Returns:** `true` if MAC is valid, `false` otherwise

**Example:**

```cpp
bool valid = HMAC<SHA256>::VerifyMAC(
    receivedMAC, sizeof(receivedMAC),
    message.data(), message.size(),
    key, keyLen
);

if (!valid) {
    std::cerr << "MAC verification failed - message tampered!" << std::endl;
}
```

### DigestSize()

```cpp
unsigned int DigestSize() const;
```

Get MAC output size in bytes.

**Returns:** MAC size (32 for SHA256, 64 for SHA512, etc.)

### AlgorithmName()

```cpp
std::string AlgorithmName() const;
```

Get algorithm name.

**Returns:** String like "HMAC(SHA-256)" or "HMAC(BLAKE3)"

## Complete Example: API Authentication

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <sstream>

using namespace CryptoPP;

// Generate API request signature
std::string signRequest(const std::string& method,
                       const std::string& path,
                       const std::string& body,
                       const byte* apiKey, size_t keyLen) {
    // Combine request components
    std::ostringstream oss;
    oss << method << "\n" << path << "\n" << body;
    std::string message = oss.str();

    // Compute HMAC-SHA256
    HMAC<SHA256> hmac(apiKey, keyLen);
    std::string mac, signature;

    StringSource(message, true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );

    // Encode as hex
    StringSource(mac, true,
        new HexEncoder(new StringSink(signature))
    );

    return signature;
}

// Verify API request signature (constant-time)
bool verifyRequest(const std::string& method,
                   const std::string& path,
                   const std::string& body,
                   const std::string& receivedSig,
                   const byte* apiKey, size_t keyLen) {
    // Rebuild message
    std::ostringstream oss;
    oss << method << "\n" << path << "\n" << body;
    std::string message = oss.str();

    // Decode received signature (hex -> bytes)
    std::string receivedMAC;
    StringSource(receivedSig, true,
        new HexDecoder(new StringSink(receivedMAC))
    );

    // One-shot verification (constant-time)
    return HMAC<SHA256>::VerifyMAC(
        reinterpret_cast<const byte*>(receivedMAC.data()), receivedMAC.size(),
        reinterpret_cast<const byte*>(message.data()), message.size(),
        apiKey, keyLen
    );
}

int main() {
    // Generate API key
    AutoSeededRandomPool rng;
    SecByteBlock apiKey(32);
    rng.GenerateBlock(apiKey, apiKey.size());

    // Client: Sign request
    std::string signature = signRequest(
        "POST",
        "/api/v1/transfer",
        "{\"amount\":100,\"to\":\"user123\"}",
        apiKey, apiKey.size()
    );

    std::cout << "Signature: " << signature << std::endl;

    // Server: Verify request
    bool valid = verifyRequest(
        "POST",
        "/api/v1/transfer",
        "{\"amount\":100,\"to\":\"user123\"}",
        signature,
        apiKey, apiKey.size()
    );

    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Complete Example: File Integrity

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

// Generate HMAC for a file
std::string hmacFile(const std::string& filename, const SecByteBlock& key) {
    HMAC<SHA256> hmac(key, key.size());
    std::string mac, hexOutput;

    FileSource(filename.c_str(), true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );

    StringSource(mac, true,
        new HexEncoder(new StringSink(hexOutput))
    );

    return hexOutput;
}

// Verify file integrity (constant-time)
bool verifyFile(const std::string& filename,
                const std::string& expectedHMACHex,
                const SecByteBlock& key) {
    // Recompute HMAC as raw bytes
    HMAC<SHA256> hmac(key, key.size());
    std::string mac;
    FileSource(filename.c_str(), true,
        new HashFilter(hmac, new StringSink(mac))
    );

    // Decode expected hex to bytes
    std::string expectedMAC;
    StringSource(expectedHMACHex, true,
        new HexDecoder(new StringSink(expectedMAC))
    );

    // Constant-time verification
    return HMAC<SHA256>::VerifyMAC(
        reinterpret_cast<const byte*>(expectedMAC.data()), expectedMAC.size(),
        reinterpret_cast<const byte*>(mac.data()), mac.size(),
        key, key.size()
    );
}

int main() {
    // Generate key
    AutoSeededRandomPool rng;
    SecByteBlock key(32);
    rng.GenerateBlock(key, key.size());

    // Compute HMAC for file
    std::string hmac = hmacFile("document.txt", key);
    std::cout << "HMAC: " << hmac << std::endl;

    // Save HMAC
    std::ofstream out("document.txt.hmac");
    out << hmac;
    out.close();

    // Later: Verify file hasn't been tampered with
    std::ifstream in("document.txt.hmac");
    std::string savedHMAC;
    in >> savedHMAC;

    if (verifyFile("document.txt", savedHMAC, key)) {
        std::cout << "File integrity verified" << std::endl;
    } else {
        std::cout << "WARNING: File has been modified!" << std::endl;
    }

    return 0;
}
```

## HMAC Variants

### HMAC-SHA256 (Recommended)

```cpp
HMAC<SHA256> hmac(key, keyLen);
// Output: 256 bits (32 bytes)
// Security: up to 128-bit collision resistance; MAC forgery ~2^(-t) for t-bit tag
```

**Use for:** Most applications, API authentication, file integrity

### HMAC-SHA512 (Recommended)

```cpp
HMAC<SHA512> hmac(key, keyLen);
// Output: 512 bits (64 bytes)
// Security: up to 256-bit collision/preimage resistance; MAC forgery ~2^(-t) for t-bit tag
```

**Use for:** High-security applications, long-term authentication

### HMAC-BLAKE3 (Fastest)

```cpp
HMAC<BLAKE3> hmac(key, keyLen);
// Output: 256 bits (32 bytes)
// Security: ~128-bit security target (per BLAKE3 spec) for all goals
// Speed: 2-4x faster than HMAC-SHA256
```

**Use for:** High-throughput applications, performance-critical systems

**Note:** BLAKE3 also has its own built-in keyed mode, which may be preferable in some designs depending on your protocol and API needs.

### HMAC-SHA3-256

```cpp
HMAC<SHA3_256> hmac(key, keyLen);
// Output: 256 bits (32 bytes)
// Security: up to 128-bit collision resistance; MAC forgery ~2^(-t) for t-bit tag
```

**Use for:** Compliance requirements, diversity from SHA-2

### HMAC-SHA1 (Legacy)

```cpp
HMAC<SHA1> hmac(key, keyLen);
// Output: 160 bits (20 bytes)
// Security: WEAK - SHA1 collision resistance is broken
```

**Use for:** Legacy systems only. Migrate to HMAC-SHA256.

## Performance

### Benchmarks (Approximate)

| Algorithm | Speed (MB/s) | Notes |
|-----------|--------------|-------|
| HMAC-BLAKE3 | 3000-6000 | Fastest |
| HMAC-SHA256 | 800-1500 | Hardware accelerated (SHA-NI) |
| HMAC-SHA512 | 600-1200 | Faster on 64-bit systems |
| HMAC-SHA3-256 | 300-600 | Software implementation |
| HMAC-SHA1 | 1000-2000 | Fast but insecure |

**Hardware Acceleration:**
- Intel/AMD: SHA Extensions (SHA-NI) accelerates HMAC-SHA256/SHA512
- ARM: SHA Extensions accelerate HMAC-SHA256/SHA512
- No acceleration: HMAC-BLAKE3 is fastest

## Security

### Security Properties

- **Primitive:** HMAC is a message authentication code (MAC) built from a cryptographic hash function. In Crypto++, `HMAC<T>` takes any `HashTransformation` (e.g. `SHA256`, `SHA512`, `BLAKE3`).

- **Tag size:**
  - The MAC tag length defaults to the full hash output size (e.g. 32 bytes for SHA-256, 64 bytes for SHA-512).
  - Tags may be truncated; forging probability then scales with the tag length (approximately 2^(-t) for a t-bit tag, assuming other limits are respected).

- **Security level / bounds:**
  - HMAC security is primarily governed by the hash function's PRF / compression-function properties and the tag length you use.
  - With a t-bit tag and proper key management, generic forgery attacks require about 2^t work.
  - For hashes with 256-bit output (SHA-256, BLAKE3), a 128-bit tag already gives a comfortable margin for most applications.

- **Key sizes:**
  - Recommended HMAC key length: **at least 128 bits**, typically 256 bits for SHA-256 / SHA-512.
  - Keys longer than the hash block size are first hashed internally; very long keys do not meaningfully increase security beyond the tag length and hash strength.

- **Deterministic MAC:** HMAC is deterministic: for a fixed key and message, the tag is always the same. There is no nonce or IV in the scheme itself.

- **Underlying hash assumptions:**
  - HMAC remains secure even if the hash has weaknesses in collision resistance, as long as its compression function behaves like a pseudorandom function.
  - You should still choose modern, standard hashes (`SHA256`, `SHA512`, `BLAKE3`) and avoid obsolete ones (e.g. `MD5`, `SHA1`).

- **Standard:** RFC 2104, FIPS 198-1

### Security Best Practices

- **Choice of hash function:**
  - Prefer `HMAC<SHA256>` for general use.
  - Use `HMAC<SHA512>` where you want larger tags or are already standardised on SHA-512.
  - `HMAC<BLAKE3>` is suitable when you need very high speed and are comfortable with BLAKE3's security model; note that BLAKE3 also has its own keyed mode, which may be preferable in some designs.

- **Key generation and management:**
  - Generate keys with a CSPRNG (e.g. `AutoSeededRandomPool`) and never derive them from predictable values.
  - Do not reuse the same key across different MAC algorithms (e.g. HMAC and CMAC), or for both MAC and encryption.
  - Use a KDF or key hierarchy to derive distinct sub-keys per purpose (encryption, MAC, KDF, etc.).

  ```cpp
  AutoSeededRandomPool rng;
  SecByteBlock key(32);  // 256-bit key
  rng.GenerateBlock(key, key.size());
  ```

- **Tag length:**
  - Use at least **128-bit** tags for new designs.
  - Truncating to 128 bits from a longer hash (like SHA-256 or SHA-512) is a common and safe pattern.
  - If you truncate further (e.g. 64 or 96 bits), understand that your forgery resistance becomes roughly 2^(-t) for a t-bit tag.

- **Verification (constant-time checks):**
  - Never compare MAC tags with `operator==` on `std::string` or raw buffers.
  - Use `HMAC<T>::VerifyMAC` or another constant-time comparison routine so that the runtime does not leak how many bytes matched.

  ```cpp
  // WRONG - timing attack vulnerable
  if (computedMAC == receivedMAC) { /* ... */ }

  // CORRECT - use static VerifyMAC (constant-time)
  bool valid = HMAC<SHA256>::VerifyMAC(
      receivedMAC, macLen,
      message, msgLen,
      key, keyLen
  );
  ```

- **Key storage:**
  ```cpp
  SecByteBlock key(32);  // Auto-zeroes on destruction
  // NOT: byte key[32];   // Leaves key in memory
  ```

- **Protocol context and replay:**
  - Because HMAC is deterministic, you must handle replay protection at the protocol level (sequence numbers, nonces/counters, timestamps, etc.).
  - When authenticating structured messages, include all relevant context in the MAC input (e.g. method, path, headers, direction, protocol version) to prevent tags being replayed in a different context.

- **Usage limits:**
  - There is no strict "block count" limit like a block cipher mode, but you should still re-key periodically in long-lived systems.
  - Avoid designs where an attacker can obtain an unbounded number of MACs under the same key on fully attacker-chosen messages, unless this is required and analysed.

- **Do not use HMAC as a password hash:**
  - HMAC is fast by design. For password storage, use a dedicated password hashing / KDF scheme (e.g. Argon2) and keep HMAC for message authentication.

- **No confidentiality:**
  - HMAC provides integrity and authenticity only. It does not encrypt or hide the message.
  - For authenticated encryption, use an AEAD construction (e.g. AES-GCM, ChaCha20-Poly1305) rather than "encrypt + HMAC" unless your protocol is explicitly designed and reviewed for that pattern.

### Test Vectors (RFC 2104)

```cpp
// HMAC-SHA256 Test Case 1
byte key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
};

std::string message = "Hi There";

// Expected HMAC-SHA256:
// b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7

HMAC<SHA256> hmac(key, sizeof(key));
std::string mac;
StringSource(message, true,
    new HashFilter(hmac, new StringSink(mac))
);
```

## Common Patterns

### Encrypt-then-MAC

Correct way to combine encryption and authentication:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

void encryptThenMAC(const std::string& plaintext,
                    const SecByteBlock& encKey,
                    const SecByteBlock& macKey,
                    const byte* iv,
                    std::string& ciphertext,
                    std::string& mac) {
    // 1. Encrypt
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(encKey, encKey.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)
        )
    );

    // 2. MAC the ciphertext (not plaintext!)
    HMAC<SHA256> hmac(macKey, macKey.size());
    StringSource(ciphertext, true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );
}

// Note: In practice, use AES-GCM instead (provides encryption + MAC in one)
```

### JWT-style Token

```cpp
std::string createToken(const std::string& header,
                       const std::string& payload,
                       const SecByteBlock& key) {
    std::string data = header + "." + payload;

    // Compute signature
    HMAC<SHA256> hmac(key, key.size());
    std::string mac, signature;

    StringSource(data, true,
        new HashFilter(hmac, new StringSink(mac))
    );

    StringSource(mac, true,
        new Base64Encoder(new StringSink(signature), false)  // URL-safe base64
    );

    return data + "." + signature;
}
```

## Thread Safety

**Not thread-safe.** Create separate `HMAC` objects for each thread.

```cpp
// WRONG - sharing between threads
HMAC<SHA256> shared_hmac(key, keyLen);

// CORRECT - one per thread
void threadFunc() {
    HMAC<SHA256> hmac(key, keyLen);  // Thread-local
    // ... use hmac ...
}
```

## Exceptions

- `InvalidKeyLength` - Key length is invalid (rarely thrown - HMAC accepts most key sizes)

## When to Use HMAC

### ✅ Use HMAC for:

1. **API Authentication** - Signing API requests
2. **File Integrity** - Detecting file tampering
3. **Message Authentication** - Verifying message sender
4. **Encrypt-then-MAC** - Adding authentication to encryption (though AES-GCM is better)
5. **Challenge-Response** - Authentication protocols
6. **Key Derivation** - HKDF uses HMAC internally

### ❌ Don't use HMAC for:

1. **Password Hashing** - Use Argon2 instead
2. **Digital Signatures** - Use Ed25519/RSA instead (HMAC requires shared secret)
3. **Checksums** - Use hash functions (SHA-256) if authentication not needed

## HMAC vs Alternatives

| Feature | HMAC | CMAC | Poly1305 | GCM |
|---------|------|------|----------|-----|
| Type | Hash-based | Block cipher-based | Universal hash | AEAD mode |
| Speed | Fast | Medium | Very Fast | Very Fast |
| Key type | Symmetric | Symmetric | Symmetric | Symmetric |
| Common use | API auth | CBC-MAC | ChaCha20-Poly1305 | AES-GCM |
| Standard | RFC 2104 | NIST SP 800-38B | RFC 7539 | NIST SP 800-38D |

## See Also

- [HMAC Guide](/docs/algorithms/hmac/) - Conceptual overview
- [Message Authentication](/docs/api/mac/) - Other MAC algorithms
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption (better than HMAC + encryption)
- [Security Concepts](/docs/guides/security-concepts/) - Understanding MACs vs signatures
- [HKDF](/docs/api/kdf/hkdf/) - Key derivation using HMAC
