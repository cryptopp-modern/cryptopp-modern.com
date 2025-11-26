---
title: ECDSA
description: Elliptic Curve Digital Signature Algorithm (ECDSA) API reference
weight: 4
---

**Header:** `#include <cryptopp/eccrypto.h>` and `#include <cryptopp/oids.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 3.2 (RFC 6979 deterministic since 6.0)
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature scheme based on elliptic curve cryptography. It provides the same security as RSA with much smaller key sizes, making it widely used in TLS, code signing, and cryptocurrencies.

## Quick Example

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate ECDSA key pair using P-256 (secp256r1)
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Create signer and verifier
    ECDSA<ECP, SHA256>::Signer signer(privateKey);
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    // Sign message
    std::string message = "Hello, World!";
    std::string signature;

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    // Verify signature
    bool valid = false;
    StringSource(signature + message, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid))
        )
    );

    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;
    std::cout << "Signature size: " << signature.size() << " bytes" << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="info" >}}
**Do:**
- Use P-256 (secp256r1) for general purpose, P-384 for higher security
- Use deterministic ECDSA (RFC 6979) when possible for reproducible signatures
- Verify curve parameters when loading keys from untrusted sources
- Use SHA-256 or stronger with ECDSA

**Avoid:**
- Using ECDSA for new applications when Ed25519 is an option (Ed25519 is simpler)
- Using P-192 or smaller curves (deprecated, insufficient security)
- Using SHA-1 with ECDSA (use SHA-256 or stronger)
- Reusing nonces (catastrophic security failure)
{{< /callout >}}

## Supported Curves

| Curve | OID | Security | Key Size | Signature Size |
|-------|-----|----------|----------|----------------|
| **P-256** (secp256r1) | `ASN1::secp256r1()` | ~128-bit | 64 bytes | 64 bytes |
| **P-384** (secp384r1) | `ASN1::secp384r1()` | ~192-bit | 96 bytes | 96 bytes |
| **P-521** (secp521r1) | `ASN1::secp521r1()` | ~256-bit | 132 bytes | 132 bytes |

## Class Templates

### ECDSA<EC, H>

Standard ECDSA signature scheme.

```cpp
template <class EC, class H>
struct ECDSA;

// Common instantiations:
ECDSA<ECP, SHA256>  // P-curves with SHA-256
ECDSA<ECP, SHA384>  // P-curves with SHA-384
ECDSA<ECP, SHA512>  // P-curves with SHA-512
```

**Template Parameters:**
- `EC` - Elliptic curve type (`ECP` for prime curves)
- `H` - Hash algorithm (`SHA256`, `SHA384`, `SHA512`)

### ECDSA_RFC6979<EC, H>

Deterministic ECDSA per RFC 6979 (no random nonce needed).

```cpp
template <class EC, class H>
struct ECDSA_RFC6979;

// Common instantiations:
ECDSA_RFC6979<ECP, SHA256>  // Deterministic with SHA-256
```

## Key Generation

### Generate New Key Pair

```cpp
AutoSeededRandomPool rng;

// Method 1: Initialize with curve OID
ECDSA<ECP, SHA256>::PrivateKey privateKey;
privateKey.Initialize(rng, ASN1::secp256r1());

ECDSA<ECP, SHA256>::PublicKey publicKey;
privateKey.MakePublicKey(publicKey);

// Method 2: Using GenerateRandomWithKeySize (bits)
ECDSA<ECP, SHA256>::PrivateKey privateKey2;
privateKey2.GenerateRandomWithKeySize(rng, 256);  // P-256
```

### Validate Keys

```cpp
AutoSeededRandomPool rng;

// Validate private key
bool privateValid = privateKey.Validate(rng, 3);  // Level 3 = thorough

// Validate public key
bool publicValid = publicKey.Validate(rng, 3);
```

### Save and Load Keys

```cpp
// Save private key
FileSink privateFile("private.key");
privateKey.Save(privateFile);

// Save public key
FileSink publicFile("public.key");
publicKey.Save(publicFile);

// Load private key
FileSource privateSource("private.key", true);
ECDSA<ECP, SHA256>::PrivateKey loadedPrivate;
loadedPrivate.Load(privateSource);

// Load public key
FileSource publicSource("public.key", true);
ECDSA<ECP, SHA256>::PublicKey loadedPublic;
loadedPublic.Load(publicSource);
```

## Signing and Verification

### Sign Message

```cpp
ECDSA<ECP, SHA256>::Signer signer(privateKey);

std::string message = "Message to sign";
std::string signature;

StringSource(message, true,
    new SignerFilter(rng, signer,
        new StringSink(signature)
    )
);
```

### Verify Signature

```cpp
ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

bool valid = false;
StringSource(signature + message, true,
    new SignatureVerificationFilter(verifier,
        new ArraySink((byte*)&valid, sizeof(valid))
    )
);

if (!valid) {
    std::cerr << "Invalid signature!" << std::endl;
}
```

### Direct Sign/Verify (without filters)

```cpp
// Sign directly
ECDSA<ECP, SHA256>::Signer signer(privateKey);
size_t sigLen = signer.MaxSignatureLength();
SecByteBlock signature(sigLen);

sigLen = signer.SignMessage(rng,
    (const byte*)message.data(), message.size(),
    signature);
signature.resize(sigLen);

// Verify directly
ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
bool valid = verifier.VerifyMessage(
    (const byte*)message.data(), message.size(),
    signature, signature.size()
);
```

## Complete Example: Deterministic ECDSA (RFC 6979)

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate key pair
    ECDSA_RFC6979<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    ECDSA_RFC6979<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Create deterministic signer (no RNG needed for signing!)
    ECDSA_RFC6979<ECP, SHA256>::Signer signer(privateKey);

    std::string message = "Deterministic signature test";

    // Sign twice - should produce identical signatures
    std::string sig1, sig2;

    StringSource(message, true,
        new SignerFilter(NullRNG(), signer,  // NullRNG - no randomness needed
            new StringSink(sig1)
        )
    );

    StringSource(message, true,
        new SignerFilter(NullRNG(), signer,
            new StringSink(sig2)
        )
    );

    // Signatures are identical (deterministic)
    if (sig1 == sig2) {
        std::cout << "Deterministic signatures match!" << std::endl;
    }

    // Verify
    ECDSA_RFC6979<ECP, SHA256>::Verifier verifier(publicKey);
    bool valid = false;
    StringSource(sig1 + message, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid))
        )
    );

    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Complete Example: Document Signing System

```cpp
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

// Sign a file and save signature
void signFile(const std::string& filename,
              const ECDSA<ECP, SHA256>::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;

    // Read file
    std::string content;
    FileSource(filename.c_str(), true,
        new StringSink(content)
    );

    // Sign
    ECDSA<ECP, SHA256>::Signer signer(privateKey);
    std::string signature;

    StringSource(content, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    // Save signature as hex
    std::string hexSig;
    StringSource(signature, true,
        new HexEncoder(new StringSink(hexSig))
    );

    std::ofstream sigFile(filename + ".sig");
    sigFile << hexSig;

    std::cout << "Signed: " << filename << std::endl;
}

// Verify a file signature
bool verifyFile(const std::string& filename,
                const ECDSA<ECP, SHA256>::PublicKey& publicKey) {
    // Read file
    std::string content;
    FileSource(filename.c_str(), true,
        new StringSink(content)
    );

    // Read signature
    std::string hexSig;
    FileSource((filename + ".sig").c_str(), true,
        new StringSink(hexSig)
    );

    std::string signature;
    StringSource(hexSig, true,
        new HexDecoder(new StringSink(signature))
    );

    // Verify
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
    bool valid = false;

    StringSource(signature + content, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid))
        )
    );

    return valid;
}

int main() {
    AutoSeededRandomPool rng;

    // Generate or load keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Sign document
    signFile("document.pdf", privateKey);

    // Verify document
    if (verifyFile("document.pdf", publicKey)) {
        std::cout << "Document signature verified!" << std::endl;
    } else {
        std::cout << "WARNING: Invalid signature!" << std::endl;
    }

    return 0;
}
```

## Performance

### Benchmarks (Approximate)

| Curve | Key Gen | Sign | Verify |
|-------|---------|------|--------|
| P-256 | 0.5-1 ms | 0.5-1 ms | 1-2 ms |
| P-384 | 1-2 ms | 1-2 ms | 2-4 ms |
| P-521 | 2-4 ms | 2-4 ms | 4-8 ms |

**Platform:** Modern x86-64 CPU

### ECDSA vs Ed25519 vs RSA

| Feature | ECDSA P-256 | Ed25519 | RSA-2048 |
|---------|-------------|---------|----------|
| Key gen | ~1 ms | ~0.05 ms | ~500 ms |
| Sign | ~1 ms | ~0.05 ms | ~5 ms |
| Verify | ~2 ms | ~0.1 ms | ~0.1 ms |
| Private key | 32 bytes | 32 bytes | 256 bytes |
| Public key | 64 bytes | 32 bytes | 256 bytes |
| Signature | 64 bytes | 64 bytes | 256 bytes |
| Security | ~128-bit | ~128-bit | ~112-bit |

## Security

### Security Properties

- **Security level:** Depends on curve (P-256 ≈ 128-bit, P-384 ≈ 192-bit)
- **Signature size:** 2× coordinate size (64 bytes for P-256)
- **Deterministic variant:** RFC 6979 eliminates nonce-related vulnerabilities
- **Standards:** FIPS 186-4, ANSI X9.62, SEC 1

### Security Notes

- **Nonce reuse is catastrophic:** If the same nonce (k) is used twice with the same key, the private key can be recovered. Use RFC 6979 deterministic ECDSA to eliminate this risk.
- **Hash algorithm:** Use SHA-256 or stronger. SHA-1 is deprecated.
- **Key validation:** Always validate keys loaded from external sources.
- **Side-channel attacks:** The implementation uses constant-time operations where possible.

### Nonce Reuse Attack

```cpp
// DANGEROUS: If you ever reuse a nonce with ECDSA, your private key
// can be mathematically recovered from two signatures!
//
// This is why RFC 6979 deterministic ECDSA exists - it derives the
// nonce deterministically from the message and private key, making
// nonce reuse impossible.

// SAFE: Use ECDSA_RFC6979 for deterministic signatures
ECDSA_RFC6979<ECP, SHA256>::Signer signer(privateKey);
```

## ECDSA vs Ed25519

| Aspect | ECDSA | Ed25519 |
|--------|-------|---------|
| Standardization | NIST, widely adopted | Modern, growing adoption |
| Complexity | More complex, nonce-sensitive | Simpler, deterministic |
| Performance | Good | Better (2-10x faster) |
| Key size | P-256: 64 bytes public | 32 bytes public |
| Compatibility | Universal (TLS, X.509, etc.) | Growing (SSH, modern protocols) |
| Recommendation | Use for compatibility | Prefer for new applications |

**Recommendation:** Use Ed25519 for new applications. Use ECDSA when NIST curves are required (compliance, interoperability with existing systems).

## When to Use ECDSA

### ✅ Use ECDSA for:

1. **TLS/SSL Certificates** - Required for NIST compliance
2. **X.509 Certificates** - Standard PKI infrastructure
3. **Code Signing** - Platform requirements (Apple, Microsoft)
4. **Interoperability** - Systems requiring NIST curves
5. **Compliance** - FIPS 186-4, government requirements

### ❌ Don't use ECDSA for:

1. **New Applications** - Prefer Ed25519 (simpler, faster)
2. **Without RFC 6979** - Random nonce ECDSA is risky
3. **With weak hashes** - Never use SHA-1 or MD5

## Exceptions

- `InvalidMaterial` - Invalid key parameters
- `InvalidDataFormat` - Malformed key or signature

## See Also

- [Ed25519](/docs/api/pubkey/ed25519/) - Modern alternative (recommended for new apps)
- [ECDH](/docs/api/pubkey/ecdh/) - Key exchange with same curves
- [RSA](/docs/api/pubkey/rsa/) - Legacy signatures
- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange
