---
title: SignerFilter / SignatureVerificationFilter
description: Pipeline filters for digital signature generation and verification
weight: 9
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 2.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

SignerFilter and SignatureVerificationFilter are pipeline filters for creating and verifying digital signatures. They work with any signature scheme (Ed25519, RSA-PSS, ECDSA, etc.) and integrate seamlessly with the Crypto++ pipeline architecture.

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

AutoSeededRandomPool rng;

// Generate key pair
ed25519::Signer signer;
signer.AccessPrivateKey().GenerateRandom(rng);
ed25519::Verifier verifier(signer);

// Sign a message
std::string message = "Document to sign";
std::string signature;

StringSource(message, true,
    new SignerFilter(rng, signer,
        new HexEncoder(new StringSink(signature))
    )
);

// Verify the signature
std::string hexSig = signature;  // Copy for verification
std::string decodedSig;
StringSource(hexSig, true, new HexDecoder(new StringSink(decodedSig)));

bool valid = verifier.VerifyMessage(
    (const byte*)message.data(), message.size(),
    (const byte*)decodedSig.data(), decodedSig.size()
);
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use Ed25519 for new applications (fastest, simplest)
- Always use a proper RNG with SignerFilter
- Store signatures in hex or base64 for text protocols
- Verify signatures before trusting data
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use RSA with key sizes < 2048 bits
- Don't skip signature verification
- Don't use signatures when HMAC suffices (signatures are slower)
- Don't reuse nonces with deterministic schemes
{{< /callout >}}

## SignerFilter

### Constructor

```cpp
SignerFilter(RandomNumberGenerator& rng,
             const PK_Signer& signer,
             BufferedTransformation* attachment = nullptr,
             bool putMessage = false);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `rng` | `RandomNumberGenerator&` | Random number generator for signing |
| `signer` | `const PK_Signer&` | Signing key/algorithm |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |
| `putMessage` | `bool` | If `true`, output message before signature |

## SignatureVerificationFilter

### Constructor

```cpp
SignatureVerificationFilter(const PK_Verifier& verifier,
                            BufferedTransformation* attachment = nullptr,
                            word32 flags = DEFAULT_FLAGS);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `verifier` | `const PK_Verifier&` | Verification key/algorithm |
| `attachment` | `BufferedTransformation*` | Next filter for verified message |
| `flags` | `word32` | Verification options (see below) |

### Flags

```cpp
// Where is the signature?
SIGNATURE_AT_END      // Signature follows message (default)
SIGNATURE_AT_BEGIN    // Signature precedes message

// What to output?
PUT_MESSAGE           // Output the message after verification
PUT_SIGNATURE         // Output the signature
PUT_RESULT            // Output verification result (1 byte: 0 or 1)

// Error handling
THROW_EXCEPTION       // Throw on verification failure (default)
```

## Complete Examples

### Example 1: Ed25519 Signing and Verification

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate Ed25519 key pair
    ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(rng);
    ed25519::Verifier verifier(signer);

    std::string message = "Important document to sign";
    std::string signature, hexSignature;

    // Sign the message
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    // Convert to hex for display/storage
    StringSource(signature, true,
        new HexEncoder(new StringSink(hexSignature))
    );

    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature: " << hexSignature << std::endl;
    std::cout << "Signature length: " << signature.size() << " bytes" << std::endl;

    // Verify the signature
    try {
        // Combine message and signature for verification
        std::string messageAndSig = message + signature;

        std::string recovered;
        StringSource(messageAndSig, true,
            new SignatureVerificationFilter(verifier,
                new StringSink(recovered),
                SignatureVerificationFilter::SIGNATURE_AT_END |
                SignatureVerificationFilter::PUT_MESSAGE |
                SignatureVerificationFilter::THROW_EXCEPTION
            )
        );

        std::cout << "Signature VALID" << std::endl;
        std::cout << "Recovered message: " << recovered << std::endl;

    } catch (const SignatureVerificationFilter::SignatureVerificationFailed& e) {
        std::cout << "Signature INVALID: " << e.what() << std::endl;
    }

    return 0;
}
```

### Example 2: RSA-PSS Signatures

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate RSA key pair
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    RSA::PublicKey publicKey(privateKey);

    // Create signer and verifier with PSS padding
    RSASS<PSS, SHA256>::Signer signer(privateKey);
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);

    std::string message = "Document requiring RSA signature";
    std::string signature;

    // Sign
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    std::cout << "RSA-PSS signature size: " << signature.size() << " bytes" << std::endl;

    // Verify
    std::string combined = message + signature;

    try {
        StringSource(combined, true,
            new SignatureVerificationFilter(verifier,
                nullptr,  // Don't need message output
                SignatureVerificationFilter::SIGNATURE_AT_END |
                SignatureVerificationFilter::THROW_EXCEPTION
            )
        );
        std::cout << "RSA-PSS signature VALID" << std::endl;
    } catch (const SignatureVerificationFilter::SignatureVerificationFailed&) {
        std::cout << "RSA-PSS signature INVALID" << std::endl;
    }

    return 0;
}
```

### Example 3: ECDSA Signatures

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate ECDSA key pair on P-256 curve
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, ASN1::secp256r1());

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    ECDSA<ECP, SHA256>::Signer signer(privateKey);
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    std::string message = "ECDSA signed message";
    std::string signature;

    // Sign
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    std::cout << "ECDSA signature size: " << signature.size() << " bytes" << std::endl;

    // Verify
    bool valid = verifier.VerifyMessage(
        (const byte*)message.data(), message.size(),
        (const byte*)signature.data(), signature.size()
    );

    std::cout << "ECDSA signature " << (valid ? "VALID" : "INVALID") << std::endl;

    return 0;
}
```

### Example 4: Sign a File

```cpp
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <fstream>

std::string signFile(const std::string& filename,
                     ed25519::Signer& signer) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    std::string signature;

    FileSource(filename, true,
        new SignerFilter(rng, signer,
            new HexEncoder(new StringSink(signature))
        )
    );

    return signature;
}

bool verifyFile(const std::string& filename,
                const std::string& hexSignature,
                ed25519::Verifier& verifier) {
    using namespace CryptoPP;

    // Decode hex signature
    std::string signature;
    StringSource(hexSignature, true,
        new HexDecoder(new StringSink(signature))
    );

    // Read file and append signature
    std::string fileContents;
    FileSource(filename, true, new StringSink(fileContents));

    std::string combined = fileContents + signature;

    try {
        StringSource(combined, true,
            new SignatureVerificationFilter(verifier,
                nullptr,
                SignatureVerificationFilter::SIGNATURE_AT_END |
                SignatureVerificationFilter::THROW_EXCEPTION
            )
        );
        return true;
    } catch (const SignatureVerificationFilter::SignatureVerificationFailed&) {
        return false;
    }
}
```

### Example 5: Detached Signatures

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <fstream>

// Create a detached signature (signature stored separately from message)
std::string createDetachedSignature(const std::string& message,
                                     ed25519::Signer& signer) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    std::string signature;

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new Base64Encoder(new StringSink(signature), false)
        )
    );

    return signature;
}

bool verifyDetachedSignature(const std::string& message,
                              const std::string& base64Signature,
                              ed25519::Verifier& verifier) {
    using namespace CryptoPP;

    // Decode signature
    std::string signature;
    StringSource(base64Signature, true,
        new Base64Decoder(new StringSink(signature))
    );

    // Verify
    return verifier.VerifyMessage(
        (const byte*)message.data(), message.size(),
        (const byte*)signature.data(), signature.size()
    );
}

// Save signature to .sig file
void saveSignature(const std::string& filename, const std::string& signature) {
    std::ofstream sigFile(filename + ".sig");
    sigFile << signature;
}

// Load signature from .sig file
std::string loadSignature(const std::string& filename) {
    std::ifstream sigFile(filename + ".sig");
    return std::string(std::istreambuf_iterator<char>(sigFile),
                       std::istreambuf_iterator<char>());
}
```

### Example 6: Message with Embedded Signature

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>

// Create message with signature appended
std::string signAndEmbed(const std::string& message,
                          ed25519::Signer& signer) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    std::string output;

    // putMessage = true: outputs message + signature
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(output),
            true  // putMessage: include original message
        )
    );

    return output;  // Contains: message || signature
}

// Verify and extract message
std::string verifyAndExtract(const std::string& signedData,
                              ed25519::Verifier& verifier) {
    using namespace CryptoPP;

    std::string message;

    StringSource(signedData, true,
        new SignatureVerificationFilter(verifier,
            new StringSink(message),
            SignatureVerificationFilter::SIGNATURE_AT_END |
            SignatureVerificationFilter::PUT_MESSAGE |
            SignatureVerificationFilter::THROW_EXCEPTION
        )
    );

    return message;
}
```

## Signature Sizes

| Algorithm | Signature Size | Notes |
|-----------|---------------|-------|
| Ed25519 | 64 bytes | Fixed size |
| ECDSA P-256 | ~72 bytes | DER encoded, variable |
| ECDSA P-384 | ~104 bytes | DER encoded, variable |
| RSA-2048 | 256 bytes | Same as key size |
| RSA-3072 | 384 bytes | Same as key size |
| RSA-4096 | 512 bytes | Same as key size |

## Key Serialization

### Ed25519

```cpp
// Save private key
std::string privateKeyBytes;
signer.GetPrivateKey().Save(StringSink(privateKeyBytes).Ref());

// Load private key
ed25519::Signer loadedSigner;
StringSource(privateKeyBytes, true,
    new Redirector(loadedSigner.AccessPrivateKey())
);

// Save public key
std::string publicKeyBytes;
verifier.GetPublicKey().Save(StringSink(publicKeyBytes).Ref());

// Load public key
ed25519::Verifier loadedVerifier;
StringSource(publicKeyBytes, true,
    new Redirector(loadedVerifier.AccessPublicKey())
);
```

### RSA

```cpp
// Save private key (PKCS#8 format)
std::string privateKeyPEM;
privateKey.Save(StringSink(privateKeyPEM).Ref());

// Save public key (X.509 format)
std::string publicKeyPEM;
publicKey.Save(StringSink(publicKeyPEM).Ref());
```

## Error Handling

```cpp
void safeVerify(const std::string& message,
                const std::string& signature,
                ed25519::Verifier& verifier) {
    using namespace CryptoPP;

    std::string combined = message + signature;

    try {
        StringSource(combined, true,
            new SignatureVerificationFilter(verifier,
                nullptr,
                SignatureVerificationFilter::SIGNATURE_AT_END |
                SignatureVerificationFilter::THROW_EXCEPTION
            )
        );
        std::cout << "Signature verified successfully" << std::endl;

    } catch (const SignatureVerificationFilter::SignatureVerificationFailed& e) {
        std::cerr << "Signature verification failed" << std::endl;
        // Don't reveal details to potential attackers

    } catch (const Exception& e) {
        std::cerr << "Cryptographic error: " << e.what() << std::endl;
    }
}
```

## Non-Throwing Verification

```cpp
bool verifyWithoutException(const std::string& message,
                             const std::string& signature,
                             ed25519::Verifier& verifier) {
    using namespace CryptoPP;

    std::string combined = message + signature;
    std::string result;

    // PUT_RESULT outputs a single byte: 1 for valid, 0 for invalid
    StringSource(combined, true,
        new SignatureVerificationFilter(verifier,
            new StringSink(result),
            SignatureVerificationFilter::SIGNATURE_AT_END |
            SignatureVerificationFilter::PUT_RESULT
            // Note: no THROW_EXCEPTION
        )
    );

    return !result.empty() && result[0] == 1;
}
```

## Performance Comparison

| Operation | Ed25519 | ECDSA P-256 | RSA-2048 |
|-----------|---------|-------------|----------|
| Key generation | ~50 µs | ~100 µs | ~50 ms |
| Sign | ~50 µs | ~100 µs | ~2 ms |
| Verify | ~100 µs | ~200 µs | ~50 µs |

**Recommendation:** Use Ed25519 for new applications - it's fastest and simplest.

## When to Use Signatures vs HMAC

| Use Signatures When | Use HMAC When |
|--------------------|---------------|
| Public verification needed | Both parties share secret |
| Non-repudiation required | Speed is critical |
| Key distribution is a concern | Simpler key management |
| Multiple verifiers | Single verifier |

## Thread Safety

SignerFilter and SignatureVerificationFilter are **not thread-safe**:

```cpp
// WRONG - shared across threads
ed25519::Signer sharedSigner;

// CORRECT - per-thread
void signInThread(const std::string& message) {
    AutoSeededRandomPool rng;
    std::string signature;

    // Create signer per thread (or use mutex)
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );
}
```

## See Also

- [Ed25519](/docs/api/pubkey/ed25519/) - Modern digital signatures
- [RSA](/docs/api/pubkey/rsa/) - RSA signatures and encryption
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation
- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String I/O
- [HMAC](/docs/api/mac/hmac/) - For symmetric authentication
