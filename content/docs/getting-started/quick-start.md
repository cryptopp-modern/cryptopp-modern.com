---
title: Quick Start
weight: 30
---

Get up and running with cryptopp-modern in 5 minutes.

## Your First Program

Create a simple program that hashes a message with BLAKE3:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string message = "Hello, cryptopp-modern!";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "BLAKE3: " << digest << std::endl;
    return 0;
}
```

## Compile and Run

### Linux / macOS

```bash
g++ -o hello hello.cpp -lcryptopp
./hello
```

### Windows (Visual Studio)

```cmd
cl /EHsc hello.cpp /I"path\to\cryptopp-modern\include" /link cryptlib.lib
hello.exe
```

## Common Use Cases

### Password Hashing with Argon2

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <iostream>

int main() {
    CryptoPP::Argon2id argon2;

    std::string password = "MySecurePassword123";
    CryptoPP::SecByteBlock salt(16);
    CryptoPP::SecByteBlock derived(32);

    // In practice, generate random salt
    memset(salt, 0x01, salt.size());

    argon2.DeriveKey(
        derived, derived.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0,  // Secret (optional)
        nullptr, 0,  // Additional data (optional)
        3,      // Time cost (iterations)
        65536   // Memory cost (KB)
    );

    std::string hexOutput;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexOutput));
    encoder.Put(derived, derived.size());
    encoder.MessageEnd();

    std::cout << "Argon2id: " << hexOutput << std::endl;
    return 0;
}
```

### AES Encryption

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Key and IV (in practice, generate these securely!)
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH] = {0};
    CryptoPP::byte iv[AES::BLOCKSIZE] = {0};

    std::string plaintext = "Secret message";
    std::string ciphertext, decrypted;

    // Encrypt
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv);
    StringSource(plaintext, true,
        new StreamTransformationFilter(enc,
            new StringSink(ciphertext)));

    // Decrypt
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv);
    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec,
            new StringSink(decrypted)));

    std::cout << "Plaintext:  " << plaintext << std::endl;
    std::cout << "Decrypted:  " << decrypted << std::endl;

    return 0;
}
```

### Digital Signatures with Ed25519

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate key pair
    ed25519Signer signer;
    signer.AccessPrivateKey().GenerateRandom(rng);

    ed25519Verifier verifier(signer);

    // Sign message
    std::string message = "Important document";
    std::string signature;

    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)));

    // Verify signature
    bool valid = false;
    StringSource(message + signature, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((CryptoPP::byte*)&valid, sizeof(valid))));

    std::cout << "Signature valid: " << (valid ? "Yes" : "No") << std::endl;

    return 0;
}
```

## Project Setup

### CMakeLists.txt Example

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp)

set(CMAKE_CXX_STANDARD 11)

find_package(cryptopp REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp cryptopp::cryptopp)
```

### Makefile Example

```makefile
CXX = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -lcryptopp

myapp: main.cpp
	$(CXX) $(CXXFLAGS) -o myapp main.cpp $(LDFLAGS)

clean:
	rm -f myapp
```

## Next Steps

- [Argon2](../../algorithms/argon2) - Password hashing
- [BLAKE3](../../algorithms/blake3) - Fast hashing
- [Security Concepts](../../guides/security-concepts) - Important security topics
- [Migration Guide](../../migration/from-cryptopp) - Migrating from Crypto++ 8.9.0
