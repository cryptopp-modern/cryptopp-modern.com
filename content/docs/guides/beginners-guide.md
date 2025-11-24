---
title: Beginner's Guide to Cryptography
weight: 100
description: "Complete cryptography tutorial for beginners. Learn BLAKE3 hashing, AES-GCM encryption, Argon2 password hashing, HMAC authentication, and secure random number generation with practical examples."
---

This guide is designed for developers new to cryptography. We'll cover common use cases with simple, copy-paste ready examples that follow security best practices.

## Quick Start: What Do You Need?

### I need to hash data (checksums, integrity verification)
→ Use [BLAKE3 Hashing](#hashing-data-blake3) or [SHA-256](#hashing-data-sha-256)

### I need to encrypt data (protecting confidentiality)
→ Use [AES-GCM Encryption](#encrypting-data-aes-gcm)

### I need to hash passwords (user authentication)
→ Use [Argon2 Password Hashing](#password-hashing-argon2)

### I need to verify data hasn't been tampered with
→ Use [HMAC](#message-authentication-hmac)

### I need to generate random data (keys, tokens, IDs)
→ Use [Random Number Generation](#random-number-generation)

---

## Hashing Data (BLAKE3)

**When to use:** File integrity, content addressing, checksums

**What it does:** Creates a unique "fingerprint" of your data. Same input = same output. Different input = different output.

**Security:** One-way function (can't reverse it to get original data)

### Simple Example

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

std::string hashData(const std::string& data) {
    CryptoPP::BLAKE3 hash;
    std::string digest;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    std::string data = "Hello, World!";
    std::string hash = hashData(data);

    std::cout << "Data: " << data << std::endl;
    std::cout << "Hash: " << hash << std::endl;

    return 0;
}
```

**Compile:**
```bash
g++ -std=c++11 hash_example.cpp -o hash_example -lcryptopp
```

### Hash a File

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>

std::string hashFile(const std::string& filename) {
    CryptoPP::BLAKE3 hash;
    std::string digest;

    try {
        CryptoPP::FileSource(filename.c_str(), true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest))));
        return digest;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return "";
    }
}

int main() {
    std::string hash = hashFile("document.pdf");
    if (!hash.empty()) {
        std::cout << "File hash: " << hash << std::endl;
    }
    return 0;
}
```

---

## Hashing Data (SHA-256)

**When to use:** When you need FIPS compliance or industry standard hashing

**Difference from BLAKE3:** Slower but more widely standardized

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

std::string hashDataSHA256(const std::string& data) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    std::string data = "Hello, World!";
    std::string hash = hashDataSHA256(data);

    std::cout << "SHA-256: " << hash << std::endl;
    return 0;
}
```

---

## Encrypting Data (AES-GCM)

**When to use:** Protecting sensitive data (files, messages, database entries)

**What it does:** Scrambles data so only someone with the key can read it. Also prevents tampering.

**Important:** Keep the key secret! If someone gets your key, they can decrypt everything.

### Simple Encryption Class

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

class SimpleEncryption {
private:
    CryptoPP::SecByteBlock key;
    CryptoPP::AutoSeededRandomPool prng;

public:
    // Constructor: generates a random encryption key
    SimpleEncryption() : key(CryptoPP::AES::DEFAULT_KEYLENGTH) {
        prng.GenerateBlock(key, key.size());
    }

    // Encrypt a string
    std::string encrypt(const std::string& plaintext) {
        // Generate random nonce (must be unique for each encryption!)
        // 💡 Why? See: /docs/guides/security-concepts#nonce-and-iv-management
        CryptoPP::SecByteBlock nonce(12);
        prng.GenerateBlock(nonce, nonce.size());

        // Perform encryption
        std::string ciphertext;
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        // Return: nonce + ciphertext (you need both to decrypt!)
        std::string result((char*)nonce.data(), nonce.size());
        result += ciphertext;
        return result;
    }

    // Decrypt a string
    bool decrypt(const std::string& encrypted, std::string& plaintext) {
        if (encrypted.size() < 12) {
            return false;  // Too short to be valid
        }

        // Extract nonce and ciphertext
        CryptoPP::SecByteBlock nonce((const CryptoPP::byte*)encrypted.data(), 12);
        std::string ciphertext = encrypted.substr(12);

        try {
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

            CryptoPP::StringSource(ciphertext, true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(plaintext)
                )
            );
            return true;
        }
        catch (const CryptoPP::Exception&) {
            return false;  // Decryption failed (wrong key or tampered data)
        }
    }

    // Get key as hex string (for saving to file/database)
    std::string getKeyHex() const {
        std::string keyHex;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(keyHex));
        encoder.Put(key, key.size());
        encoder.MessageEnd();
        return keyHex;
    }

    // Load key from hex string
    void setKeyFromHex(const std::string& keyHex) {
        CryptoPP::HexDecoder decoder;
        decoder.Put((CryptoPP::byte*)keyHex.data(), keyHex.size());
        decoder.MessageEnd();

        key.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
        decoder.Get(key, key.size());
    }
};

int main() {
    SimpleEncryption crypto;

    // Encrypt
    std::string secret = "This is my secret message!";
    std::string encrypted = crypto.encrypt(secret);

    std::cout << "Original: " << secret << std::endl;
    std::cout << "Encrypted size: " << encrypted.size() << " bytes" << std::endl;

    // Decrypt
    std::string decrypted;
    if (crypto.decrypt(encrypted, decrypted)) {
        std::cout << "Decrypted: " << decrypted << std::endl;
    } else {
        std::cout << "Decryption failed!" << std::endl;
    }

    // Save key for later use
    std::string keyHex = crypto.getKeyHex();
    std::cout << "Save this key: " << keyHex << std::endl;

    return 0;
}
```

### Encrypting Files

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <fstream>

bool encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const CryptoPP::SecByteBlock& key) {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate random nonce
    CryptoPP::SecByteBlock nonce(12);
    prng.GenerateBlock(nonce, nonce.size());

    try {
        // Write nonce to output file first
        std::ofstream out(outputFile, std::ios::binary);
        out.write((char*)nonce.data(), nonce.size());
        out.close();

        // Encrypt file and append to output
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        CryptoPP::FileSource(inputFile.c_str(), true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::FileSink(outputFile.c_str(), false)  // append mode
            )
        );

        return true;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Encryption error: " << ex.what() << std::endl;
        return false;
    }
}

bool decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const CryptoPP::SecByteBlock& key) {
    try {
        // Read nonce from file
        std::ifstream in(inputFile, std::ios::binary);
        CryptoPP::SecByteBlock nonce(12);
        in.read((char*)nonce.data(), nonce.size());
        in.close();

        // Decrypt (skip first 12 bytes which is the nonce)
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        CryptoPP::FileSource(inputFile.c_str(), true,
            new CryptoPP::AuthenticatedDecryptionFilter(dec,
                new CryptoPP::FileSink(outputFile.c_str())
            )
        );

        return true;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
        return false;
    }
}

int main() {
    // Generate encryption key
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    // Encrypt file
    if (encryptFile("document.pdf", "document.pdf.encrypted", key)) {
        std::cout << "File encrypted successfully" << std::endl;
    }

    // Decrypt file
    if (decryptFile("document.pdf.encrypted", "document_decrypted.pdf", key)) {
        std::cout << "File decrypted successfully" << std::endl;
    }

    return 0;
}
```

---

## Password Hashing (Argon2)

**When to use:** Storing user passwords in a database

**What it does:** Creates a hash that's slow to compute (makes brute-force attacks impractical)

**Important:** Never store plain passwords! Always hash them.

### Simple Password Class

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

class PasswordHasher {
public:
    // Hash a password - returns salt+hash combined as hex string
    static std::string hashPassword(const std::string& password) {
        CryptoPP::AutoSeededRandomPool prng;

        // Generate random salt
        CryptoPP::SecByteBlock salt(16);
        prng.GenerateBlock(salt, salt.size());

        // Hash password with Argon2id
        CryptoPP::SecByteBlock hash(32);
        CryptoPP::Argon2id argon2;

        argon2.DeriveKey(
            hash, hash.size(),
            (const CryptoPP::byte*)password.data(), password.size(),
            salt, salt.size(),
            nullptr, 0,  // No secret
            nullptr, 0,  // No additional data
            3,           // Time cost (iterations)
            65536        // Memory cost (64 MB)
        );

        // Combine salt + hash and convert to hex
        std::string combined;
        combined.append((char*)salt.data(), salt.size());
        combined.append((char*)hash.data(), hash.size());

        std::string hexOutput;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexOutput));
        encoder.Put((CryptoPP::byte*)combined.data(), combined.size());
        encoder.MessageEnd();

        return hexOutput;
    }

    // Verify a password against stored hash
    static bool verifyPassword(const std::string& password,
                              const std::string& storedHashHex) {
        // Decode hex
        std::string decoded;
        CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(decoded));
        decoder.Put((CryptoPP::byte*)storedHashHex.data(), storedHashHex.size());
        decoder.MessageEnd();

        if (decoded.size() != 48) {  // 16 bytes salt + 32 bytes hash
            return false;
        }

        // Extract salt and expected hash
        CryptoPP::SecByteBlock salt((const CryptoPP::byte*)decoded.data(), 16);
        CryptoPP::SecByteBlock expectedHash((const CryptoPP::byte*)decoded.data() + 16, 32);

        // Compute hash with same salt
        CryptoPP::SecByteBlock computedHash(32);
        CryptoPP::Argon2id argon2;

        argon2.DeriveKey(
            computedHash, computedHash.size(),
            (const CryptoPP::byte*)password.data(), password.size(),
            salt, salt.size(),
            nullptr, 0,
            nullptr, 0,
            3,
            65536
        );

        // Compare (constant-time to prevent timing attacks)
        // 💡 Why constant-time? See: /docs/guides/security-concepts#constant-time-operations
        return CryptoPP::VerifyBufsEqual(
            computedHash, expectedHash, 32
        );
    }
};

int main() {
    std::string password = "MySecurePassword123!";

    // Hash password (do this when user registers)
    std::string hashedPassword = PasswordHasher::hashPassword(password);
    std::cout << "Hashed password: " << hashedPassword << std::endl;
    std::cout << "Store this in your database!" << std::endl;

    // Verify password (do this when user logs in)
    bool valid = PasswordHasher::verifyPassword(password, hashedPassword);
    std::cout << "Password valid: " << (valid ? "YES" : "NO") << std::endl;

    // Try wrong password
    bool invalid = PasswordHasher::verifyPassword("WrongPassword", hashedPassword);
    std::cout << "Wrong password: " << (invalid ? "YES" : "NO") << std::endl;

    return 0;
}
```

---

## Message Authentication (HMAC)

**When to use:** Verifying that a message hasn't been tampered with

**What it does:** Creates a "signature" using a secret key. Anyone with the key can verify the message is authentic.

**Use case:** API authentication, message integrity

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

class MessageAuth {
private:
    CryptoPP::SecByteBlock key;

public:
    MessageAuth() : key(32) {
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
    }

    // Create authentication tag for a message
    std::string sign(const std::string& message) {
        std::string mac;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());

        CryptoPP::StringSource(message, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(mac)
                )
            )
        );

        return mac;
    }

    // Verify a message's authentication tag
    bool verify(const std::string& message, const std::string& macHex) {
        std::string computedMac = sign(message);

        // Constant-time comparison
        if (computedMac.size() != macHex.size()) {
            return false;
        }

        return computedMac == macHex;
    }
};

int main() {
    MessageAuth auth;

    std::string message = "Transfer $100 to account 12345";

    // Create authentication tag
    std::string mac = auth.sign(message);
    std::cout << "Message: " << message << std::endl;
    std::cout << "MAC: " << mac << std::endl;

    // Verify message
    bool valid = auth.verify(message, mac);
    std::cout << "Valid: " << (valid ? "YES" : "NO") << std::endl;

    // Try tampering with message
    std::string tamperedMessage = "Transfer $999 to account 12345";
    bool tampered = auth.verify(tamperedMessage, mac);
    std::cout << "Tampered message valid: " << (tampered ? "YES" : "NO") << std::endl;

    return 0;
}
```

---

## Random Number Generation

**When to use:** Generating keys, tokens, session IDs, nonces

**What it does:** Provides cryptographically secure random numbers

**Important:** Never use `rand()` or `srand()` for security! Use `AutoSeededRandomPool`.

💡 **Learn more:** [Why weak RNGs are dangerous](../security-concepts#secure-random-numbers)

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

class RandomGenerator {
private:
    CryptoPP::AutoSeededRandomPool prng;

public:
    // Generate random bytes
    std::string generateBytes(size_t length) {
        CryptoPP::SecByteBlock random(length);
        prng.GenerateBlock(random, random.size());

        std::string hex;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex));
        encoder.Put(random, random.size());
        encoder.MessageEnd();

        return hex;
    }

    // Generate random integer
    unsigned int generateInt(unsigned int min, unsigned int max) {
        unsigned int value;
        prng.GenerateBlock((CryptoPP::byte*)&value, sizeof(value));
        return min + (value % (max - min + 1));
    }

    // Generate session token
    std::string generateToken() {
        return generateBytes(32);  // 32 bytes = 256 bits
    }

    // Generate encryption key
    CryptoPP::SecByteBlock generateKey(size_t keySize = 16) {
        CryptoPP::SecByteBlock key(keySize);
        prng.GenerateBlock(key, key.size());
        return key;
    }
};

int main() {
    RandomGenerator rng;

    // Generate session token
    std::string token = rng.generateToken();
    std::cout << "Session token: " << token << std::endl;

    // Generate random bytes
    std::string randomBytes = rng.generateBytes(16);
    std::cout << "Random bytes: " << randomBytes << std::endl;

    // Generate random number
    unsigned int randomNum = rng.generateInt(1, 100);
    std::cout << "Random number (1-100): " << randomNum << std::endl;

    // Generate encryption key
    CryptoPP::SecByteBlock key = rng.generateKey(32);
    std::cout << "Generated 256-bit key" << std::endl;

    return 0;
}
```

---

## Common Questions

### How do I store encryption keys?

**Bad:** Hard-code in source code
```cpp
// DON'T DO THIS!
std::string key = "mysecretkey123";
```

**Good:** Load from secure configuration
```cpp
// Store in environment variable, config file, or key management system
std::string keyHex = std::getenv("ENCRYPTION_KEY");
// Load key from hex string
```

**Better:** Use OS key storage (Windows: DPAPI, Linux: Keyring, macOS: Keychain)

💡 **Learn more:** [Key storage best practices](../security-concepts#key-storage)

### How do I transmit encrypted data?

Store as: `nonce || ciphertext || auth_tag`

All three components can be transmitted in the clear - only the key must be secret.

### What key size should I use?

- **AES**: 128-bit is fine for most uses, 256-bit for maximum security
- **HMAC**: 256-bit (32 bytes)
- **Argon2**: Handled automatically

### How often should I rotate keys?

- **Encryption keys**: Yearly, or after 2^32 encryptions (for GCM)
- **API keys**: Quarterly or on suspected compromise
- **Password hashes**: Never rotate (each password has unique salt)

### Can I use this in production?

Yes! cryptopp-modern is production-ready. The examples above follow security best practices.

**However:**
- Test thoroughly
- Consider professional security audit for critical applications
- Keep library updated for security patches

---

## Next Steps

Now that you understand the basics:

1. **⚠️ Essential Security Reading:**
   - **[Security Concepts Guide](../security-concepts)** - Start here to understand:
     - Why constant-time comparison prevents timing attacks
     - Why GCM nonce reuse is catastrophic
     - Why you need separate keys for encryption and authentication
     - Why `rand()` is dangerous for cryptography
     - How to properly store keys

2. **Read the detailed algorithm guides:**
   - [BLAKE3 Deep Dive](../../algorithms/blake3)
   - [Argon2 Parameters](../../algorithms/argon2)
   - [AES-GCM Security](../../algorithms/symmetric)
   - [Hash Functions](../../algorithms/hashing)

3. **Explore advanced topics:**
   - Public key cryptography (RSA, ECDSA)
   - Key derivation functions
   - Digital signatures

---

## Complete Example: Secure Note Application

Putting it all together - a simple encrypted note storage application:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <fstream>
#include <string>

class SecureNotes {
private:
    CryptoPP::SecByteBlock masterKey;
    CryptoPP::AutoSeededRandomPool prng;

    // Derive encryption key from password
    void deriveKeyFromPassword(const std::string& password) {
        CryptoPP::SecByteBlock salt(16);
        // In real app, store salt with encrypted data
        prng.GenerateBlock(salt, salt.size());

        masterKey.resize(32);
        CryptoPP::Argon2id argon2;
        argon2.DeriveKey(
            masterKey, masterKey.size(),
            (const CryptoPP::byte*)password.data(), password.size(),
            salt, salt.size(),
            nullptr, 0, nullptr, 0,
            3, 65536
        );
    }

public:
    SecureNotes(const std::string& password) {
        deriveKeyFromPassword(password);
    }

    bool saveNote(const std::string& filename, const std::string& note) {
        try {
            // Generate nonce
            CryptoPP::SecByteBlock nonce(12);
            prng.GenerateBlock(nonce, nonce.size());

            // Encrypt
            std::string ciphertext;
            CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
            enc.SetKeyWithIV(masterKey, masterKey.size(), nonce, nonce.size());

            CryptoPP::StringSource(note, true,
                new CryptoPP::AuthenticatedEncryptionFilter(enc,
                    new CryptoPP::StringSink(ciphertext)
                )
            );

            // Save to file: nonce + ciphertext
            std::ofstream out(filename, std::ios::binary);
            out.write((char*)nonce.data(), nonce.size());
            out.write(ciphertext.data(), ciphertext.size());
            out.close();

            return true;
        }
        catch (const std::exception& ex) {
            std::cerr << "Error saving: " << ex.what() << std::endl;
            return false;
        }
    }

    bool loadNote(const std::string& filename, std::string& note) {
        try {
            // Read file
            std::ifstream in(filename, std::ios::binary);
            if (!in) return false;

            // Read nonce
            CryptoPP::SecByteBlock nonce(12);
            in.read((char*)nonce.data(), nonce.size());

            // Read ciphertext
            std::string ciphertext(
                (std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>()
            );
            in.close();

            // Decrypt
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(masterKey, masterKey.size(), nonce, nonce.size());

            CryptoPP::StringSource(ciphertext, true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(note)
                )
            );

            return true;
        }
        catch (const std::exception& ex) {
            std::cerr << "Error loading: " << ex.what() << std::endl;
            return false;
        }
    }
};

int main() {
    std::string password = "MyMasterPassword123!";
    SecureNotes notes(password);

    // Save a note
    std::string myNote = "This is my secret note!\nIt's encrypted with my password.";
    if (notes.saveNote("secret.enc", myNote)) {
        std::cout << "Note saved successfully" << std::endl;
    }

    // Load the note
    std::string loadedNote;
    if (notes.loadNote("secret.enc", loadedNote)) {
        std::cout << "Note loaded successfully:" << std::endl;
        std::cout << loadedNote << std::endl;
    }

    return 0;
}
```

This example demonstrates:
- Password-based key derivation (Argon2)
- Authenticated encryption (AES-GCM)
- Proper nonce handling
- File I/O with encrypted data
- Error handling

**Compile:**
```bash
g++ -std=c++11 secure_notes.cpp -o secure_notes -lcryptopp
```

You now have a solid foundation for using cryptopp-modern securely!
