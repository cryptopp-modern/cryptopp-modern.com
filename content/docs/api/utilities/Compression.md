---
title: Compression (Zlib, Gzip, Deflate)
description: API reference for compression and decompression using Zlib, Gzip, and Deflate algorithms in cryptopp-modern
---

**Header:** `<cryptopp/zlib.h>`, `<cryptopp/gzip.h>`, `<cryptopp/zinflate.h>` | **Namespace:** `CryptoPP`

**Since:** Crypto++ 1.0 | **Thread Safety:** Not thread-safe (use per-thread instances)

## Quick Example

```cpp
#include <cryptopp/zlib.h>
#include <cryptopp/filters.h>
#include <string>
#include <iostream>

int main() {
    std::string original = "Hello, World! This is some data to compress. "
                           "Repetitive content compresses well well well well.";
    std::string compressed, decompressed;

    // Compress
    CryptoPP::ZlibCompressor compressor;
    CryptoPP::StringSource ss1(original, true,
        new CryptoPP::StreamTransformationFilter(compressor,
            new CryptoPP::StringSink(compressed)
        )
    );

    // Decompress
    CryptoPP::ZlibDecompressor decompressor;
    CryptoPP::StringSource ss2(compressed, true,
        new CryptoPP::StreamTransformationFilter(decompressor,
            new CryptoPP::StringSink(decompressed)
        )
    );

    std::cout << "Original size: " << original.size() << std::endl;
    std::cout << "Compressed size: " << compressed.size() << std::endl;
    std::cout << "Match: " << (original == decompressed ? "YES" : "NO") << std::endl;

    return 0;
}
```

## Usage Guidelines

{{< callout type="error" title="Security Warning: Compression Oracles" >}}
**Never compress then encrypt when an attacker can:**
1. Influence part of the plaintext (e.g., HTTP headers, user input)
2. Observe the ciphertext length

This enables **CRIME/BREACH-style attacks** where attackers can recover secrets by observing compression ratios. See [Security Concepts: Compression Oracles](/docs/guides/security-concepts#compression-oracles) for details.
{{< /callout >}}

{{< callout type="info" title="When Compression Is Safe" >}}
- Compressing data where attacker cannot influence plaintext
- Compressing before encryption when content is fully controlled
- Compressing after decryption (for storage/transmission efficiency)
- Non-encrypted compression (archives, backups)
{{< /callout >}}

## Available Algorithms

| Class | Format | Use Case |
|-------|--------|----------|
| `ZlibCompressor` / `ZlibDecompressor` | Zlib (RFC 1950) | General purpose, includes header/checksum |
| `Gzip` / `Gunzip` | Gzip (RFC 1952) | File compression, HTTP Content-Encoding |
| `Deflator` / `Inflator` | Raw Deflate (RFC 1951) | Custom formats, minimal overhead |

## ZlibCompressor / ZlibDecompressor

Zlib format includes a header and Adler-32 checksum for integrity verification.

### Constructor

```cpp
// Compression
ZlibCompressor(BufferedTransformation* attachment = nullptr,
               unsigned int deflateLevel = DEFAULT_DEFLATE_LEVEL,
               unsigned int log2WindowSize = DEFAULT_LOG2_WINDOW_SIZE);

// Decompression
ZlibDecompressor(BufferedTransformation* attachment = nullptr);
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `deflateLevel` | 0 (none) to 9 (best) | 6 (DEFAULT_DEFLATE_LEVEL) |
| `log2WindowSize` | Window size: 2^n bytes (9-15) | 15 (32KB window) |

### Compression Levels

| Level | Name | Speed | Compression |
|-------|------|-------|-------------|
| 0 | Store only | Fastest | None |
| 1 | Best speed | Very fast | Low |
| 6 | Default | Balanced | Good |
| 9 | Best compression | Slow | Best |

### Example: Variable Compression Levels

```cpp
#include <cryptopp/zlib.h>
#include <cryptopp/filters.h>
#include <iostream>

void compareCompressionLevels(const std::string& data) {
    std::cout << "Original size: " << data.size() << " bytes\n\n";

    for (int level = 0; level <= 9; level++) {
        std::string compressed;

        CryptoPP::ZlibCompressor compressor(
            new CryptoPP::StringSink(compressed),
            level  // Compression level
        );

        CryptoPP::StringSource ss(data, true,
            new CryptoPP::Redirector(compressor)
        );
        compressor.MessageEnd();

        double ratio = 100.0 * compressed.size() / data.size();
        std::cout << "Level " << level << ": "
                  << compressed.size() << " bytes ("
                  << ratio << "%)\n";
    }
}

int main() {
    // Test with repetitive data (compresses well)
    std::string testData(10000, 'A');
    for (int i = 0; i < 10000; i += 100) {
        testData[i] = 'B';
    }

    compareCompressionLevels(testData);
    return 0;
}
```

## Gzip / Gunzip

Gzip format is commonly used for file compression and HTTP content encoding.

### Constructor

```cpp
// Compression
Gzip(BufferedTransformation* attachment = nullptr,
     unsigned int deflateLevel = DEFAULT_DEFLATE_LEVEL,
     unsigned int log2WindowSize = DEFAULT_LOG2_WINDOW_SIZE);

// Decompression
Gunzip(BufferedTransformation* attachment = nullptr);
```

### Example: Gzip File Compression

```cpp
#include <cryptopp/gzip.h>
#include <cryptopp/files.h>
#include <iostream>

bool compressFile(const std::string& inputFile,
                  const std::string& outputFile) {
    try {
        CryptoPP::FileSource fs(inputFile.c_str(), true,
            new CryptoPP::Gzip(
                new CryptoPP::FileSink(outputFile.c_str()),
                CryptoPP::Gzip::MAX_DEFLATE_LEVEL  // Best compression
            )
        );
        return true;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Compression error: " << e.what() << std::endl;
        return false;
    }
}

bool decompressFile(const std::string& inputFile,
                    const std::string& outputFile) {
    try {
        CryptoPP::FileSource fs(inputFile.c_str(), true,
            new CryptoPP::Gunzip(
                new CryptoPP::FileSink(outputFile.c_str())
            )
        );
        return true;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Decompression error: " << e.what() << std::endl;
        return false;
    }
}

int main() {
    // Compress
    if (compressFile("document.txt", "document.txt.gz")) {
        std::cout << "File compressed successfully" << std::endl;
    }

    // Decompress
    if (decompressFile("document.txt.gz", "document_restored.txt")) {
        std::cout << "File decompressed successfully" << std::endl;
    }

    return 0;
}
```

## Deflator / Inflator

Raw Deflate without headers - useful for custom formats or when you handle framing yourself.

### Example: Raw Deflate

```cpp
#include <cryptopp/zinflate.h>
#include <cryptopp/zdeflate.h>
#include <cryptopp/filters.h>
#include <string>

std::string deflateData(const std::string& input) {
    std::string output;

    CryptoPP::Deflator deflator(
        new CryptoPP::StringSink(output),
        CryptoPP::Deflator::DEFAULT_DEFLATE_LEVEL
    );

    CryptoPP::StringSource ss(input, true,
        new CryptoPP::Redirector(deflator)
    );
    deflator.MessageEnd();

    return output;
}

std::string inflateData(const std::string& compressed) {
    std::string output;

    CryptoPP::Inflator inflator(
        new CryptoPP::StringSink(output)
    );

    CryptoPP::StringSource ss(compressed, true,
        new CryptoPP::Redirector(inflator)
    );
    inflator.MessageEnd();

    return output;
}
```

## Complete Example: Safe Compression with Encryption

This example shows a **safe** pattern where compression is used on fully-controlled data.

```cpp
#include <cryptopp/zlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <iostream>

// SAFE: Compressing application-controlled data before encryption
// The attacker cannot influence the plaintext content
class SecureArchive {
private:
    CryptoPP::SecByteBlock key;
    CryptoPP::AutoSeededRandomPool rng;

public:
    SecureArchive() : key(32) {
        rng.GenerateBlock(key, key.size());
    }

    // Compress then encrypt (safe when content is fully controlled)
    bool saveCompressedEncrypted(const std::string& filename,
                                  const std::string& data) {
        try {
            // Step 1: Compress
            std::string compressed;
            CryptoPP::ZlibCompressor compressor(
                new CryptoPP::StringSink(compressed),
                CryptoPP::ZlibCompressor::DEFAULT_DEFLATE_LEVEL
            );
            CryptoPP::StringSource ss1(data, true,
                new CryptoPP::Redirector(compressor)
            );
            compressor.MessageEnd();

            // Step 2: Generate nonce
            CryptoPP::SecByteBlock nonce(12);
            rng.GenerateBlock(nonce, nonce.size());

            // Step 3: Encrypt compressed data
            std::string ciphertext;
            CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

            CryptoPP::StringSource ss2(compressed, true,
                new CryptoPP::AuthenticatedEncryptionFilter(enc,
                    new CryptoPP::StringSink(ciphertext)
                )
            );

            // Step 4: Write [nonce || ciphertext]
            std::ofstream out(filename, std::ios::binary);
            out.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
            out.write(ciphertext.data(), ciphertext.size());

            std::cout << "Original: " << data.size() << " bytes\n";
            std::cout << "Compressed: " << compressed.size() << " bytes\n";
            std::cout << "Encrypted: " << (nonce.size() + ciphertext.size()) << " bytes\n";

            return true;
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    // Decrypt then decompress
    bool loadCompressedEncrypted(const std::string& filename,
                                  std::string& data) {
        try {
            // Step 1: Read file
            std::ifstream in(filename, std::ios::binary);
            if (!in) return false;

            CryptoPP::SecByteBlock nonce(12);
            in.read(reinterpret_cast<char*>(nonce.data()), nonce.size());

            std::string ciphertext(
                (std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>()
            );

            // Step 2: Decrypt
            std::string compressed;
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

            CryptoPP::StringSource ss1(ciphertext, true,
                new CryptoPP::AuthenticatedDecryptionFilter(dec,
                    new CryptoPP::StringSink(compressed)
                )
            );

            // Step 3: Decompress
            CryptoPP::ZlibDecompressor decompressor(
                new CryptoPP::StringSink(data)
            );
            CryptoPP::StringSource ss2(compressed, true,
                new CryptoPP::Redirector(decompressor)
            );
            decompressor.MessageEnd();

            return true;
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    const CryptoPP::SecByteBlock& getKey() const { return key; }
};

int main() {
    SecureArchive archive;

    // This is SAFE - we fully control the content
    std::string data = "This is application data that we fully control. "
                       "No user input or attacker-controlled content here. "
                       "Repetitive data compresses well well well well.";

    archive.saveCompressedEncrypted("archive.enc", data);

    std::string restored;
    if (archive.loadCompressedEncrypted("archive.enc", restored)) {
        std::cout << "Restored: " << restored << std::endl;
        std::cout << "Match: " << (data == restored ? "YES" : "NO") << std::endl;
    }

    return 0;
}
```

## Dangerous Pattern: Compression Oracle

{{< callout type="error" title="DO NOT USE THIS PATTERN" >}}
The following shows a **vulnerable** pattern. Never do this when attacker-controlled data is mixed with secrets.
{{< /callout >}}

```cpp
// ❌ VULNERABLE TO COMPRESSION ORACLE ATTACK
std::string encryptRequest(const std::string& userInput,
                            const std::string& secretToken) {
    // Attacker controls userInput, wants to discover secretToken

    std::string request = "GET /api?user=" + userInput +
                          "&token=" + secretToken;  // Secret!

    // Compress - if userInput matches part of secretToken,
    // the compressed size will be SMALLER
    std::string compressed;
    CryptoPP::ZlibCompressor compressor(
        new CryptoPP::StringSink(compressed)
    );
    CryptoPP::StringSource(request, true,
        new CryptoPP::Redirector(compressor)
    );
    compressor.MessageEnd();

    // Encrypt
    std::string ciphertext;
    // ... encryption code ...

    // Attacker observes ciphertext.size()
    // If userInput = "token=A" and size is smaller than userInput = "token=B",
    // attacker learns the token starts with "A"!

    return ciphertext;
}
```

**Attack mechanism:**
1. Attacker tries `userInput = "token=A"` - observes ciphertext size
2. Attacker tries `userInput = "token=B"` - observes ciphertext size
3. If "A" produces smaller output, the secret token likely starts with "A"
4. Repeat for each character position to recover entire token

## Performance

### Compression Speed (approximate)

| Level | Speed | Use Case |
|-------|-------|----------|
| 1 | ~200 MB/s | Real-time streaming |
| 6 | ~50 MB/s | General purpose |
| 9 | ~10 MB/s | Archival, one-time compression |

### Memory Usage

| Window Size | Memory | Compression Ratio |
|-------------|--------|-------------------|
| 2^9 (512B) | ~1 KB | Lower |
| 2^12 (4KB) | ~8 KB | Moderate |
| 2^15 (32KB) | ~64 KB | Best |

## Error Handling

```cpp
#include <cryptopp/zlib.h>
#include <cryptopp/filters.h>
#include <iostream>

bool safeDecompress(const std::string& compressed, std::string& output) {
    try {
        CryptoPP::ZlibDecompressor decompressor(
            new CryptoPP::StringSink(output)
        );

        CryptoPP::StringSource ss(compressed, true,
            new CryptoPP::Redirector(decompressor)
        );
        decompressor.MessageEnd();

        return true;
    }
    catch (const CryptoPP::ZlibDecompressor::Err& e) {
        std::cerr << "Zlib error: " << e.what() << std::endl;
        return false;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
        return false;
    }
}
```

### Common Exceptions

| Exception | Cause |
|-----------|-------|
| `ZlibDecompressor::Err` | Invalid compressed data, checksum mismatch |
| `Inflator::UnexpectedEndErr` | Truncated compressed data |
| `Inflator::BadBlockErr` | Corrupted block in compressed stream |

## Thread Safety

Compression objects are **not thread-safe**. Use per-thread instances:

```cpp
// CORRECT - per-thread compressor
void processThread(const std::string& data) {
    CryptoPP::ZlibCompressor compressor;  // Thread-local
    // ... use compressor ...
}

// WRONG - shared compressor
CryptoPP::ZlibCompressor globalCompressor;  // Race condition!
```

## See Also

- [Security Concepts: Compression Oracles](/docs/guides/security-concepts#compression-oracles) - Understanding CRIME/BREACH attacks
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - Authenticated encryption
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Pipeline filtering
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File I/O
