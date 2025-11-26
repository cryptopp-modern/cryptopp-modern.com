---
title: FileSource / FileSink
description: File-based data sources and sinks for pipeline operations
weight: 6
---

**Header:** `#include <cryptopp/files.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

FileSource and FileSink provide efficient file I/O for the Crypto++ pipeline system. They enable memory-efficient processing of large files by streaming data through cryptographic operations without loading entire files into memory.

## Quick Example

```cpp
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Hash a file
std::string hexDigest;

FileSource("document.pdf", true,
    new HashFilter(SHA256(),
        new HexEncoder(new StringSink(hexDigest))
    )
);

std::cout << "SHA-256: " << hexDigest << std::endl;
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use `FileSource`/`FileSink` for large files (MB to GB)
- Process files in streaming mode for memory efficiency
- Use binary mode for cryptographic operations
- Handle file errors with try/catch
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use for small data (use StringSource instead)
- Don't assume files exist without error handling
- Don't mix text mode with binary crypto operations
{{< /callout >}}

## FileSource

### Constructors

```cpp
// From filename (C-string)
FileSource(const char* filename, bool pumpAll,
           BufferedTransformation* attachment = nullptr,
           bool binary = true);

// From filename (std::string) - C++11
FileSource(const std::string& filename, bool pumpAll,
           BufferedTransformation* attachment = nullptr,
           bool binary = true);

// From open stream
FileSource(std::istream& in, bool pumpAll,
           BufferedTransformation* attachment = nullptr);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | `const char*` / `std::string` | Path to input file |
| `in` | `std::istream&` | Open input stream |
| `pumpAll` | `bool` | If `true`, process entire file immediately |
| `attachment` | `BufferedTransformation*` | Next filter in pipeline |
| `binary` | `bool` | Open in binary mode (default: `true`) |

## FileSink

### Constructors

```cpp
// From filename (C-string)
FileSink(const char* filename, bool binary = true);

// From filename (std::string) - C++11
FileSink(const std::string& filename, bool binary = true);

// From open stream
FileSink(std::ostream& out);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | `const char*` / `std::string` | Path to output file |
| `out` | `std::ostream&` | Open output stream |
| `binary` | `bool` | Open in binary mode (default: `true`) |

## Complete Examples

### Example 1: Hash a File

```cpp
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

std::string hashFile(const std::string& filename) {
    using namespace CryptoPP;

    std::string hexDigest;

    SHA256 hash;
    FileSource(filename, true,
        new HashFilter(hash,
            new HexEncoder(new StringSink(hexDigest))
        )
    );

    return hexDigest;
}

int main() {
    try {
        std::string hash = hashFile("myfile.bin");
        std::cout << "SHA-256: " << hash << std::endl;
    } catch (const FileStore::OpenErr& e) {
        std::cerr << "Cannot open file: " << e.what() << std::endl;
    }
    return 0;
}
```

### Example 2: Encrypt a File

```cpp
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <iostream>

void encryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate random IV
    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    // Set up encryption
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    // Write IV to output file first, then encrypted data
    std::ofstream outFile(outputFile, std::ios::binary);
    outFile.write(reinterpret_cast<const char*>(iv), sizeof(iv));

    FileSource(inputFile, true,
        new AuthenticatedEncryptionFilter(enc,
            new FileSink(outFile)
        )
    );
}

void decryptFile(const std::string& inputFile,
                 const std::string& outputFile,
                 const SecByteBlock& key) {
    using namespace CryptoPP;

    // Read IV from beginning of file
    std::ifstream inFile(inputFile, std::ios::binary);
    byte iv[12];
    inFile.read(reinterpret_cast<char*>(iv), sizeof(iv));

    // Set up decryption
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

    // Decrypt remaining data
    FileSource(inFile, true,
        new AuthenticatedDecryptionFilter(dec,
            new FileSink(outputFile)
        )
    );
}

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate encryption key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    try {
        encryptFile("plaintext.txt", "encrypted.bin", key);
        std::cout << "File encrypted successfully" << std::endl;

        decryptFile("encrypted.bin", "decrypted.txt", key);
        std::cout << "File decrypted successfully" << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
```

### Example 3: Copy File with Progress

```cpp
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <fstream>

void copyFileWithProgress(const std::string& src, const std::string& dst) {
    using namespace CryptoPP;

    // Get file size
    std::ifstream in(src, std::ios::binary | std::ios::ate);
    size_t fileSize = in.tellg();
    in.seekg(0);

    FileSink sink(dst);
    FileSource source(in, false, new Redirector(sink));

    size_t processed = 0;
    const size_t chunkSize = 64 * 1024;  // 64KB chunks

    while (source.Pump(chunkSize)) {
        processed += chunkSize;
        int percent = (processed * 100) / fileSize;
        std::cout << "\rProgress: " << percent << "%" << std::flush;
    }
    source.PumpAll();  // Finish remaining bytes

    std::cout << "\rProgress: 100%" << std::endl;
}

int main() {
    try {
        copyFileWithProgress("large_file.bin", "copy_file.bin");
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
```

### Example 4: Compute Multiple Hashes

```cpp
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

void computeMultipleHashes(const std::string& filename) {
    using namespace CryptoPP;

    std::string sha256Hash, sha3Hash, blake2Hash;

    // Compute SHA-256
    FileSource(filename, true,
        new HashFilter(SHA256(),
            new HexEncoder(new StringSink(sha256Hash))
        )
    );

    // Compute SHA-3
    FileSource(filename, true,
        new HashFilter(SHA3_256(),
            new HexEncoder(new StringSink(sha3Hash))
        )
    );

    // Compute BLAKE2b
    FileSource(filename, true,
        new HashFilter(BLAKE2b(),
            new HexEncoder(new StringSink(blake2Hash))
        )
    );

    std::cout << "SHA-256:  " << sha256Hash << std::endl;
    std::cout << "SHA3-256: " << sha3Hash << std::endl;
    std::cout << "BLAKE2b:  " << blake2Hash << std::endl;
}
```

### Example 5: Base64 Encode a File

```cpp
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

void base64EncodeFile(const std::string& inputFile,
                      const std::string& outputFile) {
    using namespace CryptoPP;

    FileSource(inputFile, true,
        new Base64Encoder(
            new FileSink(outputFile),
            true,  // Insert line breaks
            76     // Line length
        )
    );
}

void base64DecodeFile(const std::string& inputFile,
                      const std::string& outputFile) {
    using namespace CryptoPP;

    FileSource(inputFile, true,
        new Base64Decoder(new FileSink(outputFile))
    );
}
```

### Example 6: HMAC File Authentication

```cpp
#include <cryptopp/files.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

std::string computeFileHMAC(const std::string& filename,
                            const SecByteBlock& key) {
    using namespace CryptoPP;

    HMAC<SHA256> hmac(key, key.size());
    std::string mac, hexMac;

    FileSource(filename, true,
        new HashFilter(hmac, new StringSink(mac))
    );

    StringSource(mac, true,
        new HexEncoder(new StringSink(hexMac))
    );

    return hexMac;
}

bool verifyFileHMAC(const std::string& filename,
                    const SecByteBlock& key,
                    const std::string& expectedHexMac) {
    std::string computedMac = computeFileHMAC(filename, key);
    return computedMac == expectedHexMac;
}
```

## Memory-Efficient Processing

FileSource processes files in chunks, making it suitable for large files:

```cpp
// This works for files of any size
// Memory usage is constant regardless of file size
FileSource("10GB_file.bin", true,
    new HashFilter(SHA256(),
        new HexEncoder(new StringSink(hash))
    )
);
```

### Chunked Processing with Callback

```cpp
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <functional>

class ProgressSink : public Bufferless<Sink> {
public:
    ProgressSink(std::function<void(size_t)> callback)
        : m_callback(callback), m_total(0) {}

    size_t Put2(const byte* inString, size_t length,
                int messageEnd, bool blocking) override {
        m_total += length;
        m_callback(m_total);
        return 0;
    }

private:
    std::function<void(size_t)> m_callback;
    size_t m_total;
};

void hashWithProgress(const std::string& filename) {
    using namespace CryptoPP;

    std::string hash;

    FileSource(filename, true,
        new HashFilter(SHA256(),
            new Tee(
                new HexEncoder(new StringSink(hash)),
                new ProgressSink([](size_t bytes) {
                    std::cout << "\rProcessed: " << bytes << " bytes" << std::flush;
                })
            )
        )
    );

    std::cout << std::endl << "Hash: " << hash << std::endl;
}
```

## Error Handling

```cpp
#include <cryptopp/files.h>
#include <iostream>

void safeFileOperation(const std::string& filename) {
    using namespace CryptoPP;

    try {
        std::string hash;
        FileSource(filename, true,
            new HashFilter(SHA256(),
                new HexEncoder(new StringSink(hash))
            )
        );
        std::cout << "Hash: " << hash << std::endl;

    } catch (const FileStore::OpenErr& e) {
        // File doesn't exist or can't be opened
        std::cerr << "Cannot open file: " << e.what() << std::endl;

    } catch (const FileStore::ReadErr& e) {
        // Error reading from file
        std::cerr << "Read error: " << e.what() << std::endl;

    } catch (const FileSink::OpenErr& e) {
        // Cannot create/open output file
        std::cerr << "Cannot create output file: " << e.what() << std::endl;

    } catch (const Exception& e) {
        // Other Crypto++ errors
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
    }
}
```

## Working with Streams

Use existing file streams when you need more control:

```cpp
#include <cryptopp/files.h>
#include <fstream>

void processWithStream(const std::string& filename) {
    using namespace CryptoPP;

    // Open with specific flags
    std::ifstream file(filename, std::ios::binary | std::ios::in);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    // Skip header (e.g., first 100 bytes)
    file.seekg(100);

    std::string hash;
    FileSource(file, true,
        new HashFilter(SHA256(),
            new HexEncoder(new StringSink(hash))
        )
    );
}
```

## Append Mode

FileSink opens files in truncate mode by default. For append mode:

```cpp
#include <cryptopp/files.h>
#include <fstream>

void appendToFile(const std::string& filename, const std::string& data) {
    using namespace CryptoPP;

    std::ofstream file(filename, std::ios::binary | std::ios::app);

    StringSource(data, true,
        new FileSink(file)
    );
}
```

## Performance Considerations

### Buffer Size

The default buffer size is usually optimal, but can be adjusted:

```cpp
// FileSource uses internal buffering
// For most cases, default is optimal

// For very slow storage (network drives), larger reads may help:
std::ifstream file(filename, std::ios::binary);
file.rdbuf()->pubsetbuf(buffer, bufferSize);
FileSource(file, true, ...);
```

### SSD vs HDD

- **SSD:** Default settings work well
- **HDD:** Sequential reads are faster; avoid random access patterns

### Memory-Mapped Files

For maximum performance with very large files, consider memory-mapped I/O (platform-specific, not built into Crypto++).

## Thread Safety

FileSource and FileSink are **not thread-safe**:

```cpp
// WRONG - multiple threads accessing same file
FileSource shared("file.bin", ...);  // Race condition

// CORRECT - open file per thread
void processFile(const std::string& filename) {
    FileSource(filename, true, ...);  // Thread-safe
}
```

## Platform Notes

### Windows

- Use forward slashes `/` or escaped backslashes `\\` in paths
- Binary mode is important for correct operation

```cpp
FileSource("C:/Users/name/file.bin", true, ...);
// or
FileSource("C:\\Users\\name\\file.bin", true, ...);
```

### Linux/macOS

- Paths work as expected
- Be aware of file permissions

```cpp
FileSource("/home/user/file.bin", true, ...);
```

### Unicode Filenames

For Unicode filenames, use wide string overloads or convert to UTF-8:

```cpp
// On Windows, use wide strings
FileSource(L"файл.txt", true, ...);  // If supported

// Or convert to UTF-8 (platform-dependent)
```

## See Also

- [StringSource / StringSink](/docs/api/utilities/stringsource/) - In-memory I/O
- [ArraySource / ArraySink](/docs/api/utilities/arraysource/) - Byte array I/O
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation filter
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Encryption filter
- [AES-GCM](/docs/api/symmetric/aes-gcm/) - File encryption example
