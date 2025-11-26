---
title: Redirector / Tee
description: Pipeline branching and data duplication utilities
weight: 10
---

**Header:** `#include <cryptopp/filters.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 5.0
**Thread Safety:** Not thread-safe per instance; use separate instances per thread

`Redirector` and `Tee` are pipeline utilities for controlling data flow. `Redirector` forwards data to another transformation without taking ownership, while `Tee` duplicates data to multiple destinations simultaneously.

## Quick Example

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string data = "Hello, World!";
std::string hash, copy;

// Tee: Send data to both hash computation AND a copy
SHA256 sha256;
StringSource(data, true,
    new Tee(
        new HashFilter(sha256,
            new HexEncoder(new StringSink(hash))
        ),
        new StringSink(copy)
    )
);

// hash = "DFFD6021BB2BD5B0..." (SHA-256)
// copy = "Hello, World!" (original data)
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use `Tee` to compute hash while writing data
- Use `Tee` for logging/debugging pipelines
- Use `Redirector` when you need non-owning reference to existing filter
- Chain multiple `Tee` for more than 2 outputs
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use `Redirector` with a filter that might be destroyed
- Don't create circular pipelines
- Be aware that `Tee` processes data twice (performance impact)
{{< /callout >}}

## Redirector

`Redirector` forwards data to a `BufferedTransformation` without taking ownership. This is useful when you want to redirect output to an existing filter or when the target has a different lifetime.

### Constructor

```cpp
Redirector(BufferedTransformation& target, bool passSignal = true);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | `BufferedTransformation&` | Destination (not owned) |
| `passSignal` | `bool` | Pass message signals to target |

### Example: Redirector

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string hash;
    HexEncoder encoder(new StringSink(hash));

    SHA256 sha256;

    // Redirector doesn't own encoder
    StringSource("Hello", true,
        new HashFilter(sha256,
            new Redirector(encoder)
        )
    );

    // encoder is still valid, can be reused
    StringSource("World", true,
        new HashFilter(sha256,
            new Redirector(encoder)
        )
    );

    // hash now contains both hashes concatenated
    std::cout << "Hashes: " << hash << std::endl;

    return 0;
}
```

## Tee

`Tee` duplicates data to two destinations. The first destination is set in the constructor, additional destinations can be added with `ChannelPut` or by chaining.

### Constructors

```cpp
// Single destination (add more later)
Tee(BufferedTransformation* attachment = nullptr);

// Two destinations
Tee(BufferedTransformation* first, BufferedTransformation* second);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `first` | `BufferedTransformation*` | First destination (owned) |
| `second` | `BufferedTransformation*` | Second destination (owned) |

## Complete Examples

### Example 1: Hash While Copying

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string data = "Important document content";
    std::string hash, backup;

    SHA256 sha256;

    // Compute hash AND keep a copy of data
    StringSource(data, true,
        new Tee(
            new HashFilter(sha256,
                new HexEncoder(new StringSink(hash))
            ),
            new StringSink(backup)
        )
    );

    std::cout << "Data: " << backup << std::endl;
    std::cout << "SHA-256: " << hash << std::endl;

    return 0;
}
```

### Example 2: Multiple Hashes at Once

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    std::string data = "Compute multiple hashes efficiently";
    std::string sha256Hash, sha3Hash, blake2Hash;

    SHA256 sha256;
    SHA3_256 sha3;
    BLAKE2b blake2b(false, 32);  // 256-bit output

    // Compute all three hashes in single pass
    StringSource(data, true,
        new Tee(
            new HashFilter(sha256,
                new HexEncoder(new StringSink(sha256Hash))
            ),
            new Tee(
                new HashFilter(sha3,
                    new HexEncoder(new StringSink(sha3Hash))
                ),
                new HashFilter(blake2b,
                    new HexEncoder(new StringSink(blake2Hash))
                )
            )
        )
    );

    std::cout << "SHA-256:   " << sha256Hash << std::endl;
    std::cout << "SHA3-256:  " << sha3Hash << std::endl;
    std::cout << "BLAKE2b:   " << blake2Hash << std::endl;

    return 0;
}
```

### Example 3: Hash and Encrypt

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[12];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Data to hash and encrypt";
    std::string hash, ciphertext;

    SHA256 sha256;
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    // Hash plaintext AND encrypt it
    StringSource(plaintext, true,
        new Tee(
            new HashFilter(sha256,
                new HexEncoder(new StringSink(hash))
            ),
            new AuthenticatedEncryptionFilter(enc,
                new StringSink(ciphertext)
            )
        )
    );

    std::cout << "Plaintext hash: " << hash << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

    return 0;
}
```

### Example 4: File Hash with Progress

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <functional>

// Custom sink for progress reporting
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

std::string hashFileWithProgress(const std::string& filename) {
    using namespace CryptoPP;

    std::string hash;
    SHA256 sha256;

    FileSource(filename, true,
        new Tee(
            new HashFilter(sha256,
                new HexEncoder(new StringSink(hash))
            ),
            new ProgressSink([](size_t bytes) {
                std::cout << "\rProcessed: " << bytes << " bytes" << std::flush;
            })
        )
    );

    std::cout << std::endl;
    return hash;
}
```

### Example 5: Write to File and Compute Hash

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>

std::string writeAndHash(const std::string& data,
                         const std::string& filename) {
    using namespace CryptoPP;

    std::string hash;
    SHA256 sha256;

    // Write to file AND compute hash
    StringSource(data, true,
        new Tee(
            new FileSink(filename),
            new HashFilter(sha256,
                new HexEncoder(new StringSink(hash))
            )
        )
    );

    return hash;
}

int main() {
    std::string data = "Content to write and hash";
    std::string hash = writeAndHash(data, "output.txt");

    std::cout << "Written to output.txt" << std::endl;
    std::cout << "SHA-256: " << hash << std::endl;

    return 0;
}
```

### Example 6: Debugging Pipeline

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>

// Debug sink that prints hex of data passing through
class DebugSink : public Bufferless<Sink> {
    std::string m_name;
public:
    DebugSink(const std::string& name) : m_name(name) {}

    size_t Put2(const byte* inString, size_t length,
                int messageEnd, bool blocking) override {
        std::cout << m_name << " (" << length << " bytes): ";
        for (size_t i = 0; i < std::min(length, size_t(32)); i++) {
            printf("%02X", inString[i]);
        }
        if (length > 32) std::cout << "...";
        std::cout << std::endl;
        return 0;
    }
};

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Debug this encryption";
    std::string ciphertext;

    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    // Debug: see data before and after encryption
    StringSource(plaintext, true,
        new Tee(
            new DebugSink("Input"),
            new StreamTransformationFilter(enc,
                new Tee(
                    new DebugSink("Output"),
                    new StringSink(ciphertext)
                )
            )
        )
    );

    return 0;
}
```

### Example 7: Using Redirector for Accumulation

```cpp
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <vector>

int main() {
    using namespace CryptoPP;

    // Accumulator that we don't want Tee to own
    std::string allHashes;
    HexEncoder hexEncoder(new StringSink(allHashes));

    std::vector<std::string> messages = {
        "Message 1",
        "Message 2",
        "Message 3"
    };

    SHA256 sha256;

    for (const auto& msg : messages) {
        // Each iteration redirects to same encoder
        StringSource(msg, true,
            new HashFilter(sha256,
                new Redirector(hexEncoder)
            )
        );
        // Add separator
        hexEncoder.Put((const byte*)"|", 1);
    }
    hexEncoder.MessageEnd();

    std::cout << "All hashes: " << allHashes << std::endl;

    return 0;
}
```

## Tee vs ChannelSwitch

For simple branching, `Tee` is easier. For complex routing with named channels, use `ChannelSwitch`:

```cpp
// Simple: Tee
new Tee(destination1, destination2)

// Complex routing: ChannelSwitch
ChannelSwitch* cs = new ChannelSwitch;
cs->AddDefaultRoute(destination1);
cs->AddRoute("channel2", destination2);
```

## Performance Considerations

`Tee` duplicates data to both destinations:

```cpp
// Data is processed twice - once per destination
StringSource(largeData, true,
    new Tee(
        new ExpensiveFilter1(...),  // Processes all data
        new ExpensiveFilter2(...)   // Also processes all data
    )
);

// For file operations, this means reading once but potentially
// writing/processing twice
```

## Memory Management

- `Tee` takes ownership of filters passed to constructor
- `Redirector` does NOT take ownership

```cpp
// Tee owns both filters - they're deleted when Tee is deleted
new Tee(
    new HashFilter(...),   // Owned by Tee
    new StringSink(...)    // Owned by Tee
)

// Redirector doesn't own target
StringSink sink(output);
new Redirector(sink);  // sink must outlive Redirector
```

## Thread Safety

Neither `Tee` nor `Redirector` are thread-safe:

```cpp
// WRONG - shared across threads
Tee* sharedTee = new Tee(...);

// CORRECT - per-thread or synchronized access
void processInThread(const std::string& data) {
    std::string hash, copy;
    SHA256 sha;

    StringSource(data, true,
        new Tee(
            new HashFilter(sha, new StringSink(hash)),
            new StringSink(copy)
        )
    );
}
```

## See Also

- [StringSource / StringSink](/docs/api/utilities/stringsource/) - String-based I/O
- [FileSource / FileSink](/docs/api/utilities/filesource/) - File-based I/O
- [HashFilter](/docs/api/utilities/hashfilter/) - Hash computation filter
- [StreamTransformationFilter](/docs/api/utilities/streamtransformationfilter/) - Encryption filter
