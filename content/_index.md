---
title: cryptopp-modern - Modern C++ Cryptography Library
description: "Modern cryptographic library for C++ with BLAKE3, Argon2, AES-GCM. Actively maintained fork of Crypto++ with comprehensive documentation and security best practices."
keywords: ["cryptography", "C++ crypto library", "BLAKE3", "Argon2", "AES encryption", "password hashing", "cryptopp", "crypto++", "modern cryptography", "open source crypto"]
layout: hextra-home
---

<div class="hx-mt-6 hx-mb-6">
{{< hextra/hero-headline >}}
  Modern Cryptography&nbsp;<br class="sm:hx-block hx-hidden" />for C++
{{< /hextra/hero-headline >}}
</div>

<div class="hx-mb-12">
{{< hextra/hero-subtitle >}}
  Actively maintained fork of Crypto++ with modern algorithms,&nbsp;<br class="sm:hx-block hx-hidden" />better organisation, and regular security updates.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx-mb-6">
{{< hextra/hero-button text="Get Started" link="docs" >}}
{{< hextra/hero-button text="View on GitHub" link="https://github.com/cryptopp-modern/cryptopp-modern" >}}
</div>

<div class="hx-mt-16"></div>

## Why cryptopp-modern?

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="🔐 Modern Algorithms"
    subtitle="BLAKE3 hash function and Argon2 password hashing (RFC 9106) - algorithms designed for today's security requirements."
  >}}
  {{< hextra/feature-card
    title="🔄 Active Maintenance"
    subtitle="Regular releases with security patches. Calendar versioning (2025.12.0) for clear release tracking."
  >}}
  {{< hextra/feature-card
    title="📦 Drop-in Compatible"
    subtitle="Full backward compatibility with Crypto++ 8.9.0. Same namespace, same APIs. Easy migration."
  >}}
  {{< hextra/feature-card
    title="🏗️ Better Organisation"
    subtitle="Source files organised in categorised directories. Easier to navigate and understand."
  >}}
  {{< hextra/feature-card
    title="✅ Thoroughly Tested"
    subtitle="45+ build configurations across Windows, Linux, and macOS. Sanitizer testing for memory safety."
  >}}
  {{< hextra/feature-card
    title="🆓 Free & Open Source"
    subtitle="Boost Software License 1.0. All code is public. No restrictions on commercial use."
  >}}
{{< /hextra/feature-grid >}}

<div class="hx-mt-16"></div>

## Quick Example

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

<div class="hx-mt-16"></div>

## What's New in 2025.12.0

- **Complete reorganisation** - 204 source files organised into logical categories
- **Multi-platform CI/CD** - Automated testing on all major platforms
- **Updated build systems** - GNUmakefile, Visual Studio, and nmake all updated
- **Backward compatible** - Drop-in replacement maintaining the same include structure

[View Full Changelog →](https://github.com/cryptopp-modern/cryptopp-modern/blob/main/ROADMAP.md)
