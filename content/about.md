---
title: About
type: about
---

# About cryptopp-modern

cryptopp-modern is an actively maintained fork of Crypto++ 8.9.0, providing a modern cryptographic library with contemporary algorithms, better code organization, and regular security updates.

## Project Overview

cryptopp-modern builds upon the solid foundation of Wei Dai's Crypto++ library, adding modern cryptographic algorithms and maintaining active development with regular releases. The project maintains full backward compatibility with Crypto++ 8.9.0 while introducing improvements that benefit both new and existing users.

### Current Version

**2025.12.0 (Release Candidate)** - Complete source reorganization with 204 files organized into logical categories.

**2025.11.0** - Stable release with BLAKE3 and Argon2 support.

## Why Fork Crypto++?

The upstream Crypto++ project has served the community well for over two decades. However, several factors motivated the creation of cryptopp-modern:

### Technical Limitations

**Version Encoding Issue:**
The upstream versioning system encodes versions as `(MAJOR * 100) + (MINOR * 10) + PATCH`. This creates a technical limitation where version 8.10.0 cannot be properly represented. cryptopp-modern solves this with calendar versioning (YEAR.MONTH.INCREMENT).

### Active Maintenance

**Regular Releases:**
cryptopp-modern commits to regular, predictable releases following a calendar-based schedule. This ensures timely security patches and feature additions.

**Modern Algorithms:**
The fork actively integrates modern cryptographic algorithms as they become standardized and widely adopted:
- BLAKE3 (modern hash function)
- Argon2 (RFC 9106 password hashing)
- Future additions as cryptographic best practices evolve

### Better Organization

**Source Code Structure:**
Version 2025.12.0 reorganizes 204+ source files into categorized directories (core, hash, symmetric, pubkey, kdf, etc.), making the codebase easier to navigate while maintaining backward compatibility through a flat include structure.

## Key Features

### Modern Cryptographic Algorithms

- **BLAKE3**: High-performance cryptographic hash function
- **Argon2**: Password hashing (Argon2d, Argon2i, Argon2id) per RFC 9106
- **All Crypto++ 8.9.0 algorithms**: Complete compatibility with existing code

### Security Enhancements

- Security patches including fixes for CVE-2022-4304 (Marvin attack)
- ESIGN improvements
- Regular security audits and updates

### Quality Assurance

- 45+ build configurations tested across platforms
- Windows (Visual Studio, MinGW, nmake)
- Linux (GCC, Clang)
- macOS (Xcode, Clang)
- Sanitizer testing (AddressSanitizer, UndefinedBehaviorSanitizer)
- Continuous integration with automated testing

### Comprehensive Algorithm Support

**Hash Functions:** SHA-2, SHA-3, BLAKE2b/s, BLAKE3, MD5, RIPEMD, Tiger, Whirlpool, SipHash

**Symmetric Encryption:** AES, ChaCha20, Serpent, Twofish, Camellia, ARIA with modes GCM, CCM, EAX, CBC, CTR, CFB, OFB

**Public Key Cryptography:** RSA, DSA, ECDSA, Ed25519, Diffie-Hellman, ECDH, ECIES, ElGamal

**Key Derivation:** Argon2, PBKDF2, HKDF, Scrypt

**Message Authentication:** HMAC, CMAC, GMAC, Poly1305, SipHash

## Project Goals

### Compatibility First

Maintain 100% backward compatibility with Crypto++ 8.9.0. Existing code should work without modification.

### Modern Standards

Implement modern cryptographic standards (RFCs, NIST recommendations) as they emerge.

### Active Development

Regular releases with security patches, bug fixes, and new features. Responsive to community needs.

### Quality Code

Well-organized, maintainable code structure. Comprehensive testing across platforms.

### Open Source

Free and open source under the Boost Software License 1.0. No restrictions on commercial use.

## Project History

**October 2023**: Crypto++ 8.9.0 released (upstream)

**2024**: Development of cryptopp-modern begins, addressing version encoding limitations

**November 2025**: First release - cryptopp-modern 2025.11.0
- Calendar versioning introduced
- BLAKE3 support added
- Argon2 implementation included

**December 2025**: cryptopp-modern 2025.12.0 (RC)
- Complete source reorganization
- Improved build systems
- Enhanced CI/CD pipeline

## Maintainers

**CoraleSoft** maintains cryptopp-modern, building upon:
- Wei Dai's original Crypto++ implementation
- Contributions from the Crypto++ community
- Modern cryptographic research and standards

## Contributing

We welcome contributions from the community:

### Ways to Contribute

- **Bug Reports**: Report issues on [GitHub Issues](https://github.com/cryptopp-modern/cryptopp-modern/issues)
- **Bug Fixes**: Submit pull requests for bug fixes
- **New Algorithms**: Propose and implement modern cryptographic algorithms
- **Documentation**: Improve documentation and examples
- **Testing**: Test on different platforms and configurations
- **Performance**: Optimize existing implementations

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Ensure all tests pass
5. Submit a pull request

See the [GitHub repository](https://github.com/cryptopp-modern/cryptopp-modern) for detailed contribution guidelines.

## Relationship with Crypto++

cryptopp-modern is a fork, not a replacement of Crypto++. We maintain deep respect for the original project and Wei Dai's work.

### Differences

- **Version numbering**: Calendar versioning vs traditional
- **Release schedule**: Regular predictable releases
- **New algorithms**: BLAKE3, Argon2, and future additions
- **Source organization**: Categorized directory structure

### Similarities

- **Same APIs**: Drop-in compatible
- **Same namespace**: CryptoPP
- **Same license**: Boost Software License 1.0
- **Same quality**: Rigorous testing and validation

### Upstream Compatibility

Code compatible with Crypto++ 8.9.0 works with cryptopp-modern. Migration is straightforward. See the [migration guide](../docs/migration/from-cryptopp) for details.

## License

cryptopp-modern is licensed under the **Boost Software License 1.0**, the same license as Crypto++.

This license:
- ✅ Allows commercial use
- ✅ Allows modification
- ✅ Allows distribution
- ✅ Allows private use
- ✅ Provides liability limitation
- ✅ Provides warranty disclaimer
- ✅ Requires license and copyright notice

No copyleft requirements. Use freely in proprietary and open source projects.

## Platform Support

### Operating Systems

- **Linux**: Ubuntu, Debian, Fedora, RHEL, CentOS, Arch, and others
- **Windows**: Windows 10/11, Windows Server
- **macOS**: macOS 10.15 (Catalina) and later

### Compilers

- **GCC**: 4.8 and later
- **Clang**: 3.4 and later
- **MSVC**: Visual Studio 2010 and later
- **MinGW**: MinGW-w64

### Architectures

- x86_64 (64-bit Intel/AMD)
- x86 (32-bit Intel/AMD)
- ARM (32-bit and 64-bit)
- RISC-V (experimental)

## Standards Compliance

cryptopp-modern implements numerous cryptographic standards:

- **NIST FIPS**: SHA-2, SHA-3, AES
- **RFCs**: Argon2 (9106), ChaCha20 (7539), HMAC (2104), and many others
- **ISO/IEC**: Camellia (18033-3), and others
- **Industry Standards**: BLAKE3, Ed25519, and more

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **GitHub Repository**: [cryptopp-modern organization](https://github.com/cryptopp-modern)

### Getting Help

1. Check the [documentation](../docs)
2. Search [existing issues](https://github.com/cryptopp-modern/cryptopp-modern/issues)
3. Open a new issue with details
4. Join discussions in the community

## Roadmap

### Near Term

- Additional modern algorithms as standards emerge
- Performance optimizations
- Expanded documentation
- More code examples

### Long Term

- Post-quantum cryptography algorithms (as standards stabilize)
- Enhanced hardware acceleration
- Additional language bindings
- Improved cross-platform build system

See the [ROADMAP.md](https://github.com/cryptopp-modern/cryptopp-modern/blob/main/ROADMAP.md) in the repository for detailed plans.

## Acknowledgments

cryptopp-modern stands on the shoulders of giants:

- **Wei Dai**: Creator of Crypto++, foundational implementation
- **Crypto++ Contributors**: Years of contributions and improvements
- **Cryptographic Researchers**: Algorithm designers and analysts
- **Standards Bodies**: NIST, IETF, ISO for standardization work
- **Community**: Users providing feedback, bug reports, and contributions

## Links

- **GitHub Organization**: [github.com/cryptopp-modern](https://github.com/cryptopp-modern)
- **Main Repository**: [cryptopp-modern/cryptopp-modern](https://github.com/cryptopp-modern/cryptopp-modern)
- **Documentation Site**: [cryptopp-modern.com](https://cryptopp-modern.com)
- **Releases**: [GitHub Releases](https://github.com/cryptopp-modern/cryptopp-modern/releases)

---

**cryptopp-modern**: Modern cryptography for modern applications.
