# cryptopp-modern.com

Official documentation website for [cryptopp-modern](https://github.com/cryptopp-modern/cryptopp-modern).

## About

This repository contains the Hugo source for the cryptopp-modern documentation site hosted at https://cryptopp-modern.com

## Documentation Coverage

### API Reference

#### Symmetric Encryption
- [AES-GCM](/content/docs/api/symmetric/AES-GCM.md) - Authenticated encryption (recommended)
- [ChaCha20-Poly1305](/content/docs/api/symmetric/ChaCha20-Poly1305.md) - Modern AEAD cipher
- [XChaCha20-Poly1305](/content/docs/api/symmetric/XChaCha20-Poly1305.md) - Extended nonce AEAD
- [AES-CBC](/content/docs/api/symmetric/AES-CBC.md) - Block cipher mode
- [AES-CBC-HMAC](/content/docs/api/symmetric/AES-CBC-HMAC.md) - Authenticated CBC
- [AES-CTR](/content/docs/api/symmetric/AES-CTR.md) - Counter mode
- [Twofish](/content/docs/api/symmetric/Twofish.md) - AES finalist cipher

#### Hash Functions
- [BLAKE3](/content/docs/api/hash/BLAKE3.md) - Fastest modern hash
- [BLAKE2](/content/docs/api/hash/BLAKE2.md) - High-speed hash (RFC 7693)
- [SHA-256](/content/docs/api/hash/SHA256.md) - Standard hash
- [SHA-512](/content/docs/api/hash/SHA512.md) - 512-bit hash
- [SHA-3](/content/docs/api/hash/SHA3.md) - Keccak-based hash
- [SHA-1](/content/docs/api/hash/SHA1.md) - Legacy (deprecated)
- [MD5](/content/docs/api/hash/MD5.md) - Legacy (broken)

#### Key Derivation & Password Hashing
- [Argon2](/content/docs/api/kdf/Argon2.md) - Password hashing (recommended)
- [scrypt](/content/docs/api/kdf/scrypt.md) - Memory-hard KDF
- [HKDF](/content/docs/api/kdf/HKDF.md) - Key derivation from secrets
- [PBKDF2](/content/docs/api/kdf/PBKDF2.md) - Legacy password KDF

#### Public-Key Cryptography
- [X25519](/content/docs/api/pubkey/X25519.md) - Key exchange (recommended)
- [Ed25519](/content/docs/api/pubkey/Ed25519.md) - Digital signatures
- [ECDSA](/content/docs/api/pubkey/ECDSA.md) - Elliptic curve signatures
- [ECDH](/content/docs/api/pubkey/ECDH.md) - Elliptic curve key exchange
- [RSA](/content/docs/api/pubkey/RSA.md) - Traditional public-key

#### Message Authentication
- [HMAC](/content/docs/api/mac/HMAC.md) - Hash-based MAC

#### Utilities
- [AutoSeededRandomPool](/content/docs/api/utilities/AutoSeededRandomPool.md) - Secure RNG
- [SecByteBlock](/content/docs/api/utilities/SecByteBlock.md) - Secure memory
- [HexEncoder](/content/docs/api/utilities/HexEncoder.md) - Hex encoding
- [Base64Encoder](/content/docs/api/utilities/Base64Encoder.md) - Base64 encoding
- [Integer](/content/docs/api/utilities/Integer.md) - Big integer arithmetic
- [AuthenticatedEncryptionFilter](/content/docs/api/utilities/AuthenticatedEncryptionFilter.md) - AEAD pipeline
- [Redirector](/content/docs/api/utilities/Redirector.md) - Pipeline routing

## Local Development

### Prerequisites
- Hugo Extended v0.139.0 or later
- Git

### Running Locally

```bash
# Clone the repository
git clone https://github.com/cryptopp-modern/cryptopp-modern.com.git
cd cryptopp-modern.com

# Install theme (after theme is added)
git submodule update --init --recursive

# Run Hugo development server
hugo server -D

# Visit http://localhost:1313
```

## Building

```bash
hugo --minify
```

Output will be in `public/` directory.

## Project Structure

```
content/           # Documentation content (markdown)
static/            # Static assets (images, CSS, JS)
layouts/           # Custom Hugo layouts
themes/            # Hugo theme (git submodule)
config.toml        # Hugo configuration
```

## Contributing

Contributions to improve documentation are welcome! Please:

1. Fork this repository
2. Create a branch for your changes
3. Make your edits to the markdown files in `content/`
4. Test locally with `hugo server -D`
5. Submit a pull request

### Writing Guidelines

- Use clear, concise language
- Include code examples where appropriate
- Test all code examples before submitting
- Follow the existing documentation structure

## Deployment

This site is automatically deployed to Cloudflare Pages:

- **Production:** https://cryptopp-modern.com (main branch)
- **Preview:** Pull requests get automatic preview deployments

### Build Settings (Cloudflare Pages)

- **Framework preset:** Hugo
- **Build command:** `hugo --minify`
- **Build output directory:** `public`
- **Environment variables:**
  - `HUGO_VERSION` = `0.139.0`
  - `HUGO_ENV` = `production`

## License

- **Documentation content:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Code samples:** Boost Software License 1.0 (same as cryptopp-modern)

See [LICENSE](LICENSE) for full details.

---

**Maintained by:** [cryptopp-modern organization](https://github.com/cryptopp-modern)
