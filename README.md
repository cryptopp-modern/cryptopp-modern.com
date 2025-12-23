# cryptopp-modern.com

Official documentation website for **[cryptopp-modern](https://github.com/cryptopp-modern/cryptopp-modern)**.

> **cryptopp-modern** is a community fork of Crypto++ 8.9.0 that adds modern primitives (Argon2, BLAKE3, XChaCha20-Poly1305, etc.), security fixes, and more regular releases.

---

## About

This repository contains the Hugo source for the cryptopp-modern documentation site hosted at:

- https://cryptopp-modern.com

---

## Documentation Coverage

### API Reference

#### Symmetric Encryption

- **AES-GCM** – Authenticated encryption (recommended)
- **XAES-256-GCM** – Extended nonce AES-GCM (safe random nonces)
- **AES-EAX** – Two-pass AEAD
- **AES-CCM** – Wi-Fi/Bluetooth/TLS AEAD
- **AES-CTR-HMAC** – CTR mode with HMAC (automatic key derivation)
- **ChaCha20-Poly1305** – Modern AEAD cipher
- **XChaCha20-Poly1305** – Extended nonce AEAD
- **AES-CBC** – Block cipher mode (legacy)
- **AES-CBC-HMAC** – Authenticated CBC (encrypt-then-MAC)
- **AES-CTR** – Counter mode
- **Twofish** – AES finalist cipher

#### Hash Functions

- **BLAKE3** – Fast modern hash
- **BLAKE2** – High-speed hash (RFC 7693)
- **SHA-256** – Standard hash
- **SHA-512** – 512-bit hash
- **SHA-3** – Keccak-based hash
- **SHA-1** – Legacy (deprecated)
- **MD5** – Legacy (broken)

#### Key Derivation & Password Hashing

- **Argon2** – Password hashing (recommended)
- **scrypt** – Memory-hard KDF
- **HKDF** – Key derivation from secrets
- **PBKDF2** – Legacy password KDF

#### Public-Key Cryptography

- **X25519** – Key exchange (recommended)
- **Ed25519** – Digital signatures
- **ECDSA** – Elliptic curve signatures
- **ECDH** – Elliptic curve key exchange
- **RSA** – Traditional public-key

#### Message Authentication

- **HMAC** – Hash-based MAC
- **CMAC** – Cipher-based MAC
- **Poly1305** – Fast MAC

#### Utilities

- **AutoSeededRandomPool** – Secure RNG
- **SecByteBlock** – Secure memory
- **HexEncoder** – Hex encoding
- **Base64Encoder** – Base64 encoding
- **Integer** – Big integer arithmetic
- **StringSource** – String input pipeline
- **FileSource** – File input pipeline
- **ArraySource** – Array input pipeline
- **HashFilter** – Hashing pipeline
- **SignerFilter** – Signing pipeline
- **StreamTransformationFilter** – Cipher pipeline
- **AuthenticatedEncryptionFilter** – AEAD pipeline
- **Redirector** – Pipeline routing
- **Compression** – Zlib/Gzip compression

---

## Local Development

### Prerequisites

- Hugo Extended **v0.139.0** or later
- Git

### Running Locally

```bash
# Clone the repository
git clone https://github.com/cryptopp-modern/cryptopp-modern.com.git
cd cryptopp-modern.com

# Initialise theme
git submodule update --init --recursive

# Run Hugo development server
hugo server -D

# Visit http://localhost:1313
```

### Building

```bash
hugo --minify
```

Output will be in the `public/` directory.

---

## Project Structure

```text
content/           # Documentation content (Markdown)
static/            # Static assets (images, CSS, JS)
layouts/           # Custom Hugo layouts
themes/            # Hugo theme (git submodule)
hugo.yaml          # Hugo configuration
```

---

## Contributing

Contributions to improve the documentation are welcome! Please:

1. Fork this repository
2. Create a branch for your changes
3. Make your edits to the Markdown files in `content/`
4. Test locally with `hugo server -D`
5. Submit a pull request

### Writing Guidelines

- Use clear, concise language
- Include code examples where appropriate
- Test all code examples before submitting
- Follow the existing documentation structure

---

## Deployment

This site is automatically deployed to **Cloudflare Pages**.

- **Production:** https://cryptopp-modern.com (main branch)
- **Preview:** Pull requests get automatic preview deployments

### Build Settings (Cloudflare Pages)

- **Framework preset:** Hugo
- **Build command:** `hugo --minify`
- **Build output directory:** `public`
- **Environment variables:**
  - `HUGO_VERSION` = `0.139.0`
  - `HUGO_ENV` = `production`

---

## License

- **Documentation content:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Code samples:** Boost Software License 1.0 (same as cryptopp-modern)

See [LICENSE](LICENSE) for full details.

---

**Maintained by:** [cryptopp-modern organization](https://github.com/cryptopp-modern)
