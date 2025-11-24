# cryptopp-modern.com

Official documentation website for [cryptopp-modern](https://github.com/cryptopp-modern/cryptopp-modern).

## About

This repository contains the Hugo source for the cryptopp-modern documentation site hosted at https://cryptopp-modern.com

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
