# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current          |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

**Email**: latticesafe@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response
within 7 days.

## Security Properties

This crate implements ML-KEM (FIPS 203) with the following security measures:

- **Constant-time decapsulation** — implicit rejection prevents chosen-ciphertext attacks
- **Zeroization** — secret key material is zeroized on drop
- **No unsafe code** — pure safe Rust
- **Barrett & Montgomery reduction** — side-channel resistant arithmetic
- **Bit-for-bit parity** with the [pq-crystals/kyber](https://github.com/pq-crystals/kyber) C reference

## Scope

This policy covers the `lattice-kyber` crate published on [crates.io](https://crates.io/crates/lattice-kyber).
