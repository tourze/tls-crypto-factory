# TLS Crypto Factory

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/ci.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Coverage Status](https://img.shields.io/codecov/c/github/tourze/php-monorepo/master.svg?style=flat-square)](https://codecov.io/gh/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)
[![License](https://img.shields.io/packagist/l/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)

A comprehensive TLS cryptographic component factory that provides a unified interface for creating and managing various cryptographic algorithms including symmetric/asymmetric encryption, hashing, key exchange, and digital signatures.

## Features

- **Unified Factory Pattern**: Single point of access for all cryptographic components
- **Symmetric Encryption**: AES (GCM/CBC/CTR), ChaCha20-Poly1305, 3DES support
- **Asymmetric Encryption**: RSA, ECDSA, DSA, Ed25519, Ed448 support
- **Hash Functions**: SHA-256, SHA-384, SHA-512 with HMAC variants
- **Key Exchange**: X25519, X448, ECDHE, DHE algorithms
- **Elliptic Curves**: NIST P-256/P-384/P-521, Curve25519, Curve448
- **Key Format Handling**: PEM/DER conversion, certificate and key processing
- **Random Number Generation**: Cryptographically secure random generators
- **Key Derivation**: HKDF with multiple hash algorithms
- **PHP 8.1+ Compatible**: Modern PHP with strict typing

## Requirements

- PHP 8.1 or higher
- ext-gmp extension
- ext-hash extension
- ext-openssl extension
- paragonie/sodium_compat
- phpseclib/phpseclib

## Installation

```bash
composer require tourze/tls-crypto-factory
```

## Quick Start

```php
<?php

use Tourze\TLSCryptoFactory\CryptoFactory;

// Create a random number generator
$random = CryptoFactory::createRandom();
$randomBytes = $random->generateBytes(32);

// Create hash functions
$hash = CryptoFactory::createHash('sha256');
$digest = $hash->hash('Hello World');

// Create symmetric encryption
$cipher = CryptoFactory::createCipher('aes-256-gcm');
$key = $random->generateBytes(32);
$plaintext = 'Secret message';
$encrypted = $cipher->encrypt($plaintext, $key);

// Create asymmetric encryption
$rsa = CryptoFactory::createAsymmetricCipher('rsa');
$keyPair = $rsa->generateKeyPair(2048);
$signature = $rsa->sign($plaintext, $keyPair['private']);

// Create key exchange
$x25519 = CryptoFactory::createKeyExchange('x25519');
$clientKeys = $x25519->generateKeyPair();
$serverKeys = $x25519->generateKeyPair();
$sharedSecret = $x25519->computeSharedSecret($clientKeys['private'], $serverKeys['public']);

// Create elliptic curves
$curve = CryptoFactory::createCurve('nistp256');
$point = $curve->generatePoint();

// Create MAC
$mac = CryptoFactory::createMac('hmac-sha256');
$key = $random->generateBytes(32);
$tag = $mac->compute('message', $key);

// Create KDF
$kdf = CryptoFactory::createKdf('hkdf-sha256');
$derivedKey = $kdf->derive($sharedSecret, 32, 'application-specific-info');
```

## Supported Algorithms

### Symmetric Encryption
- **AES**: aes-128-gcm, aes-192-gcm, aes-256-gcm
- **AES**: aes-128-cbc, aes-192-cbc, aes-256-cbc
- **AES**: aes-128-ctr, aes-192-ctr, aes-256-ctr
- **ChaCha20-Poly1305**: chacha20-poly1305
- **3DES**: 3des, des-ede3-cbc, des-ede-cbc

### Asymmetric Encryption
- **RSA**: rsa
- **ECDSA**: ecdsa
- **DSA**: dsa
- **Ed25519**: ed25519
- **Ed448**: ed448

### Hash Functions
- **SHA-2**: sha256, sha384, sha512
- **HMAC**: hmac-sha256, hmac-sha384, hmac-sha512

### Key Exchange
- **X25519**: x25519
- **X448**: x448
- **ECDHE**: ecdhe
- **DHE**: dhe

### Elliptic Curves
- **NIST**: nistp256 (p-256), nistp384 (p-384), nistp521 (p-521)
- **Curve25519**: curve25519
- **Curve448**: curve448

### Key Derivation Functions
- **HKDF**: hkdf-sha256, hkdf-sha384, hkdf-sha512

### Key Format Handling
- **Basic**: PEM/DER format conversion
- **Certificate**: X.509 certificate processing
- **Key**: Private/public key handling

## Error Handling

All factory methods throw `Tourze\TLSCryptoFactory\Exception\CryptoException` when:
- Unsupported algorithm is requested
- Invalid parameters are provided
- Underlying cryptographic operations fail

```php
try {
    $cipher = CryptoFactory::createCipher('unsupported-algorithm');
} catch (\Tourze\TLSCryptoFactory\Exception\CryptoException $e) {
    echo 'Crypto error: ' . $e->getMessage();
}
```

## Architecture

This package serves as a factory layer that coordinates multiple specialized cryptographic packages:

- `tourze/tls-crypto-symmetric` - Symmetric encryption algorithms
- `tourze/tls-crypto-asymmetric` - Asymmetric encryption and digital signatures
- `tourze/tls-crypto-hash` - Hash functions, MAC, and KDF
- `tourze/tls-crypto-keyexchange` - Key exchange algorithms
- `tourze/tls-crypto-curves` - Elliptic curve implementations
- `tourze/tls-crypto-random` - Cryptographically secure random generators
- `tourze/tls-key-format` - Key and certificate format handling

## Testing

```bash
composer test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
