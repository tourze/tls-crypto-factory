# TLS 加密组件工厂

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/ci.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Coverage Status](https://img.shields.io/codecov/c/github/tourze/php-monorepo/master.svg?style=flat-square)](https://codecov.io/gh/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)
[![License](https://img.shields.io/packagist/l/tourze/tls-crypto-factory.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-factory)

一个全面的 TLS 加密组件工厂，提供统一的接口来创建和管理各种加密算法，包括对称/非对称加密、哈希、密钥交换和数字签名。

## 特性

- **统一工厂模式**：所有加密组件的单一访问点
- **对称加密**：支持 AES (GCM/CBC/CTR)、ChaCha20-Poly1305、3DES
- **非对称加密**：支持 RSA、ECDSA、DSA、Ed25519、Ed448
- **哈希函数**：SHA-256、SHA-384、SHA-512 及 HMAC 变体
- **密钥交换**：X25519、X448、ECDHE、DHE 算法
- **椭圆曲线**：NIST P-256/P-384/P-521、Curve25519、Curve448
- **密钥格式处理**：PEM/DER 转换、证书和密钥处理
- **随机数生成**：密码学安全的随机数生成器
- **密钥推导**：支持多种哈希算法的 HKDF
- **PHP 8.1+ 兼容**：现代 PHP 严格类型支持

## 系统要求

- PHP 8.1 或更高版本
- ext-gmp 扩展
- ext-hash 扩展
- ext-openssl 扩展
- paragonie/sodium_compat
- phpseclib/phpseclib

## 安装

```bash
composer require tourze/tls-crypto-factory
```

## 快速开始

```php
<?php

use Tourze\TLSCryptoFactory\CryptoFactory;

// 创建随机数生成器
$random = CryptoFactory::createRandom();
$randomBytes = $random->generateBytes(32);

// 创建哈希函数
$hash = CryptoFactory::createHash('sha256');
$digest = $hash->hash('Hello World');

// 创建对称加密
$cipher = CryptoFactory::createCipher('aes-256-gcm');
$key = $random->generateBytes(32);
$plaintext = 'Secret message';
$encrypted = $cipher->encrypt($plaintext, $key);

// 创建非对称加密
$rsa = CryptoFactory::createAsymmetricCipher('rsa');
$keyPair = $rsa->generateKeyPair(2048);
$signature = $rsa->sign($plaintext, $keyPair['private']);

// 创建密钥交换
$x25519 = CryptoFactory::createKeyExchange('x25519');
$clientKeys = $x25519->generateKeyPair();
$serverKeys = $x25519->generateKeyPair();
$sharedSecret = $x25519->computeSharedSecret($clientKeys['private'], $serverKeys['public']);

// 创建椭圆曲线
$curve = CryptoFactory::createCurve('nistp256');
$point = $curve->generatePoint();

// 创建消息认证码
$mac = CryptoFactory::createMac('hmac-sha256');
$key = $random->generateBytes(32);
$tag = $mac->compute('message', $key);

// 创建密钥推导函数
$kdf = CryptoFactory::createKdf('hkdf-sha256');
$derivedKey = $kdf->derive($sharedSecret, 32, 'application-specific-info');
```

## 支持的算法

### 对称加密
- **AES**：aes-128-gcm、aes-192-gcm、aes-256-gcm
- **AES**：aes-128-cbc、aes-192-cbc、aes-256-cbc
- **AES**：aes-128-ctr、aes-192-ctr、aes-256-ctr
- **ChaCha20-Poly1305**：chacha20-poly1305
- **3DES**：3des、des-ede3-cbc、des-ede-cbc

### 非对称加密
- **RSA**：rsa
- **ECDSA**：ecdsa
- **DSA**：dsa
- **Ed25519**：ed25519
- **Ed448**：ed448

### 哈希函数
- **SHA-2**：sha256、sha384、sha512
- **HMAC**：hmac-sha256、hmac-sha384、hmac-sha512

### 密钥交换
- **X25519**：x25519
- **X448**：x448
- **ECDHE**：ecdhe
- **DHE**：dhe

### 椭圆曲线
- **NIST**：nistp256 (p-256)、nistp384 (p-384)、nistp521 (p-521)
- **Curve25519**：curve25519
- **Curve448**：curve448

### 密钥推导函数
- **HKDF**：hkdf-sha256、hkdf-sha384、hkdf-sha512

### 密钥格式处理
- **基础**：PEM/DER 格式转换
- **证书**：X.509 证书处理
- **密钥**：私钥/公钥处理

## 错误处理

当出现以下情况时，所有工厂方法都会抛出 `Tourze\TLSCryptoFactory\Exception\CryptoException` 异常：
- 请求不支持的算法
- 提供无效参数
- 底层加密操作失败

```php
try {
    $cipher = CryptoFactory::createCipher('unsupported-algorithm');
} catch (\Tourze\TLSCryptoFactory\Exception\CryptoException $e) {
    echo '加密错误：' . $e->getMessage();
}
```

## 架构

此包作为工厂层，协调多个专门的加密包：

- `tourze/tls-crypto-symmetric` - 对称加密算法
- `tourze/tls-crypto-asymmetric` - 非对称加密和数字签名
- `tourze/tls-crypto-hash` - 哈希函数、MAC 和 KDF
- `tourze/tls-crypto-keyexchange` - 密钥交换算法
- `tourze/tls-crypto-curves` - 椭圆曲线实现
- `tourze/tls-crypto-random` - 密码学安全随机数生成器
- `tourze/tls-key-format` - 密钥和证书格式处理

## 测试

```bash
composer test
```

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

MIT 许可证。详细信息请查看 [许可证文件](LICENSE)。
