<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoFactory;

use Tourze\TLSCryptoAsymmetric\Cipher\DSA;
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed25519;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed448;
use Tourze\TLSCryptoAsymmetric\Cipher\RSA;
use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;
use Tourze\TLSCryptoFactory\Exception\CryptoException;
use Tourze\TLSCryptoHash\Contract\HashInterface;
use Tourze\TLSCryptoHash\Contract\MacInterface;
use Tourze\TLSCryptoHash\HashFactory;
use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\DHE;
use Tourze\TLSCryptoKeyExchange\ECDHE;
use Tourze\TLSCryptoKeyExchange\X25519;
use Tourze\TLSCryptoKeyExchange\X448;
use Tourze\TLSCryptoRandom\Contract\RandomInterface;
use Tourze\TLSCryptoRandom\CryptoRandom;
use Tourze\TLSCryptoSymmetric\Cipher\AesCbc;
use Tourze\TLSCryptoSymmetric\Cipher\AesCtr;
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;
use Tourze\TLSCryptoSymmetric\Cipher\ChaCha20Poly1305;
use Tourze\TLSCryptoSymmetric\Cipher\TripleDES;
use Tourze\TLSCryptoSymmetric\Contract\CipherInterface;
use Tourze\TLSKeyFormat\CertificateHandler;
use Tourze\TLSKeyFormat\KeyHandler;
use Tourze\TLSKeyFormat\PemDerFormat;

/**
 * 加密组件工厂类
 */
class CryptoFactory
{
    /**
     * 创建随机数生成器
     *
     * @return RandomInterface
     */
    public static function createRandom(): RandomInterface
    {
        return new CryptoRandom();
    }

    /**
     * 创建哈希函数
     *
     * @param string $algorithm 哈希算法名称
     * @return HashInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createHash(string $algorithm): HashInterface
    {
        try {
            return HashFactory::createHash($algorithm);
        } catch (\Tourze\TLSCryptoHash\Exception\CryptoException $e) {
            throw new CryptoException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * 创建消息认证码
     *
     * @param string $algorithm MAC算法名称
     * @param array $options 选项
     * @return MacInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createMac(string $algorithm, array $options = []): MacInterface
    {
        try {
            return HashFactory::createMac($algorithm, $options);
        } catch (\Tourze\TLSCryptoHash\Exception\CryptoException $e) {
            throw new CryptoException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * 创建对称加密算法
     *
     * @param string $algorithm 加密算法名称
     * @param array $options 选项
     * @return CipherInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createCipher(string $algorithm, array $options = []): CipherInterface
    {
        if (preg_match('/^aes-(\d+)-gcm$/', $algorithm, $matches)) {
            $keySize = (int)$matches[1];
            return new AesGcm($keySize);
        }

        if (preg_match('/^aes-(\d+)-cbc$/', $algorithm, $matches)) {
            $keySize = (int)$matches[1];
            return new AesCbc($keySize);
        }

        if (preg_match('/^aes-(\d+)-ctr$/', $algorithm, $matches)) {
            $keySize = (int)$matches[1];
            return new AesCtr($keySize);
        }

        if ($algorithm === 'chacha20-poly1305') {
            return new ChaCha20Poly1305();
        }

        if (in_array($algorithm, ['3des', 'des-ede3-cbc', 'des-ede-cbc'])) {
            $keySize = 192; // 默认使用192位密钥（完全版本的3DES）
            if ($algorithm === 'des-ede-cbc') {
                $keySize = 128; // 使用128位密钥（兼容版本）
            }
            return new TripleDES($keySize);
        }

        throw new CryptoException('不支持的加密算法: ' . $algorithm);
    }

    /**
     * 创建密钥导出函数
     *
     * @param string $algorithm KDF算法名称
     * @param array $options 选项
     * @return \Tourze\TLSCryptoHash\Contract\KdfInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createKdf(string $algorithm, array $options = []): \Tourze\TLSCryptoHash\Contract\KdfInterface
    {
        try {
            return HashFactory::createKdf($algorithm, $options);
        } catch (\Tourze\TLSCryptoHash\Exception\CryptoException $e) {
            throw new CryptoException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * 创建非对称加密算法
     *
     * @param string $algorithm 算法名称
     * @param array $options 选项
     * @return AsymmetricCipherInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createAsymmetricCipher(string $algorithm, array $options = []): AsymmetricCipherInterface
    {
        return match ($algorithm) {
            'rsa' => new RSA(),
            'ed25519' => new Ed25519(),
            'ed448' => new Ed448(),
            'ecdsa' => new ECDSA(),
            'dsa' => new DSA(),
            default => throw new CryptoException('不支持的非对称加密算法: ' . $algorithm),
        };
    }

    /**
     * 创建密钥交换算法
     *
     * @param string $algorithm 算法名称
     * @param array $options 选项
     * @return KeyExchangeInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createKeyExchange(string $algorithm, array $options = []): KeyExchangeInterface
    {
        return match ($algorithm) {
            'x25519' => new X25519(),
            'x448' => new X448(),
            'ecdhe' => new ECDHE(),
            'dhe' => new DHE(),
            default => throw new CryptoException('不支持的密钥交换算法: ' . $algorithm),
        };
    }

    /**
     * 创建椭圆曲线
     *
     * @param string $curveName 曲线名称
     * @return CurveInterface
     * @throws CryptoException 如果曲线不支持
     */
    public static function createCurve(string $curveName): CurveInterface
    {
        return match ($curveName) {
            'nistp256', 'p-256' => new NISTP256(),
            'nistp384', 'p-384' => new NISTP384(),
            'nistp521', 'p-521' => new NISTP521(),
            'curve25519' => new Curve25519(),
            'curve448' => new Curve448(),
            default => throw new CryptoException('不支持的椭圆曲线: ' . $curveName),
        };
    }

    /**
     * 创建密钥格式处理组件
     *
     * @param string $type 处理类型，可选值：'basic'（基本PEM/DER转换）、'cert'（证书处理）、'key'（密钥处理）
     * @return object 相应的处理类实例
     * @throws CryptoException 如果类型不支持
     */
    public static function createKeyFormat(string $type): object
    {
        return match ($type) {
            'basic' => new PemDerFormat(),
            'cert' => new CertificateHandler(),
            'key' => new KeyHandler(),
            default => throw new CryptoException('不支持的密钥格式处理类型: ' . $type),
        };
    }
}
