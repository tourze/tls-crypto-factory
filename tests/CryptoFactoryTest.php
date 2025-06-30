<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoFactory\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\DSA;
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed25519;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed448;
use Tourze\TLSCryptoAsymmetric\Cipher\RSA;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;
use Tourze\TLSCryptoFactory\CryptoFactory;
use Tourze\TLSCryptoFactory\Exception\CryptoException;
use Tourze\TLSCryptoHash\Contract\HashInterface;
use Tourze\TLSCryptoHash\Contract\KdfInterface;
use Tourze\TLSCryptoHash\Contract\MacInterface;
use Tourze\TLSCryptoKeyExchange\DHE;
use Tourze\TLSCryptoKeyExchange\ECDHE;
use Tourze\TLSCryptoKeyExchange\X25519;
use Tourze\TLSCryptoKeyExchange\X448;
use Tourze\TLSCryptoRandom\Contract\RandomInterface;
use Tourze\TLSCryptoSymmetric\Cipher\AesCbc;
use Tourze\TLSCryptoSymmetric\Cipher\AesCtr;
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;
use Tourze\TLSCryptoSymmetric\Cipher\ChaCha20Poly1305;
use Tourze\TLSCryptoSymmetric\Cipher\TripleDES;
use Tourze\TLSKeyFormat\CertificateHandler;
use Tourze\TLSKeyFormat\KeyHandler;
use Tourze\TLSKeyFormat\PemDerFormat;

/**
 * CryptoFactory 测试类
 */
class CryptoFactoryTest extends TestCase
{
    /**
     * 测试创建随机数生成器
     */
    public function testCreateRandom(): void
    {
        $random = CryptoFactory::createRandom();
        $this->assertInstanceOf(RandomInterface::class, $random);
    }

    /**
     * 测试创建哈希函数
     *
     * @dataProvider hashAlgorithmProvider
     */
    public function testCreateHash(string $algorithm): void
    {
        $hash = CryptoFactory::createHash($algorithm);
        $this->assertInstanceOf(HashInterface::class, $hash);
    }

    /**
     * 哈希算法数据提供者
     */
    protected static function hashAlgorithmProvider(): array
    {
        return [
            ['sha256'],
            ['sha384'],
            ['sha512'],
        ];
    }

    /**
     * 测试创建不支持的哈希函数
     */
    public function testCreateHashWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createHash('unsupported-hash');
    }

    /**
     * 测试创建消息认证码
     *
     * @dataProvider macAlgorithmProvider
     */
    public function testCreateMac(string $algorithm): void
    {
        $mac = CryptoFactory::createMac($algorithm);
        $this->assertInstanceOf(MacInterface::class, $mac);
    }

    /**
     * MAC算法数据提供者
     */
    protected static function macAlgorithmProvider(): array
    {
        return [
            ['hmac-sha256'],
            ['hmac-sha384'],
            ['hmac-sha512'],
        ];
    }

    /**
     * 测试创建不支持的MAC
     */
    public function testCreateMacWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createMac('unsupported-mac');
    }

    /**
     * 测试创建对称加密算法 - AES-GCM
     *
     * @dataProvider aesGcmProvider
     */
    public function testCreateCipherAesGcm(string $algorithm, int $expectedKeySize): void
    {
        $cipher = CryptoFactory::createCipher($algorithm);
        $this->assertInstanceOf(AesGcm::class, $cipher);
    }

    /**
     * AES-GCM算法数据提供者
     */
    protected static function aesGcmProvider(): array
    {
        return [
            ['aes-128-gcm', 128],
            ['aes-192-gcm', 192],
            ['aes-256-gcm', 256],
        ];
    }

    /**
     * 测试创建对称加密算法 - AES-CBC
     *
     * @dataProvider aesCbcProvider
     */
    public function testCreateCipherAesCbc(string $algorithm, int $expectedKeySize): void
    {
        $cipher = CryptoFactory::createCipher($algorithm);
        $this->assertInstanceOf(AesCbc::class, $cipher);
    }

    /**
     * AES-CBC算法数据提供者
     */
    protected static function aesCbcProvider(): array
    {
        return [
            ['aes-128-cbc', 128],
            ['aes-192-cbc', 192],
            ['aes-256-cbc', 256],
        ];
    }

    /**
     * 测试创建对称加密算法 - AES-CTR
     *
     * @dataProvider aesCtrProvider
     */
    public function testCreateCipherAesCtr(string $algorithm, int $expectedKeySize): void
    {
        $cipher = CryptoFactory::createCipher($algorithm);
        $this->assertInstanceOf(AesCtr::class, $cipher);
    }

    /**
     * AES-CTR算法数据提供者
     */
    protected static function aesCtrProvider(): array
    {
        return [
            ['aes-128-ctr', 128],
            ['aes-192-ctr', 192],
            ['aes-256-ctr', 256],
        ];
    }

    /**
     * 测试创建对称加密算法 - ChaCha20-Poly1305
     */
    public function testCreateCipherChaCha20Poly1305(): void
    {
        $cipher = CryptoFactory::createCipher('chacha20-poly1305');
        $this->assertInstanceOf(ChaCha20Poly1305::class, $cipher);
    }

    /**
     * 测试创建对称加密算法 - 3DES
     *
     * @dataProvider tripleDesProvider
     */
    public function testCreateCipherTripleDes(string $algorithm): void
    {
        $cipher = CryptoFactory::createCipher($algorithm);
        $this->assertInstanceOf(TripleDES::class, $cipher);
    }

    /**
     * 3DES算法数据提供者
     */
    protected static function tripleDesProvider(): array
    {
        return [
            ['3des'],
            ['des-ede3-cbc'],
            ['des-ede-cbc'],
        ];
    }

    /**
     * 测试创建不支持的对称加密算法
     */
    public function testCreateCipherWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的加密算法: unsupported-cipher');
        CryptoFactory::createCipher('unsupported-cipher');
    }

    /**
     * 测试创建密钥导出函数
     *
     * @dataProvider kdfAlgorithmProvider
     */
    public function testCreateKdf(string $algorithm): void
    {
        $kdf = CryptoFactory::createKdf($algorithm);
        $this->assertInstanceOf(KdfInterface::class, $kdf);
    }

    /**
     * KDF算法数据提供者
     */
    protected static function kdfAlgorithmProvider(): array
    {
        return [
            ['hkdf-sha256'],
            ['hkdf-sha384'],
            ['hkdf-sha512'],
        ];
    }

    /**
     * 测试创建不支持的KDF
     */
    public function testCreateKdfWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createKdf('unsupported-kdf');
    }

    /**
     * 测试创建非对称加密算法
     *
     * @dataProvider asymmetricCipherProvider
     */
    public function testCreateAsymmetricCipher(string $algorithm, string $expectedClass): void
    {
        $cipher = CryptoFactory::createAsymmetricCipher($algorithm);
        $this->assertInstanceOf($expectedClass, $cipher);
    }

    /**
     * 非对称加密算法数据提供者
     */
    protected static function asymmetricCipherProvider(): array
    {
        return [
            ['rsa', RSA::class],
            ['ed25519', Ed25519::class],
            ['ed448', Ed448::class],
            ['ecdsa', ECDSA::class],
            ['dsa', DSA::class],
        ];
    }

    /**
     * 测试创建不支持的非对称加密算法
     */
    public function testCreateAsymmetricCipherWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的非对称加密算法: unsupported-asymmetric');
        CryptoFactory::createAsymmetricCipher('unsupported-asymmetric');
    }

    /**
     * 测试创建密钥交换算法
     *
     * @dataProvider keyExchangeProvider
     */
    public function testCreateKeyExchange(string $algorithm, string $expectedClass): void
    {
        $keyExchange = CryptoFactory::createKeyExchange($algorithm);
        $this->assertInstanceOf($expectedClass, $keyExchange);
    }

    /**
     * 密钥交换算法数据提供者
     */
    protected static function keyExchangeProvider(): array
    {
        return [
            ['x25519', X25519::class],
            ['x448', X448::class],
            ['ecdhe', ECDHE::class],
            ['dhe', DHE::class],
        ];
    }

    /**
     * 测试创建不支持的密钥交换算法
     */
    public function testCreateKeyExchangeWithUnsupportedAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的密钥交换算法: unsupported-kex');
        CryptoFactory::createKeyExchange('unsupported-kex');
    }

    /**
     * 测试创建椭圆曲线
     *
     * @dataProvider curveProvider
     */
    public function testCreateCurve(string $curveName, string $expectedClass): void
    {
        $curve = CryptoFactory::createCurve($curveName);
        $this->assertInstanceOf($expectedClass, $curve);
    }

    /**
     * 椭圆曲线数据提供者
     */
    protected static function curveProvider(): array
    {
        return [
            ['nistp256', NISTP256::class],
            ['p-256', NISTP256::class],
            ['nistp384', NISTP384::class],
            ['p-384', NISTP384::class],
            ['nistp521', NISTP521::class],
            ['p-521', NISTP521::class],
            ['curve25519', Curve25519::class],
            ['curve448', Curve448::class],
        ];
    }

    /**
     * 测试创建不支持的椭圆曲线
     */
    public function testCreateCurveWithUnsupportedCurve(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的椭圆曲线: unsupported-curve');
        CryptoFactory::createCurve('unsupported-curve');
    }

    /**
     * 测试创建密钥格式处理组件
     *
     * @dataProvider keyFormatProvider
     */
    public function testCreateKeyFormat(string $type, string $expectedClass): void
    {
        $handler = CryptoFactory::createKeyFormat($type);
        $this->assertInstanceOf($expectedClass, $handler);
    }

    /**
     * 密钥格式处理类型数据提供者
     */
    protected static function keyFormatProvider(): array
    {
        return [
            ['basic', PemDerFormat::class],
            ['cert', CertificateHandler::class],
            ['key', KeyHandler::class],
        ];
    }

    /**
     * 测试创建不支持的密钥格式处理类型
     */
    public function testCreateKeyFormatWithUnsupportedType(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的密钥格式处理类型: unsupported-format');
        CryptoFactory::createKeyFormat('unsupported-format');
    }
}