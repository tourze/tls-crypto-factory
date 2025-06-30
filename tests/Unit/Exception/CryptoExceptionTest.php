<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoFactory\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoFactory\Exception\CryptoException;

/**
 * CryptoException 测试类
 */
class CryptoExceptionTest extends TestCase
{
    /**
     * 测试异常基本功能
     */
    public function testExceptionCreation(): void
    {
        $message = 'Test exception message';
        $code = 123;
        $previous = new \RuntimeException('Previous exception');

        $exception = new CryptoException($message, $code, $previous);

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试空消息的异常创建
     */
    public function testExceptionWithEmptyMessage(): void
    {
        $exception = new CryptoException();

        $this->assertSame('', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试异常继承关系
     */
    public function testExceptionInheritance(): void
    {
        $exception = new CryptoException('Test message');
        
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertInstanceOf(\Throwable::class, $exception);
    }
}