<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\JWSAdapterInterface;
use Enlivenapp\FlightShield\Authentication\JWT\JWSDecoder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

#[CoversClass(JWSDecoder::class)]
class JWSDecoderTest extends TestCase
{
    private function makeMockAdapter(): JWSAdapterInterface
    {
        return $this->createMock(JWSAdapterInterface::class);
    }

    #[Test]
    public function decodePassesTokenAndKeysetToAdapter(): void
    {
        $mock = $this->makeMockAdapter();
        $payload = new stdClass();

        $mock->expects($this->once())
            ->method('decode')
            ->with('raw.jwt.token', 'my-keyset')
            ->willReturn($payload);

        $decoder = new JWSDecoder([], $mock);
        $decoder->decode('raw.jwt.token', 'my-keyset');
    }

    #[Test]
    public function decodeReturnsAdaptersReturnValue(): void
    {
        $mock = $this->makeMockAdapter();
        $expected = new stdClass();
        $expected->sub = '42';

        $mock->method('decode')->willReturn($expected);

        $decoder = new JWSDecoder([], $mock);
        $result = $decoder->decode('some.jwt.token', 'default');

        $this->assertSame($expected, $result);
    }

    #[Test]
    public function decodeUsesDefaultKeysetWhenNoneSpecified(): void
    {
        $mock = $this->makeMockAdapter();
        $payload = new stdClass();

        $mock->expects($this->once())
            ->method('decode')
            ->with($this->anything(), 'default')
            ->willReturn($payload);

        $decoder = new JWSDecoder([], $mock);
        $decoder->decode('some.jwt.token');
    }
}
