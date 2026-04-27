<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\JWSAdapterInterface;
use Enlivenapp\FlightShield\Authentication\JWT\JWSEncoder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(JWSEncoder::class)]
class JWSEncoderTest extends TestCase
{
    private function makeConfig(array $overrides = []): array
    {
        return array_merge([
            'default_claims' => ['iss' => 'test-issuer'],
            'time_to_live'   => 3600,
            'keys' => [
                'default' => [
                    ['kid' => '', 'alg' => 'HS256', 'secret' => 'test'],
                ],
            ],
        ], $overrides);
    }

    private function makeMockAdapter(): JWSAdapterInterface
    {
        return $this->createMock(JWSAdapterInterface::class);
    }

    #[Test]
    public function encodeAddsIatIfNotPresent(): void
    {
        $before = time();

        $mock = $this->makeMockAdapter();
        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use ($before): bool {
                    return isset($payload['iat'])
                        && $payload['iat'] >= $before
                        && $payload['iat'] <= time();
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $encoder->encode(['sub' => '1']);
    }

    #[Test]
    public function encodeAddsExpAsIatPlusTimeToLive(): void
    {
        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(['time_to_live' => 3600]), $mock);
        $encoder->encode(['sub' => '1']);

        $this->assertArrayHasKey('exp', $capturedPayload);
        $this->assertArrayHasKey('iat', $capturedPayload);
        $this->assertSame($capturedPayload['iat'] + 3600, $capturedPayload['exp']);
    }

    #[Test]
    public function encodeWithCustomTtlOverridesDefaultTimeToLive(): void
    {
        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(['time_to_live' => 3600]), $mock);
        $encoder->encode(['sub' => '1'], 7200);

        $this->assertSame($capturedPayload['iat'] + 7200, $capturedPayload['exp']);
    }

    #[Test]
    public function encodeWithExplicitExpPreservesIt(): void
    {
        $explicitExp = time() + 9999;

        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $encoder->encode(['sub' => '1', 'exp' => $explicitExp]);

        $this->assertSame($explicitExp, $capturedPayload['exp']);
    }

    #[Test]
    public function encodeWithExplicitIatPreservesIt(): void
    {
        $explicitIat = time() - 100;

        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $encoder->encode(['iat' => $explicitIat]);

        $this->assertSame($explicitIat, $capturedPayload['iat']);
    }

    #[Test]
    public function defaultClaimsAreMergedIntoPayload(): void
    {
        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(['default_claims' => ['iss' => 'test-issuer']]), $mock);
        $encoder->encode(['sub' => '42']);

        $this->assertSame('test-issuer', $capturedPayload['iss']);
        $this->assertSame('42', $capturedPayload['sub']);
    }

    #[Test]
    public function payloadClaimsOverrideDefaultClaims(): void
    {
        $mock = $this->makeMockAdapter();
        $capturedPayload = null;

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->callback(function (array $payload) use (&$capturedPayload): bool {
                    $capturedPayload = $payload;
                    return true;
                }),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(['default_claims' => ['iss' => 'default-issuer']]), $mock);
        $encoder->encode(['iss' => 'override-issuer']);

        $this->assertSame('override-issuer', $capturedPayload['iss']);
    }

    #[Test]
    public function keysetIsPassedToAdapter(): void
    {
        $mock = $this->makeMockAdapter();

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->anything(),
                'my-keyset',
                $this->anything(),
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $encoder->encode([], null, 'my-keyset');
    }

    #[Test]
    public function headersArePassedToAdapter(): void
    {
        $headers = ['kid' => 'my-key-id'];
        $mock = $this->makeMockAdapter();

        $mock->expects($this->once())
            ->method('encode')
            ->with(
                $this->anything(),
                $this->anything(),
                $headers,
            )
            ->willReturn('token');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $encoder->encode([], null, 'default', $headers);
    }

    #[Test]
    public function encodeReturnsAdaptersReturnValue(): void
    {
        $mock = $this->makeMockAdapter();
        $mock->method('encode')->willReturn('encoded-jwt-string');

        $encoder = new JWSEncoder($this->makeConfig(), $mock);
        $result = $encoder->encode([]);

        $this->assertSame('encoded-jwt-string', $result);
    }
}
