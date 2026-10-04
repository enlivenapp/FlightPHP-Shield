<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\Adapters\FirebaseAdapter;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Firebase\JWT\JWT as FirebaseJWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The firebase/php-jwt adapter: single-key and keyed (kid) keysets, the
 * exception mapping, and encode/decode round trips.
 */
#[CoversClass(FirebaseAdapter::class)]
class FirebaseAdapterTest extends TestCase
{
    private const SECRET = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private function singleKeyAdapter(): FirebaseAdapter
    {
        return new FirebaseAdapter([
            'default' => [
                ['kid' => '', 'alg' => 'HS256', 'secret' => self::SECRET],
            ],
        ]);
    }

    #[Test]
    public function encodeAndDecodeRoundTripWithASingleKey(): void
    {
        $adapter = $this->singleKeyAdapter();

        $token = $adapter->encode(['sub' => '42'], 'default');
        $payload = $adapter->decode($token, 'default');

        $this->assertInstanceOf(stdClass::class, $payload);
        $this->assertSame('42', $payload->sub);
    }

    #[Test]
    public function encodeAndDecodeRoundTripWithAKeyedKeySet(): void
    {
        $adapter = new FirebaseAdapter([
            'default' => [
                ['kid' => 'k1', 'alg' => 'HS256', 'secret' => self::SECRET],
                ['kid' => 'k2', 'alg' => 'HS256', 'secret' => self::SECRET],
            ],
        ]);

        $token = $adapter->encode(['sub' => '7'], 'default');
        $payload = $adapter->decode($token, 'default');

        $this->assertSame('7', $payload->sub);
    }

    #[Test]
    public function encodeAttachesTheKeyIdHeader(): void
    {
        $adapter = new FirebaseAdapter([
            'default' => [
                ['kid' => 'k1', 'alg' => 'HS256', 'secret' => self::SECRET],
            ],
        ]);

        $token = $adapter->encode(['sub' => '7'], 'default');

        $parts = explode('.', $token);
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);

        $this->assertSame('k1', $header['kid']);
    }

    #[Test]
    public function decodeRejectsAnUnknownKeyset(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown JWT keyset');

        $this->singleKeyAdapter()->decode('whatever', 'missing');
    }

    #[Test]
    public function encodeRejectsAnUnknownKeyset(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->singleKeyAdapter()->encode(['sub' => '1'], 'missing');
    }

    #[Test]
    public function decodeRejectsATokenSignedWithAnotherKey(): void
    {
        $other = new FirebaseAdapter([
            'default' => [
                ['kid' => '', 'alg' => 'HS256', 'secret' => str_repeat('b', 40)],
            ],
        ]);
        $token = $other->encode(['sub' => '1'], 'default');

        $this->expectException(AuthenticationException::class);

        $this->singleKeyAdapter()->decode($token, 'default');
    }

    #[Test]
    public function decodeRejectsGarbage(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->singleKeyAdapter()->decode('not.a.token', 'default');
    }

    #[Test]
    public function decodeRejectsAnExpiredToken(): void
    {
        $token = FirebaseJWT::encode(['sub' => '1', 'exp' => time() - 60], self::SECRET, 'HS256');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid or expired token.');

        $this->singleKeyAdapter()->decode($token, 'default');
    }

    #[Test]
    public function decodeRejectsATokenThatIsNotValidYet(): void
    {
        $token = FirebaseJWT::encode(['sub' => '1', 'nbf' => time() + 3600], self::SECRET, 'HS256');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid or expired token.');

        $this->singleKeyAdapter()->decode($token, 'default');
    }
}
