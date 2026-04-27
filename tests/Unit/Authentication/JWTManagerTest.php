<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication;

use Enlivenapp\FlightShield\Authentication\JWTManager;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(JWTManager::class)]
class JWTManagerTest extends TestCase
{
    private array $config = [
        'default_claims' => ['iss' => 'test'],
        'time_to_live'   => 3600,
        'keys' => [
            'default' => [
                ['kid' => '', 'alg' => 'HS256', 'secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
            ],
        ],
    ];

    private function skipIfNoFirebase(): void
    {
        if (! class_exists(\Firebase\JWT\JWT::class)) {
            $this->markTestSkipped('firebase/php-jwt not installed');
        }
    }

    private function makeUserMock(int|string $id = 42): User
    {
        $user = $this->createMock(User::class);
        $user->id = $id;
        return $user;
    }

    // -----------------------------------------------------------------
    // Tests that run regardless of firebase/php-jwt availability
    // -----------------------------------------------------------------

    #[Test]
    public function constructorDoesNotThrow(): void
    {
        $manager = new JWTManager($this->config);

        $this->assertInstanceOf(JWTManager::class, $manager);
    }

    #[Test]
    public function generateTokenThrowsRuntimeExceptionWhenFirebaseNotAvailable(): void
    {
        if (class_exists(\Firebase\JWT\JWT::class)) {
            $this->markTestSkipped('firebase/php-jwt is installed — skipping unavailability test');
        }

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(42);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/firebase\/php-jwt/i');

        $manager->generateToken($user);
    }

    // -----------------------------------------------------------------
    // Tests that require firebase/php-jwt
    // -----------------------------------------------------------------

    #[Test]
    public function generateTokenIncludesSubClaimFromUserId(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(42);

        $token = $manager->generateToken($user);
        $payload = $manager->parse($token);

        $this->assertSame('42', $payload->sub);
    }

    #[Test]
    public function generateTokenMergesAdditionalClaims(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(7);

        $token = $manager->generateToken($user, ['role' => 'admin', 'tenant' => 'acme']);
        $payload = $manager->parse($token);

        $this->assertSame('admin', $payload->role);
        $this->assertSame('acme', $payload->tenant);
    }

    #[Test]
    public function parseReturnsPayloadWithCorrectSub(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(99);

        $token = $manager->generateToken($user);
        $payload = $manager->parse($token);

        $this->assertSame('99', $payload->sub);
    }

    #[Test]
    public function parseWithExpiredTokenThrows(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(1);

        // Generate a token that is already expired (exp in the past)
        $token = $manager->generateToken($user, ['exp' => time() - 10]);

        $this->expectException(AuthenticationException::class);

        $manager->parse($token);
    }

    #[Test]
    public function issueCreatesTokenWithoutRequiringUser(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);

        $token = $manager->issue(['sub' => 'service-account', 'scope' => 'read']);
        $payload = $manager->parse($token);

        $this->assertSame('service-account', $payload->sub);
        $this->assertSame('read', $payload->scope);
    }

    #[Test]
    public function generateTokenAndParseRoundtrip(): void
    {
        $this->skipIfNoFirebase();

        $manager = new JWTManager($this->config);
        $user = $this->makeUserMock(123);

        $claims = ['custom' => 'value', 'num' => 5];
        $token = $manager->generateToken($user, $claims);
        $payload = $manager->parse($token);

        $this->assertSame('123', $payload->sub);
        $this->assertSame('value', $payload->custom);
        $this->assertSame(5, $payload->num);
        // Default claim from config
        $this->assertSame('test', $payload->iss);
    }
}
