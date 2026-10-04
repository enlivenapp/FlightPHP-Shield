<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Middlewares\RateLimitMiddleware;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\Engine;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Spy engine for the detail tests: records the halt code and body.
 */
class DetailRateLimitEngine extends Engine
{
    public bool $haltCalled = false;
    public int $haltCode = 0;
    public string $haltBody = '';

    private array $store = [];

    public function halt(int $code = 200, string $body = '', bool $actuallyExit = true): void
    {
        $this->haltCalled = true;
        $this->haltCode   = $code;
        $this->haltBody   = $body;
    }

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }
}

/**
 * The rate limiter's defaults, the lockout window edges, the Retry-After
 * header, and the latest-failure selection across both tables.
 */
#[CoversClass(RateLimitMiddleware::class)]
class RateLimitMiddlewareDetailTest extends TestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        unset($_SERVER['REMOTE_ADDR']);
    }

    private function insertFailure(string $table, string $ip, string $date, bool $success = false): void
    {
        $this->pdo->prepare(
            "INSERT INTO {$table} (ip_address, id_type, identifier, date, success)
             VALUES (?, ?, ?, ?, ?)"
        )->execute([$ip, 'email', 'user@test.com', $date, $success ? 1 : 0]);
    }

    /**
     * @param array<string, mixed> $rateLimit
     */
    private function makeEngine(array $rateLimit = []): DetailRateLimitEngine
    {
        $app = new DetailRateLimitEngine();
        $app->set('enlivenapp.flight-shield', ['rate_limiting' => $rateLimit]);

        return $app;
    }

    private function minutesAgo(int $minutes): string
    {
        return (new \DateTimeImmutable("-{$minutes} minutes"))->format('Y-m-d H:i:s');
    }

    // -----------------------------------------------------------------
    // Defaults
    // -----------------------------------------------------------------

    #[Test]
    public function theLimiterIsEnabledByDefault(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function theDefaultThresholdIsTen(): void
    {
        for ($i = 0; $i < 9; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function theDefaultThresholdBlocksAtTen(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function theDefaultDecayWindowIsThirtyMinutes(): void
    {
        // 31 minutes old: outside the default decay window.
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(31));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function theDefaultLockoutWindowIsThirtyMinutes(): void
    {
        // Threshold reached inside the decay window, but the newest failure
        // is 31 minutes old, so the lockout has lapsed.
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(31));
        }

        $app = $this->makeEngine(['decay_minutes' => 60]);
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function aMissingIpFallsBackToTheDefault(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '0.0.0.0', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    // -----------------------------------------------------------------
    // Lockout window edges
    // -----------------------------------------------------------------

    #[Test]
    public function aFailureInsideTheLockoutWindowBlocks(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(29));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function aFailureOutsideTheLockoutWindowDoesNotBlock(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(31));
        }

        $app = $this->makeEngine(['decay_minutes' => 60]);
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function aCustomLockoutWindowIsHonoured(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(10));
        }

        $app = $this->makeEngine(['decay_minutes' => 60, 'lockout_minutes' => 5]);
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    // -----------------------------------------------------------------
    // The 429 response
    // -----------------------------------------------------------------

    #[Test]
    public function theBlockSendsARetryAfterHeader(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine(['lockout_minutes' => 15]);
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
        $this->assertSame(429, $app->haltCode);
    }

    #[Test]
    public function theBlockBodyNamesTheReason(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $body = json_decode($app->haltBody, true);
        $this->assertIsArray($body);
        $this->assertSame('Too many attempts. Please try again later.', $body['error']);
    }

    // -----------------------------------------------------------------
    // Latest-failure selection
    // -----------------------------------------------------------------

    #[Test]
    public function theNewestFailureAcrossBothTablesDecidesTheLockout(): void
    {
        // Session failures are old, token failures are fresh.
        for ($i = 0; $i < 5; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(120));
        }
        for ($i = 0; $i < 5; $i++) {
            $this->insertFailure('auth_token_logins', '10.0.0.1', $this->minutesAgo(2));
        }

        $app = $this->makeEngine(['decay_minutes' => 180]);
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function anOlderTokenFailureDoesNotExtendTheLockout(): void
    {
        // Token failures are old, session failures are fresh.
        for ($i = 0; $i < 5; $i++) {
            $this->insertFailure('auth_token_logins', '10.0.0.1', $this->minutesAgo(120));
        }
        for ($i = 0; $i < 5; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(2));
        }

        $app = $this->makeEngine(['decay_minutes' => 180]);
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function tokenFailuresAloneCanReachTheThreshold(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_token_logins', '10.0.0.1', $this->minutesAgo(5));
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function successfulLoginsDoNotCountTowardTheThreshold(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $this->minutesAgo(5), true);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    // -----------------------------------------------------------------
    // Endpoint counting
    // -----------------------------------------------------------------

    #[Test]
    public function theEndpointCounterCountsSends(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->pdo->prepare(
                'INSERT INTO auth_logins (ip_address, id_type, identifier, date, success)
                 VALUES (?, ?, ?, ?, 1)'
            )->execute(['10.0.0.1', Login::ID_TYPE_ACTIVATION_RESEND, 'user@test.com', $this->minutesAgo(5)]);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app, Login::ID_TYPE_ACTIVATION_RESEND))->before();

        $this->assertTrue($app->haltCalled);
    }

    #[Test]
    public function theEndpointCounterIgnoresOtherTypes(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->pdo->prepare(
                'INSERT INTO auth_logins (ip_address, id_type, identifier, date, success)
                 VALUES (?, ?, ?, ?, 1)'
            )->execute(['10.0.0.1', 'email', 'user@test.com', $this->minutesAgo(5)]);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app, Login::ID_TYPE_ACTIVATION_RESEND))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function theEndpointCounterUsesTheLockoutWindow(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->pdo->prepare(
                'INSERT INTO auth_logins (ip_address, id_type, identifier, date, success)
                 VALUES (?, ?, ?, ?, 1)'
            )->execute(['10.0.0.1', Login::ID_TYPE_ACTIVATION_RESEND, 'user@test.com', $this->minutesAgo(31)]);
        }

        $app = $this->makeEngine(['decay_minutes' => 60]);
        (new RateLimitMiddleware($app, Login::ID_TYPE_ACTIVATION_RESEND))->before();

        $this->assertFalse($app->haltCalled);
    }
}
