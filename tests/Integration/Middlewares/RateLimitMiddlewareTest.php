<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Middlewares\RateLimitMiddleware;
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\Engine;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Spy subclass — defines halt() as a real method so it can be inspected
 * without actually sending output or exiting.
 */
class SpyEngine extends Engine
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

#[CoversClass(RateLimitMiddleware::class)]
class RateLimitMiddlewareTest extends TestCase
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

    protected function insertFailure(string $table, string $ip, string $date): void
    {
        $this->pdo->prepare(
            "INSERT INTO {$table} (ip_address, id_type, identifier, date, success)
             VALUES (?, ?, ?, ?, 0)"
        )->execute([$ip, 'email', 'user@test.com', $date]);
    }

    protected function makeEngine(array $rateLimitOverrides = []): SpyEngine
    {
        $defaults = [
            'enabled'         => true,
            'max_attempts'    => 5,
            'decay_minutes'   => 30,
            'lockout_minutes' => 30,
        ];

        $app = new SpyEngine();
        $app->set('enlivenapp.flight-shield', [
            'rate_limiting' => array_merge($defaults, $rateLimitOverrides),
        ]);

        return $app;
    }

    // -----------------------------------------------------------------
    // Allowed through
    // -----------------------------------------------------------------

    #[Test]
    public function beforeAllowsWhenBelowThreshold(): void
    {
        $recent = (new \DateTimeImmutable('-5 minutes'))->format('Y-m-d H:i:s');
        for ($i = 0; $i < 3; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $recent);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function beforeAllowsWhenDisabled(): void
    {
        $recent = (new \DateTimeImmutable('-1 minute'))->format('Y-m-d H:i:s');
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $recent);
        }

        $app = $this->makeEngine(['enabled' => false]);
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function beforeAllowsWhenNoFailures(): void
    {
        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    #[Test]
    public function beforeDoesNotBlockOtherIps(): void
    {
        $recent = (new \DateTimeImmutable('-5 minutes'))->format('Y-m-d H:i:s');
        for ($i = 0; $i < 10; $i++) {
            $this->insertFailure('auth_logins', '99.99.99.99', $recent);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertFalse($app->haltCalled);
    }

    // -----------------------------------------------------------------
    // Blocked (429)
    // -----------------------------------------------------------------

    #[Test]
    public function beforeBlocksWhenThresholdReachedWithinLockout(): void
    {
        $recent = (new \DateTimeImmutable('-5 minutes'))->format('Y-m-d H:i:s');
        for ($i = 0; $i < 5; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $recent);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
        $this->assertSame(429, $app->haltCode);
    }

    #[Test]
    public function beforeCombinesSessionAndTokenLoginFailures(): void
    {
        $recent = (new \DateTimeImmutable('-5 minutes'))->format('Y-m-d H:i:s');

        for ($i = 0; $i < 3; $i++) {
            $this->insertFailure('auth_logins', '10.0.0.1', $recent);
        }
        for ($i = 0; $i < 2; $i++) {
            $this->insertFailure('auth_token_logins', '10.0.0.1', $recent);
        }

        $app = $this->makeEngine();
        (new RateLimitMiddleware($app))->before();

        $this->assertTrue($app->haltCalled);
        $this->assertSame(429, $app->haltCode);
    }
}
