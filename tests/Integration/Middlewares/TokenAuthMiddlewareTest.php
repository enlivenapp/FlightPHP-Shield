<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\TokenAuthMiddleware;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The bearer-token guard: missing/!valid tokens get JSON errors, an active
 * user is recorded, an inactive one is turned away.
 */
#[CoversClass(TokenAuthMiddleware::class)]
class TokenAuthMiddlewareTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected AuthSpyEngine $app;
    protected Auth $auth;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $config = TestHelper::getConfig();
        $this->app = new AuthSpyEngine();
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_AUTHORIZATION']);
    }

    private function mintToken(?User $for = null): string
    {
        $user = $for ?? $this->user;
        $token = (new UserIdentity($this->pdo))->generateAccessToken($user, 'test', [], null);

        return $token->rawToken;
    }

    #[Test]
    public function missingTokenGetsA401JsonResponse(): void
    {
        (new TokenAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(401, $this->app->jsonCalls[0]['code']);
    }

    #[Test]
    public function validTokenPassesAndRecordsTheActiveDate(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->mintToken();

        (new TokenAuthMiddleware($this->app))->before();

        $this->assertSame([], $this->app->jsonCalls);
        $lastActive = $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
        $this->assertNotNull($lastActive);
    }

    #[Test]
    public function inactiveAccountGetsA403(): void
    {
        $inactive = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->mintToken($inactive);

        (new TokenAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(403, $this->app->jsonCalls[0]['code']);
    }
}
