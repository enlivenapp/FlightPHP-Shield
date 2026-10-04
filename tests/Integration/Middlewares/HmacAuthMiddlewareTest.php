<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\HmacAuthMiddleware;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The HMAC guard: unsigned or mis-signed requests get JSON errors, an
 * active user is recorded, an inactive one is turned away.
 */
#[CoversClass(HmacAuthMiddleware::class)]
class HmacAuthMiddlewareTest extends TestCase
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
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/api';

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
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['HTTP_X_REQUEST_TIMESTAMP'],
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['REQUEST_URI']
        );
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function mintKey(?User $for = null): array
    {
        $user = $for ?? $this->user;
        $token = (new UserIdentity($this->pdo))->generateHmacToken($user, 'test', [], null, null);
        $key = $token->rawToken;

        $stmt = $this->pdo->prepare("SELECT secret2 FROM auth_identities WHERE type = 'hmac_sha256' AND secret = ?");
        $stmt->execute([$key]);

        return [$key, (string) $stmt->fetchColumn()];
    }

    private function sign(string $key, string $secret, int $ts): string
    {
        $sig = hash_hmac('sha256', 'GET' . "\n" . '/api' . "\n" . $ts . "\n" . '', $secret);

        return 'HMAC-SHA256 ' . $key . ':' . $sig;
    }

    #[Test]
    public function unsignedRequestGetsA401JsonResponse(): void
    {
        (new HmacAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(401, $this->app->jsonCalls[0]['code']);
    }

    #[Test]
    public function validSignaturePassesAndRecordsTheActiveDate(): void
    {
        [$key, $secret] = $this->mintKey();
        $ts = time();

        $_SERVER['HTTP_AUTHORIZATION'] = $this->sign($key, $secret, $ts);
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;

        (new HmacAuthMiddleware($this->app))->before();

        $this->assertSame([], $this->app->jsonCalls);
        $lastActive = $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
        $this->assertNotNull($lastActive);
    }

    #[Test]
    public function inactiveAccountGetsA403(): void
    {
        $inactive = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        [$key, $secret] = $this->mintKey($inactive);
        $ts = time();

        $_SERVER['HTTP_AUTHORIZATION'] = $this->sign($key, $secret, $ts);
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;

        (new HmacAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(403, $this->app->jsonCalls[0]['code']);
    }
}
