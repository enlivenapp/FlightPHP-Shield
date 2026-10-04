<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Authentication\Authenticators\JWT;
use Enlivenapp\FlightShield\Authentication\JWTManager;
use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\JWTAuthMiddleware;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The JWT guard: missing/!invalid tokens get JSON errors, an active user is
 * recorded, an inactive one is turned away.
 */
#[CoversClass(JWTAuthMiddleware::class)]
class JWTAuthMiddlewareTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected AuthSpyEngine $app;
    protected Auth $auth;
    protected User $user;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->config = TestHelper::getConfig();
        $this->config['authenticators']['jwt'] = JWT::class;
        $this->config['jwt'] = $this->jwtConfig();

        $this->app = new AuthSpyEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->auth = new Auth($this->app, $this->config);
        $this->app->authStub = $this->auth;

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_AUTHORIZATION']);
    }

    /**
     * @return array<string, mixed>
     */
    private function jwtConfig(): array
    {
        return [
            'header'         => 'Authorization',
            'time_to_live'   => 3600,
            'default_claims' => ['iss' => 'test'],
            'keys'           => [
                'default' => [
                    ['kid' => '', 'alg' => 'HS256', 'secret' => str_repeat('s', 40)],
                ],
            ],
        ];
    }

    private function tokenFor(User $user): string
    {
        return (new JWTManager($this->jwtConfig()))->generateToken($user, [], null);
    }

    #[Test]
    public function missingTokenGetsA401JsonResponse(): void
    {
        (new JWTAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(401, $this->app->jsonCalls[0]['code']);
        $this->assertArrayHasKey('error', $this->app->jsonCalls[0]['data']);
    }

    #[Test]
    public function validBearerTokenPassesAndRecordsTheActiveDate(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        (new JWTAuthMiddleware($this->app))->before();

        $this->assertSame([], $this->app->jsonCalls);
        $lastActive = $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
        $this->assertNotNull($lastActive);
    }

    #[Test]
    public function inactiveAccountGetsA403(): void
    {
        $inactive = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $_SERVER['HTTP_AUTHORIZATION'] = $this->tokenFor($inactive);

        (new JWTAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(403, $this->app->jsonCalls[0]['code']);
    }
}
