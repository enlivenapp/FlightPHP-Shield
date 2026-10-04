<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Authorization\Groups;
use Enlivenapp\FlightShield\Authorization\Permissions;
use Enlivenapp\FlightShield\Services\UserManagement;
use Enlivenapp\FlightShield\Services\UserStats;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The Auth facade: the delegation methods it exposes and its management
 * service accessors.
 */
#[CoversClass(Auth::class)]
class AuthFacadeTest extends TestCase
{
    protected PDO $pdo;
    protected Auth $auth;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')");

        $this->config = TestHelper::getConfig();
        $this->auth = new Auth(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    #[Test]
    public function usersReturnsTheManagementService(): void
    {
        $this->assertInstanceOf(UserManagement::class, $this->auth->users());
    }

    #[Test]
    public function groupsReturnsTheGroupService(): void
    {
        $this->assertInstanceOf(Groups::class, $this->auth->groups());
    }

    #[Test]
    public function permissionsReturnsThePermissionService(): void
    {
        $this->assertInstanceOf(Permissions::class, $this->auth->permissions());
    }

    #[Test]
    public function statsReturnsTheStatsService(): void
    {
        $this->assertInstanceOf(UserStats::class, $this->auth->stats());
    }

    #[Test]
    public function idReturnsNullWhenNobodyIsLoggedIn(): void
    {
        $this->assertNull($this->auth->id());
    }

    #[Test]
    public function attemptAndLoginRoundTrip(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($user->id, $this->auth->id());
        $this->assertSame($user->id, $this->auth->user()->id);

        $this->auth->recordActiveDate();

        $this->auth->logout();

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function checkDelegatesToTheAuthenticator(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);

        $result = $this->auth->check(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function loginByIdDelegatesToTheAuthenticator(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);

        $this->auth->loginById($user->id);

        $this->assertSame($user->id, $this->auth->id());
    }

    #[Test]
    public function registerReportsSuccessForANewAccount(): void
    {
        $result = $this->auth->register([
            'email'            => 'new@example.com',
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ]);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function registerReturnsErrorsForInvalidInput(): void
    {
        $result = $this->auth->register([
            'email'            => 'nope',
            'password'         => 'short',
            'password_confirm' => 'short',
        ]);

        $this->assertFalse($result->isOK());
        $this->assertIsArray($result->extraInfo());
    }

    #[Test]
    public function registerIsSilentlySuccessfulForAnExistingAddress(): void
    {
        TestHelper::createUser($this->pdo, 'dup@example.com', 'Str0ng!Passw0rd', 'dup', true);

        $result = $this->auth->register([
            'email'            => 'dup@example.com',
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ]);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function registerRefusesASoftDeletedAddress(): void
    {
        $user = TestHelper::createUser($this->pdo, 'gone@example.com', 'Str0ng!Passw0rd', 'gone', true);
        $this->pdo->exec("UPDATE users SET deleted_at = '2026-01-01 00:00:00' WHERE id = {$user->id}");

        $result = $this->auth->register([
            'email'            => 'gone@example.com',
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ]);

        $this->assertFalse($result->isOK());
        $this->assertSame('That email address is no longer available.', $result->reason());
    }
}
