<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Traits;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The Resettable trait reads the force_reset flag off the email identity.
 */
class ResettableTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    #[Test]
    public function userWithoutTheFlagDoesNotRequireAReset(): void
    {
        $this->assertFalse($this->user->requiresPasswordReset());
    }

    #[Test]
    public function userWithTheFlagRequiresAReset(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET force_reset = 1 WHERE user_id = {$this->user->id}");

        $this->assertTrue($this->user->requiresPasswordReset());
    }

    #[Test]
    public function userWithoutAnEmailIdentityDoesNotRequireAReset(): void
    {
        $this->pdo->exec("DELETE FROM auth_identities WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->user->requiresPasswordReset());
    }
}
