<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A correct password on an unactivated account is not a login. attempt()
 * reports it with its own code so the login controller forwards to the
 * activation page instead of showing a generic failure.
 */
#[CoversClass(Session::class)]
class SessionAttemptActivationTest extends TestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    #[Test]
    public function inactiveAccountIsReportedWithTheActivationCode(): void
    {
        TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);

        $auth = new Session(\Flight::app(), TestHelper::getConfig());

        $result = $auth->attempt(['email' => 'pending@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());
        $this->assertSame(Session::ACCOUNT_NOT_ACTIVATED, $result->extraInfo());
        $this->assertFalse($auth->loggedIn());
        $this->assertArrayNotHasKey('user', $_SESSION);
    }

    #[Test]
    public function wrongPasswordOnAnInactiveAccountStaysGeneric(): void
    {
        TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);

        $auth = new Session(\Flight::app(), TestHelper::getConfig());

        $result = $auth->attempt(['email' => 'pending@example.com', 'password' => 'wrong']);

        $this->assertFalse($result->isOK());
        $this->assertNull($result->extraInfo());
        $this->assertSame('Invalid credentials.', $result->reason());
    }
}
