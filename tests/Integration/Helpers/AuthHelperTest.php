<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Helpers;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The auth() and user_id() helper functions.
 */
#[CoversNothing]
class AuthHelperTest extends TestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $config = TestHelper::getConfig();
        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->register('auth', Auth::class, [$app, $config]);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    #[Test]
    public function authReturnsTheFacade(): void
    {
        $this->assertInstanceOf(Auth::class, auth());
    }

    #[Test]
    public function authWithAnAliasSwitchesTheAuthenticator(): void
    {
        $this->assertInstanceOf(Auth::class, auth('tokens'));
    }

    #[Test]
    public function userIdIsNullForAnonymousVisitors(): void
    {
        $this->assertNull(user_id());
    }

    #[Test]
    public function userIdReturnsTheLoggedInUsersId(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        auth('session')->login($user);

        $this->assertSame($user->id, user_id());
    }
}
