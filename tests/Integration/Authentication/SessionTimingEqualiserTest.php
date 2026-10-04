<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Services\CredentialVerifier;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * An unknown email must still run a password check, so a miss cannot be
 * told apart from a wrong password by how long the answer took.
 */
#[CoversClass(Session::class)]
#[CoversClass(CredentialVerifier::class)]
class SessionTimingEqualiserTest extends TestCase
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

    /**
     * A CredentialVerifier that records burnTiming() calls instead of hashing.
     */
    private function spyVerifier(): CredentialVerifier
    {
        return new class (\Flight::app(), TestHelper::getConfig()) extends CredentialVerifier {
            /** @var string[] */
            public array $burned = [];

            public function burnTiming(string $password): void
            {
                $this->burned[] = $password;
            }
        };
    }

    #[Test]
    public function unknownEmailStillBurnsAPasswordCheck(): void
    {
        $spy = $this->spyVerifier();
        $auth = new Session(\Flight::app(), TestHelper::getConfig(), $spy);

        $result = $auth->check(['email' => 'ghost@example.com', 'password' => 'secret']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid credentials.', $result->reason());
        $this->assertSame(['secret'], $spy->burned);
    }

    #[Test]
    public function knownEmailWithWrongPasswordDoesNotBurnTheEqualiser(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $spy = $this->spyVerifier();
        $auth = new Session(\Flight::app(), TestHelper::getConfig(), $spy);

        $result = $auth->check(['email' => 'user@example.com', 'password' => 'wrong']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid credentials.', $result->reason());
        $this->assertSame([], $spy->burned);
    }

    #[Test]
    public function theEqualiserHashIsARealBcryptHashThatRejectsAnyPassword(): void
    {
        $info = password_get_info(CredentialVerifier::TIMING_EQUALISER_HASH);

        $this->assertSame(PASSWORD_BCRYPT, $info['algo']);
        $this->assertSame(12, $info['options']['cost']);
        $this->assertFalse(password_verify('secret', CredentialVerifier::TIMING_EQUALISER_HASH));
    }
}
