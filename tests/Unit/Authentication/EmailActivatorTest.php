<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Token-only activation resolution. The whole point is that an email click
 * needs no session, so these tests never put anything in $_SESSION.
 */
#[CoversClass(EmailActivator::class)]
class EmailActivatorTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'activate@example.com', 'password123', 'activateuser', false);

        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function mintToken(string $token, ?string $expires = null): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_identities (user_id, type, name, secret, expires, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $this->user->id,
            UserIdentity::TYPE_EMAIL_ACTIVATE,
            'register',
            hash('sha256', $token),
            $expires,
            $now,
            $now,
        ]);
    }

    #[Test]
    public function validTokenResolvesUserAndBurnsToken(): void
    {
        $this->mintToken('good-token');

        $result = (new EmailActivator())->consume('good-token');

        $this->assertTrue($result->isOK());
        $this->assertSame($this->user->id, $result->extraInfo()->id);
        $this->assertSame(0, $this->countActivations());
    }

    #[Test]
    public function tokenCannotBeUsedTwice(): void
    {
        $this->mintToken('one-shot');
        $activator = new EmailActivator();

        $this->assertTrue($activator->consume('one-shot')->isOK());
        $this->assertFalse($activator->consume('one-shot')->isOK());
    }

    #[Test]
    public function expiredTokenIsRejectedAndBurned(): void
    {
        $this->mintToken('stale', '2020-01-01 00:00:00');

        $result = (new EmailActivator())->consume('stale');

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('expired', (string) $result->reason());
        $this->assertSame(0, $this->countActivations());
    }

    #[Test]
    public function unknownTokenIsRejected(): void
    {
        $result = (new EmailActivator())->consume('nope');

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function consumeNeverTouchesTheSession(): void
    {
        $this->mintToken('session-free');

        (new EmailActivator())->consume('session-free');

        $this->assertSame([], $_SESSION);
    }

    private function countActivations(): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_identities WHERE type = 'email_activate'")
            ->fetchColumn();
    }
}
