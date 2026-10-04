<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Services;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Services\ResendCooldown;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The cooldown window shared by the activation and 2FA resend buttons.
 */
#[CoversClass(ResendCooldown::class)]
class ResendCooldownTest extends TestCase
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

    private function seedIdentity(string $type, int $ageSeconds): void
    {
        $createdAt = (new \DateTimeImmutable())->modify("-{$ageSeconds} seconds")->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_identities (user_id, type, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$this->user->id, $type, 'x', $createdAt, $createdAt]);
    }

    #[Test]
    public function secondsFallsBackToTheDefault(): void
    {
        $this->assertSame(300, (new ResendCooldown([]))->seconds());
    }

    #[Test]
    public function secondsReadsTheConfig(): void
    {
        $this->assertSame(60, (new ResendCooldown(['resend_cooldown' => 60]))->seconds());
    }

    #[Test]
    public function remainingIsZeroWithoutAnIdentity(): void
    {
        $this->assertSame(0, (new ResendCooldown(['resend_cooldown' => 300]))->remaining($this->user, 'email_2fa'));
    }

    #[Test]
    public function remainingCountsDownFromTheCreationTime(): void
    {
        $this->seedIdentity('email_2fa', 100);

        $this->assertSame(200, (new ResendCooldown(['resend_cooldown' => 300]))->remaining($this->user, 'email_2fa'));
    }

    #[Test]
    public function remainingIsZeroOnceTheWindowHasElapsed(): void
    {
        $this->seedIdentity('email_2fa', 400);

        $this->assertSame(0, (new ResendCooldown(['resend_cooldown' => 300]))->remaining($this->user, 'email_2fa'));
    }

    #[Test]
    public function remainingIgnoresIdentitiesOfAnotherType(): void
    {
        $this->seedIdentity('email_activate', 10);

        $this->assertSame(0, (new ResendCooldown(['resend_cooldown' => 300]))->remaining($this->user, 'email_2fa'));
    }

    #[Test]
    public function formatPadsToMss(): void
    {
        $cooldown = new ResendCooldown([]);

        $this->assertSame('5:00', $cooldown->format(300));
        $this->assertSame('0:09', $cooldown->format(9));
        $this->assertSame('1:05', $cooldown->format(65));
    }
}
