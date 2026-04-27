<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Models;

use Enlivenapp\FlightShield\Models\TokenLogin;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(TokenLogin::class)]
class TokenLoginQueriesTest extends TestCase
{
    protected PDO $pdo;
    protected TokenLogin $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        $this->model = new TokenLogin($this->pdo);
    }

    protected function insertTokenLogin(string $ip, bool $success, string $date): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_token_logins (ip_address, id_type, identifier, date, success)
             VALUES (?, ?, ?, ?, ?)'
        )->execute([$ip, 'token', 'tok_abc', $date, $success ? 1 : 0]);
    }

    // -----------------------------------------------------------------
    // countRecentFailuresByIp
    // -----------------------------------------------------------------

    #[Test]
    public function countRecentFailuresByIpCountsCorrectly(): void
    {
        $this->insertTokenLogin('1.2.3.4', false, '2026-04-25 10:00:00');
        $this->insertTokenLogin('1.2.3.4', false, '2026-04-25 11:00:00');
        $this->insertTokenLogin('1.2.3.4', true,  '2026-04-25 12:00:00');
        $this->insertTokenLogin('5.6.7.8', false, '2026-04-25 10:00:00');

        $this->assertSame(2, $this->model->countRecentFailuresByIp('1.2.3.4', '2026-04-25 00:00:00'));
    }

    #[Test]
    public function countRecentFailuresByIpReturnsZeroWhenNone(): void
    {
        $this->assertSame(0, $this->model->countRecentFailuresByIp('1.2.3.4', '2026-04-25 00:00:00'));
    }

    // -----------------------------------------------------------------
    // latestFailureDateByIp
    // -----------------------------------------------------------------

    #[Test]
    public function latestFailureDateByIpReturnsLatestDate(): void
    {
        $this->insertTokenLogin('1.2.3.4', false, '2026-04-25 08:00:00');
        $this->insertTokenLogin('1.2.3.4', false, '2026-04-25 14:00:00');

        $this->assertSame('2026-04-25 14:00:00', $this->model->latestFailureDateByIp('1.2.3.4'));
    }

    #[Test]
    public function latestFailureDateByIpReturnsNullWhenNone(): void
    {
        $this->assertNull($this->model->latestFailureDateByIp('1.2.3.4'));
    }
}
