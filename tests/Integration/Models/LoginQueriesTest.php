<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Models;

use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Login::class)]
class LoginQueriesTest extends TestCase
{
    protected PDO $pdo;
    protected Login $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        $this->model = new Login($this->pdo);
    }

    protected function insertLogin(string $ip, bool $success, string $date): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_logins (ip_address, id_type, identifier, date, success)
             VALUES (?, ?, ?, ?, ?)'
        )->execute([$ip, 'email', 'user@test.com', $date, $success ? 1 : 0]);
    }

    // -----------------------------------------------------------------
    // countRecentFailuresByIp
    // -----------------------------------------------------------------

    #[Test]
    public function countRecentFailuresByIpCountsFailuresAfterSince(): void
    {
        $this->insertLogin('1.2.3.4', false, '2026-04-25 10:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-25 11:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-24 08:00:00');

        $this->assertSame(2, $this->model->countRecentFailuresByIp('1.2.3.4', '2026-04-25 00:00:00'));
    }

    #[Test]
    public function countRecentFailuresByIpExcludesSuccesses(): void
    {
        $this->insertLogin('1.2.3.4', false, '2026-04-25 10:00:00');
        $this->insertLogin('1.2.3.4', true,  '2026-04-25 11:00:00');

        $this->assertSame(1, $this->model->countRecentFailuresByIp('1.2.3.4', '2026-04-25 00:00:00'));
    }

    #[Test]
    public function countRecentFailuresByIpExcludesOtherIps(): void
    {
        $this->insertLogin('1.2.3.4', false, '2026-04-25 10:00:00');
        $this->insertLogin('5.6.7.8', false, '2026-04-25 10:00:00');

        $this->assertSame(1, $this->model->countRecentFailuresByIp('1.2.3.4', '2026-04-25 00:00:00'));
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
        $this->insertLogin('1.2.3.4', false, '2026-04-25 10:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-25 12:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-25 11:00:00');

        $this->assertSame('2026-04-25 12:00:00', $this->model->latestFailureDateByIp('1.2.3.4'));
    }

    #[Test]
    public function latestFailureDateByIpReturnsNullWhenNone(): void
    {
        $this->assertNull($this->model->latestFailureDateByIp('1.2.3.4'));
    }

    #[Test]
    public function latestFailureDateByIpIgnoresSuccesses(): void
    {
        $this->insertLogin('1.2.3.4', true,  '2026-04-25 12:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-25 10:00:00');

        $this->assertSame('2026-04-25 10:00:00', $this->model->latestFailureDateByIp('1.2.3.4'));
    }

    // -----------------------------------------------------------------
    // loginAttemptsSummary
    // -----------------------------------------------------------------

    #[Test]
    public function loginAttemptsSummaryReturnsTotals(): void
    {
        $recent = (new \DateTimeImmutable('-5 days'))->format('Y-m-d H:i:s');

        $this->insertLogin('1.2.3.4', true,  $recent);
        $this->insertLogin('1.2.3.4', true,  $recent);
        $this->insertLogin('1.2.3.4', false, $recent);

        $result = $this->model->loginAttemptsSummary(30);

        $this->assertSame(3, $result['total']);
        $this->assertSame(2, $result['success']);
        $this->assertSame(1, $result['failed']);
    }

    #[Test]
    public function loginAttemptsSummaryExcludesOldEntries(): void
    {
        $this->insertLogin('1.2.3.4', true, '2020-01-01 00:00:00');

        $recent = (new \DateTimeImmutable('-1 day'))->format('Y-m-d H:i:s');
        $this->insertLogin('1.2.3.4', true, $recent);

        $result = $this->model->loginAttemptsSummary(30);

        $this->assertSame(1, $result['total']);
    }

    #[Test]
    public function loginAttemptsSummaryReturnsZerosWhenEmpty(): void
    {
        $result = $this->model->loginAttemptsSummary(30);

        $this->assertSame(0, $result['total']);
        $this->assertSame(0, $result['success']);
        $this->assertSame(0, $result['failed']);
    }

    // -----------------------------------------------------------------
    // loginAttemptsByDay
    // -----------------------------------------------------------------

    #[Test]
    public function loginAttemptsByDayGroupsByDay(): void
    {
        $this->insertLogin('1.2.3.4', true,  '2026-04-24 10:00:00');
        $this->insertLogin('1.2.3.4', false, '2026-04-24 11:00:00');
        $this->insertLogin('1.2.3.4', true,  '2026-04-25 09:00:00');

        $result = $this->model->loginAttemptsByDay(365);

        $this->assertArrayHasKey('2026-04-24', $result);
        $this->assertArrayHasKey('2026-04-25', $result);

        $this->assertSame(1, $result['2026-04-24']['success']);
        $this->assertSame(1, $result['2026-04-24']['failed']);
        $this->assertSame(1, $result['2026-04-25']['success']);
        $this->assertSame(0, $result['2026-04-25']['failed']);
    }

    #[Test]
    public function loginAttemptsByDayReturnsEmptyWhenNoData(): void
    {
        $this->assertSame([], $this->model->loginAttemptsByDay(30));
    }
}
