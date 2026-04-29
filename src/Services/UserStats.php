<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Services;

use Enlivenapp\FlightShield\Models\GroupUser;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\User;

class UserStats
{
    protected User $userModel;
    protected GroupUser $groupUserModel;
    protected Login $loginModel;

    public function __construct(\PDO $pdo)
    {
        $this->userModel      = new User($pdo);
        $this->groupUserModel = new GroupUser($pdo);
        $this->loginModel     = new Login($pdo);
    }

    /**
     * Total non-deleted users.
     */
    public function totalUsers(): int
    {
        return $this->userModel->countAll(true);
    }

    /**
     * Active users (active = 1, not deleted).
     */
    public function activeUsers(): int
    {
        return $this->userModel->countActive();
    }

    /**
     * Inactive users (active = 0, not deleted, not banned).
     */
    public function inactiveUsers(): int
    {
        return $this->userModel->countInactive();
    }

    /**
     * Banned users.
     */
    public function bannedUsers(): int
    {
        return $this->userModel->countBanned();
    }

    /**
     * User count per group.
     *
     * @return array<string, int> group_alias => count
     */
    public function usersByGroup(): array
    {
        return $this->groupUserModel->countByGroup();
    }

    /**
     * New user registrations by month.
     *
     * @param int $months Number of months to look back
     * @return array<string, int> 'YYYY-MM' => count
     */
    public function newUsersByMonth(int $months = 12): array
    {
        return $this->userModel->countNewByMonth($months);
    }

    /**
     * New users registered this month.
     */
    public function newUsersThisMonth(): int
    {
        return $this->userModel->countNewSince(date('Y-m-01'));
    }

    /**
     * New users registered last month.
     */
    public function newUsersLastMonth(): int
    {
        $firstOfLastMonth = (new \DateTimeImmutable('first day of last month'))->format('Y-m-d');
        $firstOfThisMonth = date('Y-m-01');

        return $this->userModel->countNewBetween($firstOfLastMonth, $firstOfThisMonth);
    }

    /**
     * Percentage change in new users this month vs last month.
     *
     * @return float Percentage change (positive = growth, negative = decline)
     */
    public function newUsersPercentChange(): float
    {
        $thisMonth = $this->newUsersThisMonth();
        $lastMonth = $this->newUsersLastMonth();

        if ($lastMonth === 0) {
            return $thisMonth > 0 ? 100.0 : 0.0;
        }

        return round((($thisMonth - $lastMonth) / $lastMonth) * 100, 1);
    }

    /**
     * Login attempts summary.
     *
     * @param int $days Number of days to look back
     * @return array{total: int, success: int, failed: int}
     */
    public function loginAttempts(int $days = 30): array
    {
        return $this->loginModel->loginAttemptsSummary($days);
    }

    /**
     * Login attempts by day for charting.
     *
     * @param int $days Number of days to look back
     * @return array<string, array{success: int, failed: int}> 'YYYY-MM-DD' => counts
     */
    public function loginAttemptsByDay(int $days = 30): array
    {
        return $this->loginModel->loginAttemptsByDay($days);
    }
}
