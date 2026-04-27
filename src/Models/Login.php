<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class Login extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_logins', $config);
    }

    public int $id;
    public string $ip_address;
    public ?string $user_agent = null;
    public string $id_type;
    public string $identifier;
    public ?int $user_id = null;
    public string $date;
    public bool $success;

    /**
     * Count recent failed login attempts for an IP.
     */
    public function countRecentFailuresByIp(string $ip, string $since): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->eq('ip_address', $ip)
            ->eq('success', 0)
            ->gte('date', $since)
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Most recent failure date for an IP, or null if none.
     */
    public function latestFailureDateByIp(string $ip): ?string
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('MAX(date) as latest_date')
            ->eq('ip_address', $ip)
            ->eq('success', 0)
            ->find();

        return $result->latest_date ?? null;
    }

    /**
     * Login attempts summary over the last N days.
     *
     * @return array{total: int, success: int, failed: int}
     */
    public function loginAttemptsSummary(int $days = 30): array
    {
        $since = (new \DateTimeImmutable())->modify("-{$days} days")->format('Y-m-d H:i:s');

        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) AS total', 'SUM(success = 1) AS success_count', 'SUM(success = 0) AS failed_count')
            ->gte('date', $since)
            ->find();

        return [
            'total'   => (int) ($result->total ?? 0),
            'success' => (int) ($result->success_count ?? 0),
            'failed'  => (int) ($result->failed_count ?? 0),
        ];
    }

    /**
     * Login attempts by day for charting.
     *
     * @return array<string, array{success: int, failed: int}>
     */
    public function loginAttemptsByDay(int $days = 30): array
    {
        $since = (new \DateTimeImmutable())->modify("-{$days} days")->format('Y-m-d H:i:s');

        $results = (new self($this->getDatabaseConnection()))
            ->select('DATE(date) AS day', 'SUM(success = 1) AS success_count', 'SUM(success = 0) AS failed_count')
            ->gte('date', $since)
            ->group('DATE(date)')
            ->order('day ASC')
            ->findAll();

        $data = [];
        foreach ($results as $row) {
            $data[$row->day] = [
                'success' => (int) $row->success_count,
                'failed'  => (int) $row->failed_count,
            ];
        }
        return $data;
    }
}
