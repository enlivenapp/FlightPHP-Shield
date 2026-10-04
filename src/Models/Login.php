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
    /**
     * id_type for an activation resend submit. The row is a rate-limit
     * counter, not a login, and is excluded from the login statistics.
     */
    public const ID_TYPE_ACTIVATION_RESEND = 'activation_resend';

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(mixed $pdo = null, array $config = [])
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
     * Count every row of one id_type for an IP within the window.
     *
     * Unlike the failure counters this counts successes too. It backs a
     * per-IP throttle for endpoints where a successful action is still
     * worth limiting, such as a resend that sends mail.
     */
    public function countRecentByIpAndType(string $ip, string $idType, string $since): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->eq('ip_address', $ip)
            ->eq('id_type', $idType)
            ->gte('date', $since)
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Most recent row date for an IP and id_type, or null if none.
     */
    public function latestDateByIpAndType(string $ip, string $idType): ?string
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('MAX(date) as latest_date')
            ->eq('ip_address', $ip)
            ->eq('id_type', $idType)
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
            ->ne('id_type', self::ID_TYPE_ACTIVATION_RESEND)
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
            ->ne('id_type', self::ID_TYPE_ACTIVATION_RESEND)
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
