<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\TokenLogin;
use flight\Engine;

/**
 * Per-IP rate limiting middleware for authentication endpoints.
 *
 * Counts failed login attempts from the client IP within the configured
 * decay window. If the threshold is reached and the most recent failure
 * falls within the lockout window, the request is halted with a 429.
 *
 * Configuration (merged from 'enlivenapp.flight-shield'):
 *   rate_limiting.enabled         - bool, default true
 *   rate_limiting.max_attempts    - int,  default 10
 *   rate_limiting.decay_minutes   - int,  default 30
 *   rate_limiting.lockout_minutes - int,  default 30
 */
class RateLimitMiddleware
{
    protected Engine $app;
    protected ?string $countedIdType;

    /**
     * @param string|null $countedIdType When set, the limiter counts the
     *   auth_logins rows of this id_type for the client IP, sends included,
     *   and leaves the token-login table alone. The login, 2FA and magic-link
     *   routes pass nothing and keep counting failures across both tables.
     */
    public function __construct(Engine $app, ?string $countedIdType = null)
    {
        $this->app = $app;
        $this->countedIdType = $countedIdType;
    }

    public function before(): void
    {
        $config = $this->app->get('enlivenapp.flight-shield') ?? [];
        $rl     = $config['rate_limiting'] ?? [];

        if (! ($rl['enabled'] ?? true)) {
            return;
        }

        $maxAttempts    = (int) ($rl['max_attempts']    ?? 10);
        $decayMinutes   = (int) ($rl['decay_minutes']   ?? 30);
        $lockoutMinutes = (int) ($rl['lockout_minutes'] ?? 30);

        $ip    = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $since = (new \DateTimeImmutable("-{$decayMinutes} minutes"))->format('Y-m-d H:i:s');

        $db         = \Flight::db();
        $loginModel = new Login($db);
        $tokenModel = new TokenLogin($db);

        if ($this->countedIdType !== null) {
            // Endpoint counter: every row of this id_type counts, sends included.
            $hits = $loginModel->countRecentByIpAndType($ip, $this->countedIdType, $since);

            if ($hits < $maxAttempts) {
                return;
            }

            $latestDate = $loginModel->latestDateByIpAndType($ip, $this->countedIdType);
        } else {
            // Count failures across both session and token login tables
            $recentFailures = $loginModel->countRecentFailuresByIp($ip, $since)
                            + $tokenModel->countRecentFailuresByIp($ip, $since);

            if ($recentFailures < $maxAttempts) {
                return;
            }

            // Threshold reached - check if the most recent failure is still within the lockout window
            $loginLatest = $loginModel->latestFailureDateByIp($ip);
            $tokenLatest = $tokenModel->latestFailureDateByIp($ip);

            $latestDate = $loginLatest;
            if ($tokenLatest !== null && ($latestDate === null || $tokenLatest > $latestDate)) {
                $latestDate = $tokenLatest;
            }
        }

        if ($latestDate === null) {
            return;
        }

        $lockoutCutoff = (new \DateTimeImmutable("-{$lockoutMinutes} minutes"))->format('Y-m-d H:i:s');

        if ($latestDate >= $lockoutCutoff) {
            header('Retry-After: ' . ($lockoutMinutes * 60));
            $this->app->halt(429, (string) json_encode([
                'error' => 'Too many attempts. Please try again later.',
            ]));
        }
    }
}
