<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use Enlivenapp\FlightShield\Entities\Login;
use flight\Engine;

/**
 * Per-IP rate limiting middleware for authentication endpoints.
 *
 * Counts failed login attempts from the client IP within the configured
 * decay window. If the threshold is reached and the most recent failure
 * falls within the lockout window, the request is halted with a 429.
 *
 * Configuration (merged from 'enlivenapp.flight-shield'):
 *   rate_limiting.enabled         — bool, default true
 *   rate_limiting.max_attempts    — int,  default 10
 *   rate_limiting.decay_minutes   — int,  default 30
 *   rate_limiting.lockout_minutes — int,  default 30
 */
class RateLimitMiddleware
{
    protected Engine $app;

    public function __construct(Engine $app)
    {
        $this->app = $app;
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

        $ip      = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $since   = new \DateTimeImmutable("-{$decayMinutes} minutes");

        /** @var \Cycle\ORM\Select\Repository $loginRepo */
        $loginRepo = $this->app->orm()->getRepository(Login::class);

        $recentFailures = $loginRepo->select()
            ->where('ip_address', $ip)
            ->where('success', false)
            ->where('date', '>=', $since->format('Y-m-d H:i:s'))
            ->count();

        if ($recentFailures < $maxAttempts) {
            return;
        }

        // Threshold reached — check if the most recent failure is still within the lockout window
        /** @var Login|null $latest */
        $latest = $loginRepo->select()
            ->where('ip_address', $ip)
            ->where('success', false)
            ->orderBy('date', 'DESC')
            ->limit(1)
            ->fetchOne();

        if ($latest === null) {
            return;
        }

        $lockoutCutoff = new \DateTimeImmutable("-{$lockoutMinutes} minutes");

        if ($latest->date >= $lockoutCutoff) {
            $this->app->halt(429, json_encode([
                'error' => 'Too many attempts. Please try again later.',
            ]));
        }
    }
}
