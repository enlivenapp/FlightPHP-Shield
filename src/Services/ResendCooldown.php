<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Services;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;

/**
 * The server-side cooldown that holds back resend emails.
 *
 * The activation page and the 2FA page both send a fresh link or code on
 * demand. This reads the last identity of a given type and reports how long
 * the caller has to wait before sending another.
 */
class ResendCooldown
{
    /** Seconds between resend emails when the config key is absent. */
    public const DEFAULT_SECONDS = 300;

    /** @var array<string, mixed> */
    protected array $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Configured cooldown in seconds.
     */
    public function seconds(): int
    {
        return (int) ($this->config['resend_cooldown'] ?? self::DEFAULT_SECONDS);
    }

    /**
     * Seconds left before another send is allowed.
     *
     * Read from the existing identity of $identityType. A send replaces that
     * row, so this has to run before the send.
     */
    public function remaining(User $user, string $identityType): int
    {
        $identity = (new UserIdentity(\Flight::db()))
            ->getIdentityByType($user, $identityType);

        if ($identity === null || $identity->created_at === null) {
            return 0;
        }

        $elapsed = time() - (new \DateTimeImmutable($identity->created_at))->getTimestamp();
        $cooldown = $this->seconds();

        return $elapsed < $cooldown ? $cooldown - $elapsed : 0;
    }

    /**
     * Format seconds as m:ss for display.
     */
    public function format(int $seconds): string
    {
        return intdiv($seconds, 60) . ':' . str_pad((string) ($seconds % 60), 2, '0', STR_PAD_LEFT);
    }
}
