<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Traits;

use Enlivenapp\FlightShield\Models\UserIdentity;

/**
 * Provides password reset enforcement methods.
 * Intended for use on the User entity.
 */
trait Resettable
{
    /**
     * Whether this user's email identity has force_reset set.
     */
    public function requiresPasswordReset(): bool
    {
        $identity = new UserIdentity(\Flight::db());
        $identity->eq('user_id', $this->id)
                 ->eq('type', UserIdentity::TYPE_EMAIL_PASSWORD)
                 ->find();

        if (!$identity->isHydrated()) {
            return false;
        }

        return (bool) $identity->force_reset;
    }
}
