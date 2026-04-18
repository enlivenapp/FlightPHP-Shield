<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Traits;

use Enlivenapp\FlightShield\Entities\UserIdentity;

/**
 * Provides password reset enforcement methods.
 * Intended for use on the User entity.
 */
trait Resettable
{
    /**
     * Whether this user's email identity has force_reset set.
     * Requires identities to be loaded or a repository lookup.
     */
    public function requiresPasswordReset(): bool
    {
        foreach ($this->identities as $identity) {
            if ($identity->type === UserIdentity::TYPE_EMAIL_PASSWORD) {
                return $identity->force_reset;
            }
        }

        return false;
    }
}
