<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Actions;

use Enlivenapp\FlightShield\Models\User;

/**
 * Actions implementing this interface are only started when the given
 * user satisfies appliesTo(). Actions that do not implement it apply to
 * every user.
 *
 * Ported from CodeIgniter Shield's ConditionalActionInterface
 * (original PR by memleakd — @see https://github.com/codeigniter4/shield/pull/1328).
 */
interface ConditionalActionInterface
{
    /**
     * Whether this action should run for the given user.
     */
    public function appliesTo(User $user): bool;
}