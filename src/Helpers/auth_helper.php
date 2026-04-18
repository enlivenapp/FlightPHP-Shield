<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

use Enlivenapp\FlightShield\Auth;

if (! function_exists('auth')) {
    /**
     * Provides convenient access to the Auth facade.
     */
    function auth(?string $alias = null): Auth
    {
        /** @var Auth $auth */
        $auth = Flight::auth();

        if ($alias !== null) {
            $auth->setAuthenticator($alias);
        }

        return $auth;
    }
}

if (! function_exists('user_id')) {
    /**
     * Returns the ID of the currently logged-in user.
     */
    function user_id(): int|string|null
    {
        return Flight::auth()->id();
    }
}
