<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Actions;

use Enlivenapp\FlightShield\Models\User;
use flight\Engine;

/**
 * Authentication Actions are steps after the main authentication,
 * like email activation or 2FA verification.
 */
interface ActionInterface
{
    /**
     * Show the initial screen (e.g., "we sent you a code").
     */
    public function show(Engine $app): string;

    /**
     * Handle the form submission (e.g., send the email).
     */
    public function handle(Engine $app): string;

    /**
     * Verify the user's response (e.g., check the code).
     */
    public function verify(Engine $app): string;

    /**
     * Return the identity type string (e.g., 'email_2fa').
     */
    public function getType(): string;

    /**
     * Create an identity record for this action.
     *
     * @return string The secret/code
     */
    public function createIdentity(User $user, Engine $app): string;
}
