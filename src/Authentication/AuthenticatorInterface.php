<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

namespace Enlivenapp\FlightShield\Authentication;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Result;

interface AuthenticatorInterface
{
    /**
     * @param array<string, mixed> $credentials
     */
    public function attempt(array $credentials): Result;

    /**
     * @param array<string, mixed> $credentials
     */
    public function check(array $credentials): Result;
    public function loggedIn(): bool;
    public function login(User $user): void;
    public function loginById(int|string $userId): void;
    public function logout(): void;
    public function getUser(): ?User;
    public function recordActiveDate(): void;
}
