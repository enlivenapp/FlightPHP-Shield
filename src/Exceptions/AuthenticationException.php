<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Exceptions;

class AuthenticationException extends RuntimeException
{
    protected int $httpCode = 403;

    public function getHttpCode(): int
    {
        return $this->httpCode;
    }

    public static function forUnknownAuthenticator(string $alias): static
    {
        return new static("Unknown authenticator: {$alias}");
    }

    public static function forInvalidUser(): static
    {
        return new static('Invalid user.');
    }

    public static function forBannedUser(): static
    {
        return new static('User is banned.');
    }

    public static function forInvalidCredentials(): static
    {
        return new static('Invalid credentials.');
    }

    public static function forNoPassword(): static
    {
        return new static('No password identity found.');
    }

    public static function forNoEntityProvided(): static
    {
        return new static('No user entity provided for password validation.');
    }

    public static function forUnsetPasswordLength(): static
    {
        return new static('Minimum password length must be greater than zero.');
    }

    public static function forHIBPCurlFail(\Throwable $e): static
    {
        return new static('Failed to connect to HIBP API: ' . $e->getMessage(), 0, $e);
    }

    public static function forTooManyRequests(): static
    {
        $e = new static('Too many requests. Please try again later.');
        $e->httpCode = 429;
        return $e;
    }
}
