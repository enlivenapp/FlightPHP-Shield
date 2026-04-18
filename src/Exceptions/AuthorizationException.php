<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Exceptions;

class AuthorizationException extends RuntimeException
{
    protected int $httpCode = 403;

    public function getHttpCode(): int
    {
        return $this->httpCode;
    }

    public static function forUnknownGroup(string $group): static
    {
        return new static("Unknown group: {$group}");
    }

    public static function forUnknownPermission(string $permission): static
    {
        return new static("Unknown permission: {$permission}");
    }

    public static function forUnauthorized(): static
    {
        return new static('Not authorized.');
    }
}
