<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\JWT\Exceptions;

use Enlivenapp\FlightShield\Exceptions\ValidationException;

class InvalidTokenException extends ValidationException
{
    public const INVALID_TOKEN      = 1;
    public const EXPIRED_TOKEN      = 2;
    public const BEFORE_VALID_TOKEN = 3;

    public static function forInvalidToken(\Exception $e): static
    {
        return new static('Invalid JWT.', self::INVALID_TOKEN, $e);
    }

    public static function forExpiredToken(\Exception $e): static
    {
        return new static('Expired JWT.', self::EXPIRED_TOKEN, $e);
    }

    public static function forBeforeValidToken(\Exception $e): static
    {
        return new static('JWT is not yet valid.', self::BEFORE_VALID_TOKEN, $e);
    }
}
