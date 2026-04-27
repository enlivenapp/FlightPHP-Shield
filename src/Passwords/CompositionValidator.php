<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Passwords;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Result;

/**
 * Checks password meets minimum length requirements per NIST SP 800-63B.
 */
class CompositionValidator extends BaseValidator implements ValidatorInterface
{
    public function check(string $password, ?User $user = null): Result
    {
        $minLength = $this->config['min_length'] ?? 8;

        if (mb_strlen($password, 'UTF-8') < $minLength) {
            return (new Result())
                ->setSuccess(false)
                ->setReason("Password must be at least {$minLength} characters.")
                ->setExtraInfo('Longer passwords are more secure.');
        }

        if (mb_strlen($password, 'UTF-8') > 128) {
            return (new Result())->setSuccess(false)->setReason('Password must not exceed 128 characters.');
        }

        return (new Result())->setSuccess(true);
    }
}
