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

interface ValidatorInterface
{
    public function check(string $password, ?User $user = null): Result;
    public function error(): ?string;
    public function suggestion(): ?string;
}
