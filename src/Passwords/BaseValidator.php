<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Passwords;

class BaseValidator
{
    protected ?string $error = null;
    protected ?string $suggestion = null;
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function error(): ?string
    {
        return $this->error;
    }

    public function suggestion(): ?string
    {
        return $this->suggestion;
    }
}
