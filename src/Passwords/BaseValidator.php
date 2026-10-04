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
    /** @var array<string, mixed> */
    protected array $config;

    /**
     * @param array<string, mixed> $config
     */
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
