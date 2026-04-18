<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Traits;

trait Bannable
{
    public function isBanned(): bool
    {
        return $this->status === 'banned';
    }

    public function ban(?string $message = null): static
    {
        $this->status = 'banned';
        $this->status_message = $message;
        return $this;
    }

    public function unBan(): static
    {
        $this->status = null;
        $this->status_message = null;
        return $this;
    }

    public function getBanMessage(): ?string
    {
        return $this->status_message;
    }
}
