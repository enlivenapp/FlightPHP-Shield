<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Traits;

trait Activatable
{
    public function isActivated(): bool
    {
        return $this->active;
    }

    public function isNotActivated(): bool
    {
        return ! $this->isActivated();
    }

    public function activate(): void
    {
        $this->active = true;
    }

    public function deactivate(): void
    {
        $this->active = false;
    }
}
