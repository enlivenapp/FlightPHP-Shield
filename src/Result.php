<?php

declare(strict_types=1);

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

namespace Enlivenapp\FlightShield;

/**
 * Value object representing the outcome of an authentication or authorization check.
 */
class Result
{
    protected bool $success = false;
    protected ?string $reason = null;
    protected mixed $extraInfo = null;

    public function isOK(): bool
    {
        return $this->success;
    }

    public function reason(): ?string
    {
        return $this->reason;
    }

    public function extraInfo(): mixed
    {
        return $this->extraInfo;
    }

    public function setSuccess(bool $success): static
    {
        $this->success = $success;
        return $this;
    }

    public function setReason(?string $reason): static
    {
        $this->reason = $reason;
        return $this;
    }

    public function setExtraInfo(mixed $extraInfo): static
    {
        $this->extraInfo = $extraInfo;
        return $this;
    }
}
