<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Traits;

use Enlivenapp\FlightShield\Models\AccessToken;

/**
 * Provides HMAC Token methods.
 * Intended for use on the User entity.
 */
trait HasHmacTokens
{
    private ?AccessToken $currentHmacToken = null;

    public function currentHmacToken(): ?AccessToken
    {
        return $this->currentHmacToken;
    }

    public function setHmacToken(?AccessToken $accessToken): static
    {
        $this->currentHmacToken = $accessToken;
        return $this;
    }

    public function hmacTokenCan(string $scope): bool
    {
        if ($this->currentHmacToken === null) {
            return false;
        }

        return $this->currentHmacToken->can($scope);
    }

    public function hmacTokenCant(string $scope): bool
    {
        if ($this->currentHmacToken === null) {
            return true;
        }

        return $this->currentHmacToken->cant($scope);
    }

    public function isHmacTokenExpired(AccessToken $token): bool
    {
        return $token->isExpired();
    }
}
