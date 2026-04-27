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
 * Provides Personal Access Token methods.
 * Intended for use on the User entity.
 *
 * Token generation/revocation requires the ORM and identity repository,
 * which are accessed via the Auth facade at runtime.
 */
trait HasAccessTokens
{
    private ?AccessToken $currentAccessToken = null;

    public function currentAccessToken(): ?AccessToken
    {
        return $this->currentAccessToken;
    }

    public function setAccessToken(?AccessToken $accessToken): static
    {
        $this->currentAccessToken = $accessToken;
        return $this;
    }

    public function tokenCan(string $scope): bool
    {
        if ($this->currentAccessToken === null) {
            return false;
        }

        return $this->currentAccessToken->can($scope);
    }

    public function tokenCant(string $scope): bool
    {
        if ($this->currentAccessToken === null) {
            return true;
        }

        return $this->currentAccessToken->cant($scope);
    }

    public function isAccessTokenExpired(AccessToken $token): bool
    {
        return $token->isExpired();
    }
}
