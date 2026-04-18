<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

namespace Enlivenapp\FlightShield;

use Enlivenapp\FlightShield\Authentication\Authentication;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Entities\User;
use flight\Engine;

/**
 * Auth facade — provides a convenient interface to the authentication system.
 *
 * Delegates to the active authenticator for: attempt, check, login, loginById,
 * logout, loggedIn, getUser, recordActiveDate.
 */
class Auth
{
    protected Authentication $authentication;
    protected ?AuthenticatorInterface $authenticator = null;
    protected Engine $app;
    protected array $config;

    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
        $this->authentication = new Authentication($app, $config);
    }

    public function setAuthenticator(?string $alias = null): static
    {
        $this->authenticator = $this->authentication->factory($alias);
        return $this;
    }

    public function getAuthenticator(): AuthenticatorInterface
    {
        if ($this->authenticator === null) {
            $this->authenticator = $this->authentication->factory();
        }

        return $this->authenticator;
    }

    public function user(): ?User
    {
        return $this->getAuthenticator()->getUser();
    }

    public function id(): int|string|null
    {
        return $this->user()?->id;
    }

    // -----------------------------------------------------------------
    // Delegate to active authenticator
    // -----------------------------------------------------------------

    public function attempt(array $credentials): Result
    {
        return $this->getAuthenticator()->attempt($credentials);
    }

    public function check(array $credentials): Result
    {
        return $this->getAuthenticator()->check($credentials);
    }

    public function login(User $user): void
    {
        $this->getAuthenticator()->login($user);
    }

    public function loginById(int|string $userId): void
    {
        $this->getAuthenticator()->loginById($userId);
    }

    public function logout(): void
    {
        $this->getAuthenticator()->logout();
    }

    public function loggedIn(): bool
    {
        return $this->getAuthenticator()->loggedIn();
    }

    public function recordActiveDate(): void
    {
        $this->getAuthenticator()->recordActiveDate();
    }
}
