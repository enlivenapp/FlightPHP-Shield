<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield;

use Enlivenapp\FlightShield\Authentication\Authentication;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authorization\Groups;
use Enlivenapp\FlightShield\Authorization\Permissions;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Services\UserManagement;
use Enlivenapp\FlightShield\Services\UserStats;
use flight\Engine;

/**
 * Auth facade — provides a convenient interface to the authentication system.
 *
 * Delegates to the active authenticator for: attempt, check, login, loginById,
 * logout, loggedIn, getUser, recordActiveDate.
 *
 * Also exposes Shield's high-level management APIs:
 *   users()       - user administration (list/find/create/update/activate/delete)
 *   groups()      - group administration (CRUD + permission assignment)
 *   permissions() - permission administration (CRUD)
 *   stats()       - user/login statistics
 */
class Auth
{
    protected Authentication $authentication;
    protected ?AuthenticatorInterface $authenticator = null;
    protected Engine $app;
    protected array $config;

    protected ?UserManagement $usersService = null;
    protected ?Groups $groupsService = null;
    protected ?Permissions $permissionsService = null;
    protected ?UserStats $statsService = null;

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

    // -----------------------------------------------------------------
    // Management APIs (per-request singletons)
    // -----------------------------------------------------------------

    /**
     * User administration: list, find, create, update, activate, delete.
     */
    public function users(): UserManagement
    {
        if ($this->usersService === null) {
            $this->usersService = new UserManagement($this->app->db(), $this->config);
        }

        return $this->usersService;
    }

    /**
     * Group administration: CRUD and permission assignment.
     */
    public function groups(): Groups
    {
        if ($this->groupsService === null) {
            $this->groupsService = new Groups($this->app->db());
        }

        return $this->groupsService;
    }

    /**
     * Permission administration: CRUD.
     */
    public function permissions(): Permissions
    {
        if ($this->permissionsService === null) {
            $this->permissionsService = new Permissions($this->app->db());
        }

        return $this->permissionsService;
    }

    /**
     * User and login statistics.
     */
    public function stats(): UserStats
    {
        if ($this->statsService === null) {
            $this->statsService = new UserStats($this->app->db());
        }

        return $this->statsService;
    }
}
