<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield;

use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Authentication\Authentication;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authorization\Groups;
use Enlivenapp\FlightShield\Authorization\Permissions;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Services\UserManagement;
use Enlivenapp\FlightShield\Services\UserStats;
use Enlivenapp\FlightShield\Validation\ValidationRules;
use flight\Engine;

/**
 * Auth facade - provides a convenient interface to the authentication system.
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
    // Registration
    // -----------------------------------------------------------------

    /**
     * Create an account from registration fields.
     *
     * This is the one entry point for registration, for the built-in form and
     * for any other caller. No session is read or written. When the config
     * requires email activation, the account is created inactive and the
     * activation email is sent here.
     *
     * On failure the field errors are returned as an array via extraInfo(),
     * with the first error also set as the reason. A duplicate email address
     * reports success without revealing whether the account exists.
     */
    public function register(array $fields): Result
    {
        $errors = (new ValidationRules($this->config['passwords'] ?? []))
            ->validate($fields, (new ValidationRules($this->config['passwords'] ?? []))->getRegistrationRules());

        if ($errors !== []) {
            return (new Result())
                ->setSuccess(false)
                ->setReason((string) reset($errors))
                ->setExtraInfo(array_values($errors));
        }

        $email = trim((string) ($fields['email'] ?? ''));

        // Silent success for an address that already has an account, so the
        // form cannot be used to probe for registered emails.
        $existing = (new UserIdentity($this->app->db()))
            ->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

        if ($existing !== null) {
            $this->sendRegistrationAttemptNotice($email);
            return (new Result())->setSuccess(true);
        }

        $requiresActivation = $this->requiresEmailActivation();

        $result = $this->users()->create(
            (string) ($fields['username'] ?? ''),
            $email,
            (string) ($fields['password'] ?? ''),
            $fields['group'] ?? null,
            $requiresActivation
        );

        if (! $result->isOK()) {
            return $result->setExtraInfo([$result->reason() ?? 'Registration failed.']);
        }

        if ($requiresActivation) {
            /** @var User $user */
            $user = $result->extraInfo();
            (new EmailActivator())->begin($user, $this->app);
        }

        return $result;
    }

    /**
     * Whether new accounts have to confirm their email before logging in.
     */
    protected function requiresEmailActivation(): bool
    {
        $actionClass = $this->config['actions']['register'] ?? null;

        return is_string($actionClass)
            && $actionClass !== ''
            && is_a($actionClass, EmailActivator::class, true);
    }

    /**
     * Tell an existing address that someone tried to register with it.
     */
    protected function sendRegistrationAttemptNotice(string $email): void
    {
        $sender = $this->config['email_sender'] ?? null;

        if ($sender === null || ! is_callable($sender)) {
            return;
        }

        $body = $this->app->view()->fetch('Email/email_register_existing', [
            'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'date'      => date('Y-m-d H:i:s'),
        ]);

        $sender($email, 'Registration Attempt', $body);
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
