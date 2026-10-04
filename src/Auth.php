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
use Enlivenapp\FlightShield\Services\CredentialVerifier;
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
    // verifyCredentials() failure reasons. One sentence per outcome; the
    // caller tells them apart by reading reason().
    public const CREDENTIALS_INVALID   = 'Invalid credentials.';
    public const ACCOUNT_BANNED        = 'This account has been banned.';
    public const ACCOUNT_NOT_ACTIVATED = 'This account is not activated. A new activation email has been sent.';

    protected Authentication $authentication;
    protected ?AuthenticatorInterface $authenticator = null;
    protected Engine $app;
    /** @var array<string, mixed> */
    protected array $config;
    protected CredentialVerifier $credentialVerifier;

    protected ?UserManagement $usersService = null;
    protected ?Groups $groupsService = null;
    protected ?Permissions $permissionsService = null;
    protected ?UserStats $statsService = null;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
        $this->authentication = new Authentication($app, $config);
        $this->credentialVerifier = new CredentialVerifier($app, $config);
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

    /**
     * @param array<string, mixed> $credentials
     */
    public function attempt(array $credentials): Result
    {
        return $this->getAuthenticator()->attempt($credentials);
    }

    /**
     * @param array<string, mixed> $credentials
     */
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
     * for any other caller. Only email and password are needed: the username
     * is derived from the email, and any username in $fields is ignored. No
     * session is read or written. When the config requires email activation,
     * the account is created inactive and the activation email is sent here.
     *
     * On failure the field errors are returned as an array via extraInfo(),
     * with the first error also set as the reason. A duplicate email address
     * reports success without revealing whether the account exists, except
     * for an address belonging to a soft-deleted account, which is refused.
     */
    /**
     * @param array<string, mixed> $fields
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
            return $this->followUpOnExistingAccount($existing->user_id, $email);
        }

        $requiresActivation = $this->requiresEmailActivation();

        $result = $this->users()->create(
            '',
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

            if (! $this->credentialVerifier->sendActivation($user)) {
                return (new Result())
                    ->setSuccess(false)
                    ->setReason('We could not send the activation email. Please try again.')
                    ->setExtraInfo(['We could not send the activation email. Please try again.']);
            }
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
     * Handle a registration attempt for an address that already has an
     * identity row.
     *
     * A soft-deleted account refuses the attempt. An unactivated account
     * gets a fresh link. Anything else gets the usual "someone tried to
     * register" notice. Every outcome other than the refusal reports
     * success, so the form cannot be used to probe for registered
     * addresses.
     */
    protected function followUpOnExistingAccount(int|string $userId, string $email): Result
    {
        $user = (new User($this->app->db()))->findByIdIncludingDeleted($userId);

        if ($user !== null && $user->deleted_at !== null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('That email address is no longer available.')
                ->setExtraInfo(['That email address is no longer available.']);
        }

        if ($this->requiresEmailActivation() && $user !== null && $user->isNotActivated()) {
            $this->credentialVerifier->sendActivation($user);
            return (new Result())->setSuccess(true);
        }

        $this->sendRegistrationAttemptNotice($email);

        return (new Result())->setSuccess(true);
    }

    /**
     * Tell an existing address that someone tried to register with it.
     *
     * Best effort: a mail failure here must not fail the request.
     */
    protected function sendRegistrationAttemptNotice(string $email): void
    {
        try {
            $sender = $this->config['email_sender'] ?? null;

            if ($sender === null || ! is_callable($sender)) {
                return;
            }

            $body = $this->app->view()->fetch('Email/email_register_existing', [
                'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                'date'      => date('Y-m-d H:i:s'),
            ]);

            $sender($email, 'Registration Attempt', $body);
        } catch (\Throwable $e) {
            // Swallowed on purpose.
        }
    }

    // -----------------------------------------------------------------
    // Credential verification (no session, no login)
    // -----------------------------------------------------------------

    /**
     * Verify an email/password pair without logging anyone in.
     *
     * Built for other plugins - a store, a checkout, an API - that need to
     * confirm who is at the keyboard before doing their own thing. No
     * session state is written and no login is started.
     *
     * Checks run in this order, and the first one that applies wins:
     *
     *   1. wrong email or password   -> failure, reason CREDENTIALS_INVALID
     *   2. banned account            -> failure, reason ACCOUNT_BANNED
     *   3. not activated             -> failure, reason ACCOUNT_NOT_ACTIVATED;
     *                                   a fresh activation email is sent
     *   4. valid, active, not banned -> success, user() is the User
     *
     * Failure: reason() names the outcome, user() is null. Success: user()
     * holds the User, reason() is null.
     */
    /**
     * @param array<string, mixed> $credentials
     */
    public function verifyCredentials(array $credentials): Result
    {
        $email    = trim((string) ($credentials['email'] ?? ''));
        $password = (string) ($credentials['password'] ?? '');

        $user = (new User($this->app->db()))->findByCredentials(['email' => $email]);

        if ($user === null) {
            // Burn the same time as a real check, so an unknown email cannot
            // be told apart from a wrong password by how long the answer took.
            $this->credentialVerifier->burnTiming($password);

            return $this->credentialFailure($email, self::CREDENTIALS_INVALID);
        }

        if ($password === '' || ! $this->credentialVerifier->passwordMatches($user, $password)) {
            return $this->credentialFailure($email, self::CREDENTIALS_INVALID);
        }

        if ($user->isBanned()) {
            return $this->credentialFailure(
                $email,
                $user->getBanMessage() ?? self::ACCOUNT_BANNED,
                $user->id
            );
        }

        if (! $user->isActivated()) {
            $this->credentialVerifier->sendActivation($user);

            return $this->credentialFailure($email, self::ACCOUNT_NOT_ACTIVATED, $user->id);
        }

        $this->credentialVerifier->recordAttempt(
            $email,
            UserIdentity::TYPE_EMAIL_PASSWORD,
            true,
            $user->id
        );

        return (new Result())
            ->setSuccess(true)
            ->setUser($user);
    }

    /**
     * Build a failed verification Result and record the attempt.
     */
    protected function credentialFailure(string $email, string $reason, ?int $userId = null): Result
    {
        $this->credentialVerifier->recordAttempt(
            $email,
            UserIdentity::TYPE_EMAIL_PASSWORD,
            false,
            $userId
        );

        return (new Result())
            ->setSuccess(false)
            ->setReason($reason);
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
