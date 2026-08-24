<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\RememberToken;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Result;
use Enlivenapp\FlightSessions\SessionManager;
use flight\Engine;

class Session implements AuthenticatorInterface
{
    // User states
    public const STATE_UNKNOWN   = 0;
    public const STATE_ANONYMOUS = 1;
    public const STATE_PENDING   = 2;
    public const STATE_LOGGED_IN = 3;

    // Identity type constants (used by actions)
    public const ID_TYPE_EMAIL_PASSWORD = 'email_password';
    public const ID_TYPE_MAGIC_LINK     = 'magic-link';
    public const ID_TYPE_EMAIL_2FA      = 'email_2fa';
    public const ID_TYPE_EMAIL_ACTIVATE = 'email_activate';

    protected Engine $app;
    protected array $config;
    protected ?User $user = null;
    protected int $userState = self::STATE_UNKNOWN;
    protected Passwords $passwords;

    /** @var SessionManager|null Resolved lazily via sessions() */
    protected ?SessionManager $store = null;

    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
        $this->passwords = new Passwords($config['passwords'] ?? []);

        $this->ensureSession();
    }

    // -----------------------------------------------------------------
    // AuthenticatorInterface
    // -----------------------------------------------------------------

    public function attempt(array $credentials): Result
    {
        $result = $this->check($credentials);

        if (! $result->isOK()) {
            $this->recordLogin($credentials, false);
            return $result;
        }

        /** @var User $user */
        $user = $result->extraInfo();

        if ($user->isBanned()) {
            $this->recordLogin($credentials, false, $user->id);
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid credentials.');
        }

        if (! $user->isActivated()) {
            $this->recordLogin($credentials, false, $user->id);
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid credentials.');
        }

        // Rehash password if needed
        $identityRepo = $this->getIdentityModel();
        $identity = $identityRepo->getEmailIdentity($user);

        if ($identity && $this->passwords->needsRehash($identity->secret2)) {
            $identity->secret2 = $this->passwords->hash($credentials['password']);
            $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
            // Explicit dirty(): typed property assignment bypasses __set().
            $identity->dirty(['secret2' => $identity->secret2, 'updated_at' => $identity->updated_at]);
            $identity->save();
        }

        if ($identity) {
            $identityRepo->touchIdentity($identity);
        }

        // Check for login action (2FA, activation)
        $actionClass = $this->config['actions']['login'] ?? null;
        if ($actionClass !== null) {
            $this->startAction($actionClass, $user);
            $this->recordLogin($credentials, true, $user->id);
            return (new Result())->setSuccess(true)->setExtraInfo($user);
        }

        $this->login($user);
        $this->recordLogin($credentials, true, $user->id);

        return $result;
    }

    public function check(array $credentials): Result
    {
        $userRepo = $this->getUserModel();
        $user = $userRepo->findByCredentials($credentials);

        if ($user === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid credentials.');
        }

        if (! isset($credentials['password'])) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Password is required.');
        }

        $identityRepo = $this->getIdentityModel();
        $identity = $identityRepo->getEmailIdentity($user);

        if ($identity === null || $identity->secret2 === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('No password identity found.');
        }

        if (! $this->passwords->verify($credentials['password'], $identity->secret2)) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid credentials.');
        }

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    public function login(User $user): void
    {
        $this->regenerateSession();

        $sessionField = $this->config['session']['field'] ?? 'user';
        $this->sessions()->setUserContext((int) $user->id)->set($sessionField, $user->id);

        $this->user = $user;
        $this->userState = self::STATE_LOGGED_IN;
    }

    public function loginById(int|string $userId): void
    {
        $user = $this->getUserModel()->findById($userId);

        if ($user === null) {
            throw AuthenticationException::forInvalidUser();
        }

        $this->login($user);
    }

    public function logout(): void
    {
        $sessionField = $this->config['session']['field'] ?? 'user';

        // Remove remember-me token
        $cookieName = $this->config['session']['remember_cookie_name'] ?? 'remember';
        if (isset($_COOKIE[$cookieName]) && $this->user) {
            $rememberRepo = $this->getRememberModel();
            $rememberRepo->deleteByUser($this->user->id);
            $this->clearCookie($cookieName);
        }

        $this->sessions()->delete($sessionField)->delete('auth_action')->setUserContext(null);

        $this->regenerateSession();

        $this->user = null;
        $this->userState = self::STATE_ANONYMOUS;
    }

    public function loggedIn(): bool
    {
        if ($this->userState === self::STATE_LOGGED_IN) {
            return true;
        }

        $this->checkUserState();

        return $this->userState === self::STATE_LOGGED_IN;
    }

    public function getUser(): ?User
    {
        if ($this->userState !== self::STATE_LOGGED_IN) {
            $this->checkUserState();
        }

        return $this->user;
    }

    public function recordActiveDate(): void
    {
        if ($this->user === null) {
            return;
        }

        if (! ($this->config['record_active_date'] ?? true)) {
            return;
        }

        $this->user->last_active = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->user->save();
    }

    // -----------------------------------------------------------------
    // Pending user (for actions / 2FA)
    // -----------------------------------------------------------------

    public function getPendingUser(): ?User
    {
        $sessionField = $this->config['session']['field'] ?? 'user';
        $store = $this->sessions();

        if (! $store->has($sessionField)) {
            return null;
        }

        return $this->getUserModel()->findById($store->get($sessionField));
    }

    public function isPending(): bool
    {
        $this->checkUserState();
        return $this->userState === self::STATE_PENDING;
    }

    public function startAction(string $actionClass, User $user): void
    {
        $sessionField = $this->config['session']['field'] ?? 'user';
        $this->sessions()->setUserContext((int) $user->id)
            ->set($sessionField, $user->id)
            ->set('auth_action', $actionClass);

        $this->user = $user;
        $this->userState = self::STATE_PENDING;
    }

    public function getAction(): ?object
    {
        $actionClass = $this->sessions()->get('auth_action');

        if ($actionClass === null || ! class_exists($actionClass)) {
            return null;
        }

        if (! in_array($actionClass, [$this->config['actions']['login'] ?? '', $this->config['actions']['register'] ?? ''], true)) {
            return null;
        }

        return new $actionClass();
    }

    public function hasAction(int|string $userId): bool
    {
        return $this->sessions()->has('auth_action');
    }

    public function completeAction(): void
    {
        $this->sessions()->delete('auth_action')->delete('2fa_code_sent');
        $this->regenerateSession();
        $this->userState = self::STATE_LOGGED_IN;
    }

    public function checkAction(?UserIdentity $identity, ?string $token): bool
    {
        if ($identity === null || $token === null) {
            return false;
        }

        if ($identity->isExpired()) {
            return false;
        }

        if (!hash_equals($identity->secret, hash('sha256', $token))) {
            return false;
        }

        // Delete the identity
        $identity->delete();

        $this->completeAction();

        return true;
    }

    // -----------------------------------------------------------------
    // Remember me
    // -----------------------------------------------------------------

    public function remember(): void
    {
        if ($this->user === null) {
            return;
        }

        $selector  = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(20));
        $expires   = $this->config['session']['remember_length'] ?? 30 * 86400;

        $token = new RememberToken(\Flight::db());
        $token->selector         = $selector;
        $token->hashed_validator = hash('sha256', $validator);
        $token->user_id          = $this->user->id;
        $token->expires          = (new \DateTimeImmutable("+{$expires} seconds"))->format('Y-m-d H:i:s');
        $token->created_at       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $token->updated_at       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $token->insert();

        $cookieName = $this->config['session']['remember_cookie_name'] ?? 'remember';

        setcookie($cookieName, $selector . ':' . $validator, [
            'expires'  => time() + $expires,
            'path'     => '/',
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Lax',
        ]);
    }

    protected function checkRememberMe(): void
    {
        $cookieName = $this->config['session']['remember_cookie_name'] ?? 'remember';

        if (! isset($_COOKIE[$cookieName])) {
            return;
        }

        $parts = explode(':', $_COOKIE[$cookieName]);
        if (count($parts) !== 2) {
            $this->clearCookie($cookieName);
            return;
        }

        [$selector, $validator] = $parts;

        $rememberRepo = $this->getRememberModel();
        $token = $rememberRepo->findBySelector($selector);

        if ($token === null || $token->isExpired()) {
            $this->clearCookie($cookieName);
            return;
        }

        if (! hash_equals($token->hashed_validator, hash('sha256', $validator))) {
            // Possible token theft — purge all tokens for this user
            $rememberRepo->deleteByUser($token->user_id);
            $this->clearCookie($cookieName);
            return;
        }

        $user = $this->getUserModel()->findById($token->user_id);

        if ($user === null || $user->isBanned() || ! $user->isActivated()) {
            $this->clearCookie($cookieName);
            return;
        }

        // Delete old token, log in, issue new token
        $token->delete();

        $this->login($user);
        $this->remember();

        // Purge expired tokens occasionally (20% chance)
        if (random_int(1, 5) === 1) {
            $rememberRepo->purgeExpired();
        }
    }

    // -----------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------

    protected function checkUserState(): void
    {
        if ($this->userState !== self::STATE_UNKNOWN) {
            return;
        }

        $sessionField = $this->config['session']['field'] ?? 'user';
        $store = $this->sessions();

        if (! $store->has($sessionField)) {
            if ($this->config['session']['allow_remembering'] ?? true) {
                $this->checkRememberMe();
            }

            if ($this->user === null) {
                $this->userState = self::STATE_ANONYMOUS;
            }
            return;
        }

        $userId = $store->get($sessionField);
        $user = $this->getUserModel()->findById($userId);

        if ($user === null) {
            $store->delete($sessionField);
            $this->userState = self::STATE_ANONYMOUS;
            return;
        }

        $this->user = $user;

        if ($store->has('auth_action')) {
            $this->userState = self::STATE_PENDING;
        } else {
            $this->userState = self::STATE_LOGGED_IN;
        }
    }

    protected function recordLogin(array $credentials, bool $success, ?int $userId = null): void
    {
        $recordLevel = $this->config['record_login_attempt'] ?? 'none';

        if ($recordLevel === 'none') {
            return;
        }

        if ($recordLevel === 'failure' && $success) {
            return;
        }

        $login = new Login(\Flight::db());
        $login->id_type    = isset($credentials['email']) ? 'email_password' : 'username';
        $login->identifier = $credentials['email'] ?? $credentials['username'] ?? 'unknown';
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $login->insert();
    }

    protected function getUserModel(): User
    {
        return new User(\Flight::db());
    }

    protected function getIdentityModel(): UserIdentity
    {
        return new UserIdentity(\Flight::db());
    }

    protected function getRememberModel(): RememberToken
    {
        return new RememberToken(\Flight::db());
    }

    protected function ensureSession(): void
    {
        if (php_sapi_name() !== 'cli' && ! $this->sessions()->isActive()) {
            $this->sessions()->start();
        }
    }

    protected function regenerateSession(): void
    {
        if (php_sapi_name() !== 'cli') {
            $this->sessions()->regenerate(true);
        }
    }

    /**
     * Resolve the unified session store: the 'session' service bound by
     * enlivenapp/flight-sessions when available, otherwise a local
     * SessionManager wired to the app database (standalone/test contexts).
     */
    protected function sessions(): SessionManager
    {
        if ($this->store !== null) {
            return $this->store;
        }

        try {
            $resolved = $this->app->session();
        } catch (\Throwable) {
            $resolved = null;
        }

        if ($resolved instanceof SessionManager) {
            return $this->store = $resolved;
        }

        $manager = new SessionManager($this->config['session'] ?? []);

        try {
            $manager->setPdo($this->app->db());
        } catch (\Throwable) {
            // Storage unavailable — consumers that need persistence will
            // get a clear error from start().
        }

        return $this->store = $manager;
    }

    protected function clearCookie(string $name): void
    {
        setcookie($name, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Lax',
        ]);
    }
}
