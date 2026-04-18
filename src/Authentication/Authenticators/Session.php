<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Cycle\ORM\EntityManager;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Entities\Login;
use Enlivenapp\FlightShield\Entities\RememberToken;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Repositories\RememberTokenRepository;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use Enlivenapp\FlightShield\Repositories\UserRepository;
use Enlivenapp\FlightShield\Result;
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
                ->setReason('User is banned: ' . ($user->getBanMessage() ?? ''));
        }

        if (! $user->isActivated()) {
            $this->recordLogin($credentials, false, $user->id);
            return (new Result())
                ->setSuccess(false)
                ->setReason('User account is not active.');
        }

        // Rehash password if needed
        $identityRepo = $this->getIdentityRepository();
        $identity = $identityRepo->getEmailIdentity($user);

        if ($identity && $this->passwords->needsRehash($identity->secret2)) {
            $identity->secret2 = $this->passwords->hash($credentials['password']);
            $identity->updated_at = new \DateTimeImmutable();
            $em = new EntityManager($this->getOrm());
            $em->persist($identity)->run();
        }

        if ($identity) {
            $identityRepo->touchIdentity($identity, $this->getOrm());
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
        $userRepo = $this->getUserRepository();
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

        $identityRepo = $this->getIdentityRepository();
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
        $_SESSION[$sessionField] = $user->id;

        $this->user = $user;
        $this->userState = self::STATE_LOGGED_IN;
    }

    public function loginById(int|string $userId): void
    {
        $user = $this->getUserRepository()->findById($userId);

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
            $rememberRepo = $this->getRememberRepository();
            $rememberRepo->deleteByUser($this->user->id, $this->getOrm());
            $this->clearCookie($cookieName);
        }

        unset($_SESSION[$sessionField], $_SESSION['auth_action']);

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

        $this->user->last_active = new \DateTimeImmutable();
        $em = new EntityManager($this->getOrm());
        $em->persist($this->user)->run();
    }

    // -----------------------------------------------------------------
    // Pending user (for actions / 2FA)
    // -----------------------------------------------------------------

    public function getPendingUser(): ?User
    {
        $sessionField = $this->config['session']['field'] ?? 'user';

        if (! isset($_SESSION[$sessionField])) {
            return null;
        }

        return $this->getUserRepository()->findById($_SESSION[$sessionField]);
    }

    public function isPending(): bool
    {
        $this->checkUserState();
        return $this->userState === self::STATE_PENDING;
    }

    public function startAction(string $actionClass, User $user): void
    {
        $sessionField = $this->config['session']['field'] ?? 'user';
        $_SESSION[$sessionField] = $user->id;
        $_SESSION['auth_action'] = $actionClass;

        $this->user = $user;
        $this->userState = self::STATE_PENDING;
    }

    public function getAction(): ?object
    {
        $actionClass = $_SESSION['auth_action'] ?? null;

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
        return isset($_SESSION['auth_action']);
    }

    public function completeAction(): void
    {
        unset($_SESSION['auth_action']);
        $this->regenerateSession();
        $this->userState = self::STATE_LOGGED_IN;
    }

    public function checkAction(?UserIdentity $identity, ?string $token): bool
    {
        if ($identity === null || $token === null) {
            return false;
        }

        if (!hash_equals($identity->secret, $token)) {
            return false;
        }

        // Delete the identity
        $em = new EntityManager($this->getOrm());
        $em->delete($identity)->run();

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

        $token = new RememberToken();
        $token->selector         = $selector;
        $token->hashed_validator = hash('sha256', $validator);
        $token->user_id          = $this->user->id;
        $token->expires          = new \DateTimeImmutable("+{$expires} seconds");
        $token->created_at       = new \DateTimeImmutable();
        $token->updated_at       = new \DateTimeImmutable();

        $em = new EntityManager($this->getOrm());
        $em->persist($token)->run();

        $cookieName = $this->config['session']['remember_cookie_name'] ?? 'remember';

        setcookie($cookieName, $selector . ':' . $validator, [
            'expires'  => time() + $expires,
            'path'     => '/',
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Strict',
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

        $rememberRepo = $this->getRememberRepository();
        $token = $rememberRepo->findBySelector($selector);

        if ($token === null || $token->isExpired()) {
            $this->clearCookie($cookieName);
            return;
        }

        if (! hash_equals($token->hashed_validator, hash('sha256', $validator))) {
            // Possible token theft — purge all tokens for this user
            $rememberRepo->deleteByUser($token->user_id, $this->getOrm());
            $this->clearCookie($cookieName);
            return;
        }

        $user = $this->getUserRepository()->findById($token->user_id);

        if ($user === null || $user->isBanned() || ! $user->isActivated()) {
            $this->clearCookie($cookieName);
            return;
        }

        // Delete old token, log in, issue new token
        $em = new EntityManager($this->getOrm());
        $em->delete($token)->run();

        $this->login($user);
        $this->remember();

        // Purge expired tokens occasionally (20% chance)
        if (random_int(1, 5) === 1) {
            $rememberRepo->purgeExpired($this->getOrm());
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

        if (! isset($_SESSION[$sessionField])) {
            if ($this->config['session']['allow_remembering'] ?? true) {
                $this->checkRememberMe();
            }

            if ($this->user === null) {
                $this->userState = self::STATE_ANONYMOUS;
            }
            return;
        }

        $userId = $_SESSION[$sessionField];
        $user = $this->getUserRepository()->findById($userId);

        if ($user === null) {
            unset($_SESSION[$sessionField]);
            $this->userState = self::STATE_ANONYMOUS;
            return;
        }

        $this->user = $user;

        if (isset($_SESSION['auth_action'])) {
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

        $login = new Login();
        $login->id_type    = isset($credentials['email']) ? 'email_password' : 'username';
        $login->identifier = $credentials['email'] ?? $credentials['username'] ?? 'unknown';
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = new \DateTimeImmutable();

        $em = new EntityManager($this->getOrm());
        $em->persist($login)->run();
    }

    protected function getUserRepository(): UserRepository
    {
        return $this->app->orm()->getRepository(User::class);
    }

    protected function getIdentityRepository(): UserIdentityRepository
    {
        return $this->app->orm()->getRepository(UserIdentity::class);
    }

    protected function getRememberRepository(): RememberTokenRepository
    {
        return $this->app->orm()->getRepository(RememberToken::class);
    }

    protected function getOrm(): \Cycle\ORM\ORMInterface
    {
        return $this->app->orm();
    }

    protected function ensureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE && php_sapi_name() !== 'cli') {
            session_start();
        }
    }

    protected function regenerateSession(): void
    {
        if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
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
