<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Support\RobotDetector;
use flight\Engine;

class MagicLinkController
{
    protected Engine $app;
    protected array $config;

    public function __construct(Engine $app, string $configPrepend)
    {
        $this->app = $app;
        $this->config = $app->get($configPrepend) ?? [];
    }

    public function showLoginForm(): void
    {
        if (! ($this->config['allow_magic_link'] ?? true)) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        if ($this->app->auth()->loggedIn()) {
            $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
            return;
        }

        $this->app->render('magic_link_login', ['config' => $this->config]);
    }

    public function sendMagicLink(): void
    {
        if (! ($this->config['allow_magic_link'] ?? true)) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        $email = trim($this->app->request()->data->email ?? '');

        /** @var UserRepository $userRepo */
        $userModel = new User(\Flight::db());
        $user = $userModel->findByCredentials(['email' => $email]);

        if ($user === null) {
            $this->app->render('magic_link_message', ['config' => $this->config]);
            return;
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());

        // Delete previous magic link identities
        $identityModel->deleteIdentitiesByType($user, UserIdentity::TYPE_MAGIC_LINK);

        // Generate token
        $token = bin2hex(random_bytes(20));
        $lifetime = $this->config['magic_link_lifetime'] ?? 3600;

        $identity = new UserIdentity(\Flight::db());
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_MAGIC_LINK;
        $identity->secret  = hash('sha256', $token);
        $identity->expires = (new \DateTimeImmutable("+{$lifetime} seconds"))->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $identity->insert();

        $sender = $this->config['email_sender'] ?? null;
        if ($sender !== null && is_callable($sender)) {
            $emailIdentity = $identityModel->getEmailIdentity($user);
            $to = $emailIdentity ? $emailIdentity->secret : '';

            $baseUrl = rtrim($this->app->get('flight.base_url') ?? '', '/');
            $magicLinkUrl = $baseUrl . '/auth/magic-link/verify?token=' . urlencode($token);

            $body = $this->app->view()->fetch('Email/magic_link_email', [
                'magicLinkUrl' => $magicLinkUrl,
                'ipAddress'    => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                'userAgent'    => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'date'         => date('Y-m-d H:i:s'),
            ]);

            $sender($to, 'Your Login Link', $body);
        }

        $this->app->render('magic_link_message', ['config' => $this->config]);
    }

    public function verify(): void
    {
        if (! ($this->config['allow_magic_link'] ?? true)) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        // Ignore robots so they cannot consume magic-link tokens
        if (RobotDetector::isBot($_SERVER['HTTP_USER_AGENT'] ?? '', $this->config['bot_detection'] ?? [])) {
            $this->app->halt(404);
            return;
        }

        $token = $this->app->request()->query->token ?? '';

        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getIdentityBySecret(UserIdentity::TYPE_MAGIC_LINK, hash('sha256', $token));

        if ($identity === null) {
            $this->recordMagicLinkLogin($token, false);
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        // Delete the identity so it can't be reused
        $identity->delete();

        // Expired?
        if ($identity->isExpired()) {
            $this->recordMagicLinkLogin($token, false);
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        /** @var UserRepository $userRepo */
        $userModel = new User(\Flight::db());
        $user = $userModel->findById($identity->user_id);

        if ($user === null) {
            $this->recordMagicLinkLogin($token, false);
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        if ($user->isBanned()) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        /** @var Session $authenticator */
        $authenticator = $this->app->auth()->setAuthenticator('session')->getAuthenticator();

        // Start a login action (e.g. 2FA) when one applies to this user,
        // otherwise start the register action (email activation) for
        // inactive users. Inactive users either way continue to an action
        // instead of being logged straight in.
        $started = $authenticator->startUpAction('login', $user);
        if (! $started && ! $user->isActivated()) {
            $started = $authenticator->startUpAction('register', $user);
        }

        if ($started) {
            $authenticator->setPendingLoginMethod(Session::ID_TYPE_MAGIC_LINK);
            $this->recordMagicLinkLogin($token, true, $identity->user_id);
            $this->redirectToAction($authenticator->getAction());
            return;
        }

        $authenticator->setPendingLoginMethod(Session::ID_TYPE_MAGIC_LINK);
        $authenticator->loginById($identity->user_id);

        $this->recordMagicLinkLogin($token, true, $identity->user_id);

        $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
    }

    /**
     * Redirect to the pending action's page, mirroring LoginController.
     */
    protected function redirectToAction(?object $action): void
    {
        if ($action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
            $this->app->redirect('/auth/2fa');
            return;
        }

        if ($action instanceof \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator) {
            $this->app->redirect('/auth/activate');
            return;
        }

        $this->app->redirect('/');
    }

    protected function recordMagicLinkLogin(string $identifier, bool $success, ?int $userId = null): void
    {
        $recordLevel = $this->config['record_login_attempt'] ?? 'none';
        if ($recordLevel === 'none') {
            return;
        }
        if ($recordLevel === 'failure' && $success) {
            return;
        }

        $login = new Login(\Flight::db());
        $login->id_type    = UserIdentity::TYPE_MAGIC_LINK;
        $login->identifier = hash('sha256', $identifier);
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $login->insert();
    }
}
