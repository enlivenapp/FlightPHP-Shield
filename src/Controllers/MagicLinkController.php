<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Cycle\ORM\EntityManager;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Entities\Login;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use Enlivenapp\FlightShield\Repositories\UserRepository;
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
        $userRepo = $this->app->orm()->getRepository(\Enlivenapp\FlightShield\Entities\User::class);
        $user = $userRepo->findByCredentials(['email' => $email]);

        if ($user === null) {
            $this->app->render('magic_link_message', ['config' => $this->config]);
            return;
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $this->app->orm()->getRepository(UserIdentity::class);

        // Delete previous magic link identities
        $identityRepo->deleteIdentitiesByType($user, UserIdentity::TYPE_MAGIC_LINK, $this->app->orm());

        // Generate token
        $token = bin2hex(random_bytes(20));
        $lifetime = $this->config['magic_link_lifetime'] ?? 3600;

        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_MAGIC_LINK;
        $identity->secret  = hash('sha256', $token);
        $identity->expires = new \DateTimeImmutable("+{$lifetime} seconds");
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($this->app->orm());
        $em->persist($identity)->run();

        $sender = $this->config['email_sender'] ?? null;
        if ($sender !== null && is_callable($sender)) {
            $emailIdentity = $identityRepo->getEmailIdentity($user);
            $to = $emailIdentity ? $emailIdentity->secret : '';

            $magicLinkUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
                . '/auth/magic-link/verify?token=' . urlencode($token);

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

        $token = $this->app->request()->query->token ?? '';

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $this->app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getIdentityBySecret(UserIdentity::TYPE_MAGIC_LINK, hash('sha256', $token));

        if ($identity === null) {
            $this->recordMagicLinkLogin($token, false);
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        // Delete the identity so it can't be reused
        $em = new EntityManager($this->app->orm());
        $em->delete($identity)->run();

        // Expired?
        if ($identity->isExpired()) {
            $this->recordMagicLinkLogin($token, false);
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        /** @var \Enlivenapp\FlightShield\Repositories\UserRepository $userRepo */
        $userRepo = $this->app->orm()->getRepository(\Enlivenapp\FlightShield\Entities\User::class);
        $user = $userRepo->findById($identity->user_id);

        if ($user->isBanned()) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }
        if (!$user->isActivated()) {
            $this->app->redirect($this->config['redirects']['login'] ?? '/auth/login');
            return;
        }

        /** @var Session $authenticator */
        $authenticator = $this->app->auth()->setAuthenticator('session')->getAuthenticator();
        $authenticator->loginById($identity->user_id);

        $this->recordMagicLinkLogin($token, true, $identity->user_id);

        $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
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

        $login = new Login();
        $login->id_type    = UserIdentity::TYPE_MAGIC_LINK;
        $login->identifier = hash('sha256', $identifier);
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = new \DateTimeImmutable();

        $em = new EntityManager($this->app->orm());
        $em->persist($login)->run();
    }
}
