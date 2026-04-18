<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Actions;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use flight\Engine;

class Email2FA implements ActionInterface
{
    private string $type = Session::ID_TYPE_EMAIL_2FA;

    public function show(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        $code = $this->createIdentity($user, $app);
        $this->sendCodeEmail($user, $code, $app);

        return $app->view()->fetch('2fa_verify');
    }

    public function handle(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        $code = $this->createIdentity($user, $app);
        $this->sendCodeEmail($user, $code, $app);

        return $app->view()->fetch('2fa_verify', ['message' => 'A new code has been sent.']);
    }

    public function verify(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $postedToken = $app->request()->data->token ?? '';

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getIdentityByType($user, $this->type);

        if ($identity->isExpired()) {
            return $app->view()->fetch('2fa_verify', ['error' => 'The 2FA code has expired. Please log in again.']);
        }

        if (! $authenticator->checkAction($identity, $postedToken)) {
            return $app->view()->fetch('2fa_verify', ['error' => 'Invalid 2FA code.']);
        }

        $redirect = $app->get('enlivenapp.flight-shield')['redirects']['after_login'] ?? '/';
        $app->redirect($redirect);
        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    protected function sendCodeEmail(User $user, string $code, Engine $app): void
    {
        $config = $app->get('enlivenapp.flight-shield') ?? [];
        $sender = $config['email_sender'] ?? null;

        if ($sender === null || !is_callable($sender)) {
            throw new \RuntimeException('Shield email_sender callback is not configured.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(\Enlivenapp\FlightShield\Entities\UserIdentity::class);
        $identity = $identityRepo->getEmailIdentity($user);
        $to = $identity ? $identity->secret : '';

        $body = $app->view()->fetch('Email/email_2fa_email', [
            'code'      => $code,
            'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'date'      => date('Y-m-d H:i:s'),
        ]);

        $sender($to, 'Your Verification Code', $body);
    }

    public function createIdentity(User $user, Engine $app): string
    {
        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(UserIdentity::class);

        $identityRepo->deleteIdentitiesByType($user, $this->type, $app->orm());

        $generator = static fn(): string => (string) random_int(100000, 999999);

        return $identityRepo->createCodeIdentity(
            $user,
            ['type' => $this->type, 'name' => 'login', 'extra' => 'Two-factor authentication required.'],
            $generator,
            $app->orm()
        );
    }
}
