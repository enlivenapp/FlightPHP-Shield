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

class EmailActivator implements ActionInterface
{
    private string $type = Session::ID_TYPE_EMAIL_ACTIVATE;

    public function show(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        $code = $this->createIdentity($user, $app);
        $this->sendActivationEmail($user, $code, $app);

        return $app->view()->fetch('activate', ['user' => $user]);
    }

    public function handle(Engine $app): string
    {
        // Not used for email activation — the user clicks a link in the email
        throw new \RuntimeException('Not supported for email activation.');
    }

    public function verify(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $postedToken = $app->request()->query->token ?? $app->request()->data->token ?? '';

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getIdentityByType($user, $this->type);

        if ($identity->isExpired()) {
            return $app->view()->fetch('activate', ['error' => 'The activation token has expired. Please register again.']);
        }

        if (! $authenticator->checkAction($identity, $postedToken)) {
            return $app->view()->fetch('activate', ['error' => 'Invalid activation token.']);
        }

        // Activate the user
        $user->activate();
        $em = new \Cycle\ORM\EntityManager($app->orm());
        $em->persist($user)->run();

        $redirect = $app->get('enlivenapp.flight-shield')['redirects']['after_register'] ?? '/';
        $app->redirect($redirect);
        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    protected function sendActivationEmail(User $user, string $code, Engine $app): void
    {
        $config = $app->get('enlivenapp.flight-shield') ?? [];
        $sender = $config['email_sender'] ?? null;

        if ($sender === null || !is_callable($sender)) {
            throw new \RuntimeException('Shield email_sender callback is not configured.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getEmailIdentity($user);
        $to = $identity ? $identity->secret : '';

        $activationUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
            . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
            . '/auth/activate/verify?token=' . urlencode($code);

        $body = $app->view()->fetch('Email/email_activate_email', [
            'activationUrl' => $activationUrl,
            'ipAddress'     => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'userAgent'     => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'date'          => date('Y-m-d H:i:s'),
        ]);

        $sender($to, 'Activate Your Account', $body);
    }

    public function createIdentity(User $user, Engine $app): string
    {
        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $app->orm()->getRepository(UserIdentity::class);

        $identityRepo->deleteIdentitiesByType($user, $this->type, $app->orm());

        $generator = static fn(): string => (string) random_int(100000, 999999);

        return $identityRepo->createCodeIdentity(
            $user,
            [
                'type'    => $this->type,
                'name'    => 'register',
                'extra'   => 'Email verification required.',
                'expires' => new \DateTimeImmutable('+24 hours'),
            ],
            $generator,
            $app->orm()
        );
    }
}
