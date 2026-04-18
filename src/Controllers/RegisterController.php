<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Cycle\ORM\EntityManager;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use flight\Engine;

class RegisterController
{
    protected Engine $app;
    protected array $config;

    public function __construct(Engine $app, string $configPrepend)
    {
        $this->app = $app;
        $this->config = $app->get($configPrepend) ?? [];
    }

    public function showRegister(): void
    {
        if (! ($this->config['allow_registration'] ?? true)) {
            $this->app->redirect('/');
            return;
        }

        if ($this->app->auth()->loggedIn()) {
            $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
            return;
        }

        $this->app->render('register', [
            'config' => $this->config,
        ]);
    }

    public function processRegister(): void
    {
        if (! ($this->config['allow_registration'] ?? true)) {
            $this->app->redirect('/');
            return;
        }

        $request = $this->app->request();
        $data = $request->data;

        $email    = trim($data->email ?? '');
        $username = trim($data->username ?? '');
        $password = $data->password ?? '';
        $passConf = $data->password_confirm ?? '';

        $errors = [];

        if (empty($email)) {
            $errors[] = 'Email is required.';
        }

        if ($password !== $passConf) {
            $errors[] = 'Passwords do not match.';
        }

        // Run password through validators
        $passwords = new Passwords($this->config['passwords'] ?? []);

        // Build a temp user for personal info checking
        $tempUser = new User();
        $tempUser->username = $username ?: null;

        $passResult = $passwords->check($password, $tempUser);
        if (! $passResult->isOK()) {
            $errors[] = $passResult->reason();
        }

        if (! empty($errors)) {
            $this->app->render('register', [
                'errors' => $errors,
                'config' => $this->config,
                'old'    => ['email' => $email, 'username' => $username],
            ]);
            return;
        }

        $orm = $this->app->orm();

        // Check if email already exists
        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $orm->getRepository(UserIdentity::class);
        $existing = $identityRepo->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

        if ($existing !== null) {
            $this->app->render('register', [
                'errors' => ['An account with that email already exists.'],
                'config' => $this->config,
                'old'    => ['email' => $email, 'username' => $username],
            ]);
            return;
        }

        // Create user
        $user = new User();
        $user->username   = $username ?: null;
        $user->active     = true;
        $user->created_at = new \DateTimeImmutable();
        $user->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($user)->run();

        // Create email identity
        $identityRepo->createEmailIdentity($user, [
            'email'         => $email,
            'password_hash' => $passwords->hash($password),
        ], $orm);

        // Add to default group
        $defaultGroup = $this->config['default_group'] ?? 'user';
        $user->addGroup($defaultGroup, $orm);

        // Check for registration action (email activation)
        $actionClass = $this->config['actions']['register'] ?? null;
        if ($actionClass !== null) {
            /** @var \Enlivenapp\FlightShield\Authentication\Authenticators\Session $authenticator */
            $authenticator = $this->app->auth()->setAuthenticator('session')->getAuthenticator();
            $authenticator->startAction($actionClass, $user);
            if (is_a($actionClass, \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator::class, true)) {
                $this->app->redirect('/auth/activate');
            } elseif (is_a($actionClass, \Enlivenapp\FlightShield\Authentication\Actions\Email2FA::class, true)) {
                $this->app->redirect('/auth/2fa');
            } else {
                $this->app->redirect('/');
            }
            return;
        }

        // Log them in
        $this->app->auth()->login($user);

        $redirect = $this->config['redirects']['after_register'] ?? '/';
        $this->app->redirect($redirect);
    }
}
