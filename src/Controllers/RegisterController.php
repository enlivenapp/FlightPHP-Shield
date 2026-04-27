<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Validation\ValidationRules;
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

        // Validate input fields
        $validator = new ValidationRules($this->config['passwords'] ?? []);
        $errors = $validator->validate(
            ['username' => $username, 'email' => $email, 'password' => $password, 'password_confirm' => $passConf],
            $validator->getRegistrationRules()
        );

        // Run password through strength validators
        $passwords = new Passwords($this->config['passwords'] ?? []);
        $tempUser = new User();
        $tempUser->username = $username ?: null;

        $passResult = $passwords->check($password, $tempUser);
        if (! $passResult->isOK()) {
            $errors['password_strength'] = $passResult->reason();
        }

        if (! empty($errors)) {
            $this->app->render('register', [
                'errors' => array_values($errors),
                'config' => $this->config,
                'old'    => ['email' => $email, 'username' => $username],
            ]);
            return;
        }

        // Check if email already exists — show same success page either way
        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());
        $existing = $identityModel->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

        if ($existing !== null) {
            // Send notice to the existing email address
            $sender = $this->config['email_sender'] ?? null;
            if ($sender !== null && is_callable($sender)) {
                $body = $this->app->view()->fetch('Email/email_register_existing', [
                    'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                    'date'      => date('Y-m-d H:i:s'),
                ]);
                $sender($email, 'Registration Attempt', $body);
            }

            $this->app->render('register_success', ['config' => $this->config]);
            return;
        }

        // Create user — inactive when email activation is required
        $actionClass = $this->config['actions']['register'] ?? null;
        $requiresActivation = is_a($actionClass, \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator::class, true);

        $user = new User(\Flight::db());
        $user->username   = $username ?: null;
        $user->active     = !$requiresActivation;
        $user->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $user->insert();

        // Create email identity
        $identityModel->createEmailIdentity($user, [
            'email'         => $email,
            'password_hash' => $passwords->hash($password),
        ]);

        // Add to default group
        $defaultGroup = $this->config['default_group'] ?? 'user';
        $user->addGroup($defaultGroup);

        // Check for registration action (email activation)
        if ($actionClass !== null) {
            /** @var \Enlivenapp\FlightShield\Authentication\Authenticators\Session $authenticator */
            $authenticator = $this->app->auth()->setAuthenticator('session')->getAuthenticator();
            $authenticator->startAction($actionClass, $user);
        } else {
            // Log them in
            $this->app->auth()->login($user);
        }

        // Always show the same success page
        $this->app->render('register_success', ['config' => $this->config]);
    }
}
