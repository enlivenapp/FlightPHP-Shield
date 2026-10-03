<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

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

        $data = $this->app->request()->data;

        $fields = [
            'email'            => trim($data->email ?? ''),
            'password'         => $data->password ?? '',
            'password_confirm' => $data->password_confirm ?? '',
        ];

        // Account creation, validation, and the activation email all live
        // behind this one call. No session is touched.
        $result = $this->app->auth()->register($fields);

        if (! $result->isOK()) {
            $errors = $result->extraInfo();

            if (! is_array($errors) || $errors === []) {
                $errors = [$result->reason() ?? 'Registration failed.'];
            }

            $this->app->render('register', [
                'errors' => array_values($errors),
                'config' => $this->config,
                'old'    => ['email' => $fields['email']],
            ]);
            return;
        }

        $this->app->render('register_success', ['config' => $this->config]);
    }
}
