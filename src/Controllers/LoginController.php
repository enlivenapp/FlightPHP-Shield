<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use flight\Engine;

class LoginController
{
    protected Engine $app;
    protected array $config;

    public function __construct(Engine $app, string $configPrepend)
    {
        $this->app = $app;
        $this->config = $app->get($configPrepend) ?? [];
    }

    public function showLogin(): void
    {
        if ($this->app->auth()->loggedIn()) {
            $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
            return;
        }

        $this->app->render('login', [
            'config' => $this->config,
        ]);
    }

    public function processLogin(): void
    {
        $request = $this->app->request();
        $data = $request->data;

        $credentials = [
            'email'    => $data->email ?? '',
            'password' => $data->password ?? '',
        ];

        // Support username login if configured
        $validFields = $this->config['valid_login_fields'] ?? ['email'];
        if (in_array('username', $validFields) && ! empty($data->username)) {
            $credentials['username'] = $data->username;
            unset($credentials['email']);
        }

        $auth = $this->app->auth();
        $result = $auth->attempt($credentials);

        if (! $result->isOK()) {
            $this->app->render('login', [
                'error'  => $result->reason(),
                'config' => $this->config,
            ]);
            return;
        }

        // Check if we're in a pending state (2FA, activation)
        $authenticator = $auth->getAuthenticator();
        if (method_exists($authenticator, 'isPending') && $authenticator->isPending()) {
            $action = $authenticator->getAction();
            if ($action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
                $this->app->redirect('/auth/2fa');
            } elseif ($action instanceof \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator) {
                $this->app->redirect('/auth/activate');
            } else {
                $this->app->redirect('/');
            }
            return;
        }

        // Handle remember me
        if (! empty($data->remember)) {
            if (method_exists($authenticator, 'remember')) {
                $authenticator->remember();
            }
        }

        $redirect = $this->config['redirects']['after_login'] ?? '/';
        $this->app->redirect($redirect);
    }

    public function logout(): void
    {
        $this->app->auth()->logout();

        $redirect = $this->config['redirects']['after_logout'] ?? '/';
        $this->app->redirect($redirect);
    }
}
