<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use flight\Engine;

class LoginController
{
    protected Engine $app;
    /** @var array<string, mixed> */
    protected array $config;

    public function __construct(Engine $app, string $configPrepend)
    {
        $this->app = $app;
        /** @var array<string, mixed> $config */
        $config = $app->get($configPrepend) ?? [];
        $this->config = $config;
    }

    public function showLogin(): void
    {
        if ($this->app->auth()->loggedIn()) {
            $user = $this->app->auth()->user();
            $adminRedirect = $this->config['redirects']['after_login_admin'] ?? null;

            if ($adminRedirect !== null && $user !== null && $user->can('admin.access')) {
                $this->app->redirect($adminRedirect);
            } else {
                $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
            }
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
            // Correct password, but the account is not activated. Send them
            // to the activation page instead of a dead-end error.
            if ($result->extraInfo() === Session::ACCOUNT_NOT_ACTIVATED) {
                $this->app->redirect($this->config['redirects']['activate'] ?? '/auth/activate');
                return;
            }

            $this->app->render('login', [
                'error'  => $result->reason(),
                'config' => $this->config,
            ]);
            return;
        }

        // Check if we're in a pending state (2FA)
        $authenticator = $auth->getAuthenticator();
        if ($authenticator instanceof Session && $authenticator->isPending()) {
            $action = $authenticator->getAction();
            if ($action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
                $this->app->redirect('/auth/2fa');
            } else {
                $this->app->redirect('/');
            }
            return;
        }

        // Handle remember me
        if (! empty($data->remember)) {
            if ($authenticator instanceof Session) {
                $authenticator->remember();
            }
        }

        $user = $auth->user();
        $adminRedirect = $this->config['redirects']['after_login_admin'] ?? null;

        if ($adminRedirect !== null && $user !== null && $user->can('admin.access')) {
            $this->app->redirect($adminRedirect);
        } else {
            $this->app->redirect($this->config['redirects']['after_login'] ?? '/');
        }
    }

    public function logout(): void
    {
        $this->app->auth()->logout();

        $redirect = $this->config['redirects']['after_logout'] ?? '/';
        $this->app->redirect($redirect);
    }
}
