<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use flight\Engine;

/**
 * Checks that the logged-in user has one of the required permissions.
 *
 * Usage in routes:
 *   $router->group('/users', function() { ... }, [new PermissionMiddleware($app, 'users.list')]);
 */
class PermissionMiddleware
{
    protected Engine $app;
    protected array $permissions;

    public function __construct(Engine $app, string ...$permissions)
    {
        $this->app = $app;
        $this->permissions = $permissions;
    }

    public function before(): void
    {
        $auth = $this->app->auth();

        if (! $auth->loggedIn()) {
            $config = $this->app->get('enlivenapp.flight-shield') ?? [];
            $this->app->redirect($config['redirects']['login'] ?? '/auth/login');
            $this->app->halt(303);
        }

        $user = $auth->user();
        $config = $this->app->get('enlivenapp.flight-shield') ?? [];

        foreach ($this->permissions as $permission) {
            if ($user->can($permission)) {
                return;
            }
        }

        $this->app->redirect($config['redirects']['permission_denied'] ?? '/auth/login');
        $this->app->halt(303);
    }
}
