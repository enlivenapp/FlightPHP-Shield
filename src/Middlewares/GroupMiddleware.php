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
 * Checks that the logged-in user belongs to one of the required groups.
 *
 * Usage in routes:
 *   $router->group('/admin', function() { ... }, [new GroupMiddleware($app, 'admin', 'superadmin')]);
 */
class GroupMiddleware
{
    protected Engine $app;
    /** @var list<string> */
    protected array $groups;

    public function __construct(Engine $app, string ...$groups)
    {
        $this->app = $app;
        $this->groups = array_values($groups);
    }

    public function before(): void
    {
        $auth = $this->app->auth();

        if (! $auth->loggedIn()) {
            $config = $this->app->get('enlivenapp.flight-shield') ?? [];
            $this->app->redirect($config['redirects']['login'] ?? '/auth/login');
            $this->app->halt(303);
            return;
        }

        $user = $auth->user();
        $config = $this->app->get('enlivenapp.flight-shield') ?? [];

        if ($user === null) {
            $this->app->redirect($config['redirects']['login'] ?? '/auth/login');
            $this->app->halt(303);
            return;
        }

        if (! $user->inGroup(...$this->groups)) {
            $this->app->redirect($config['redirects']['group_denied'] ?? '/auth/login');
            $this->app->halt(303);
        }
    }
}
