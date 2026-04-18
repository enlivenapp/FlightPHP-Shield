<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

/**
 * Flight Shield routes.
 *
 * Auto-prefixed by Flight School. Default prefix: /auth
 *
 * Routes:
 *   GET  /auth/login              - Show login form
 *   POST /auth/login              - Process login
 *   GET  /auth/logout             - Logout
 *   GET  /auth/register           - Show registration form
 *   POST /auth/register           - Process registration
 *   GET  /auth/magic-link         - Show magic link form
 *   POST /auth/magic-link         - Send magic link
 *   GET  /auth/magic-link/verify  - Verify magic link token
 *   GET  /auth/2fa                - Show 2FA verify page (sends code)
 *   POST /auth/2fa/verify         - Verify 2FA code
 *   POST /auth/2fa/resend         - Resend 2FA code
 *   GET  /auth/activate           - Show activation page (sends email)
 *   GET  /auth/activate/verify    - Verify activation token
 */

use Enlivenapp\FlightCsrf\Middlewares\CsrfMiddleware;
use Enlivenapp\FlightShield\Controllers\LoginController;
use Enlivenapp\FlightShield\Controllers\MagicLinkController;
use Enlivenapp\FlightShield\Controllers\RegisterController;
use Enlivenapp\FlightShield\Middlewares\RateLimitMiddleware;

/** @var \flight\net\Router $router */
/** @var \flight\Engine $app */
/** @var string $configPrepend */

// Login
$router->get('/login', function () use ($app, $configPrepend) {
    (new LoginController($app, $configPrepend))->showLogin();
});

$router->post('/login', function () use ($app, $configPrepend) {
    (new LoginController($app, $configPrepend))->processLogin();
})->addMiddleware(new CsrfMiddleware($app))->addMiddleware(new RateLimitMiddleware($app));

$router->get('/logout', function () use ($app, $configPrepend) {
    (new LoginController($app, $configPrepend))->logout();
});

// Registration
$router->get('/register', function () use ($app, $configPrepend) {
    (new RegisterController($app, $configPrepend))->showRegister();
});

$router->post('/register', function () use ($app, $configPrepend) {
    (new RegisterController($app, $configPrepend))->processRegister();
})->addMiddleware(new CsrfMiddleware($app));

// Magic Link
$router->get('/magic-link', function () use ($app, $configPrepend) {
    (new MagicLinkController($app, $configPrepend))->showLoginForm();
});

$router->post('/magic-link', function () use ($app, $configPrepend) {
    (new MagicLinkController($app, $configPrepend))->sendMagicLink();
})->addMiddleware(new CsrfMiddleware($app))->addMiddleware(new RateLimitMiddleware($app));

$router->get('/magic-link/verify', function () use ($app, $configPrepend) {
    (new MagicLinkController($app, $configPrepend))->verify();
});

// 2FA
$router->get('/2fa', function () use ($app) {
    $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();
    $action = $authenticator->getAction();
    if ($action === null || !$action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
        $app->redirect('/');
        return;
    }
    echo $action->show($app);
});

$router->post('/2fa/verify', function () use ($app) {
    $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();
    $action = $authenticator->getAction();
    if ($action === null || !$action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
        $app->redirect('/');
        return;
    }
    echo $action->verify($app);
})->addMiddleware(new CsrfMiddleware($app))->addMiddleware(new RateLimitMiddleware($app));

$router->post('/2fa/resend', function () use ($app) {
    $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();
    $action = $authenticator->getAction();
    if ($action === null || !$action instanceof \Enlivenapp\FlightShield\Authentication\Actions\Email2FA) {
        $app->redirect('/');
        return;
    }
    echo $action->handle($app);
})->addMiddleware(new CsrfMiddleware($app))->addMiddleware(new RateLimitMiddleware($app));

// Email Activation
$router->get('/activate', function () use ($app) {
    $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();
    $action = $authenticator->getAction();
    if ($action === null || !$action instanceof \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator) {
        $app->redirect('/');
        return;
    }
    echo $action->show($app);
});

$router->get('/activate/verify', function () use ($app) {
    $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();
    $action = $authenticator->getAction();
    if ($action === null || !$action instanceof \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator) {
        $app->redirect('/');
        return;
    }
    echo $action->verify($app);
});
