<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Controllers;

use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Services\CredentialVerifier;
use Enlivenapp\FlightShield\Services\ResendCooldown;
use flight\Engine;

/**
 * The activation page.
 *
 * Landing point for a login that found an unactivated account, and for an
 * expired or used activation link. Shows a message and a resend form.
 *
 * The button is the only thing that sends mail, and a server-side cooldown
 * holds it back so a reload cannot spam the inbox.
 */
class ActivationController
{
    protected Engine $app;
    /** @var array<string, mixed> */
    protected array $config;
    protected CredentialVerifier $credentialVerifier;
    protected ResendCooldown $cooldown;

    public function __construct(Engine $app, string $configPrepend)
    {
        $this->app = $app;
        /** @var array<string, mixed> $config */
        $config = $app->get($configPrepend) ?? [];
        $this->config = $config;
        $this->credentialVerifier = new CredentialVerifier($app, $this->config);
        $this->cooldown = new ResendCooldown($this->config);
    }

    public function show(): void
    {
        $this->render([
            'message' => 'Your account is not activated yet. Request a new activation link below.',
            'old'     => ['email' => trim((string) ($this->app->request()->query->email ?? ''))],
        ]);
    }

    public function resend(): void
    {
        $email = trim((string) ($this->app->request()->data->email ?? ''));

        // Count every submit for the per-IP throttle, before any early
        // return, so a flood of bad addresses is limited too.
        $this->credentialVerifier->recordThrottleHit(
            $email !== '' ? $email : 'unknown',
            Login::ID_TYPE_ACTIVATION_RESEND
        );

        if ($email === '') {
            $this->render([
                'error' => 'Enter your email address.',
                'old'   => ['email' => $email],
            ]);
            return;
        }

        $user = (new User($this->app->db()))->findByCredentials(['email' => $email]);

        // Only a real, unactivated, unbanned account gets mail. Every other
        // input gets the same message, so the form cannot be used to probe
        // for accounts.
        if ($user === null || $user->isActivated() || $user->isBanned()) {
            $this->render([
                'message' => $this->sentMessage(),
                'old'     => ['email' => $email],
            ]);
            return;
        }

        $remaining = $this->cooldown->remaining($user, UserIdentity::TYPE_EMAIL_ACTIVATE);

        if ($remaining > 0) {
            $this->render([
                'error'    => 'Please wait ' . $this->cooldown->format($remaining) . ' before requesting another link.',
                'old'      => ['email' => $email],
                'cooldown' => $remaining,
            ]);
            return;
        }

        if (! $this->credentialVerifier->sendActivation($user)) {
            $this->render([
                'error' => 'We could not send the activation email. Please try again.',
                'old'   => ['email' => $email],
            ]);
            return;
        }

        $this->render([
            'message'  => $this->sentMessage(),
            'old'      => ['email' => $email],
            'cooldown' => $this->cooldown->seconds(),
        ]);
    }

    protected function sentMessage(): string
    {
        return 'If that address still needs activation, a new link is on its way.';
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function render(array $data = []): void
    {
        $this->app->render('activate', array_merge([
            'config'   => $this->config,
            'old'      => ['email' => ''],
            'cooldown' => 0,
        ], $data));
    }
}
