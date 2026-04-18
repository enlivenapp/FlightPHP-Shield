<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield;

use Enlivenapp\FlightSchool\PluginInterface;
use flight\Engine;
use flight\net\Router;

class Plugin implements PluginInterface
{
    public function register(Engine $app, Router $router, array $config = []): void
    {
        // Ensure app config has required shield entries
        $this->ensureAppConfig();

        // Register the Auth facade as a Flight service
        $app->register('auth', Auth::class, [$app, $config]);

        // Register entity directory for schema discovery
        $database = $app->get('database');
        if ($database) {
            $database->addEntityDirectory(__DIR__ . '/Entities');
        }

        // Load helper functions
        require_once __DIR__ . '/Helpers/auth_helper.php';
    }

    /**
     * Ensure required config entries exist in app/config/config.php.
     * Adds missing entries with safe defaults on first run.
     */
    protected function ensureAppConfig(): void
    {
        $configFile = defined('PROJECT_ROOT')
            ? PROJECT_ROOT . '/app/config/config.php'
            : null;

        if ($configFile === null || !file_exists($configFile)) {
            return;
        }

        $contents = file_get_contents($configFile);
        if ($contents === false) {
            return;
        }

        $blocks = [];

        if (!str_contains($contents, "'hmac'")) {
            $blocks[] = "\t\t\t'hmac' => [\n"
                . "\t\t\t\t'encryption_keys' => [],\n"
                . "\t\t\t\t'encryption_current_key' => '',\n"
                . "\t\t\t],";
        }

        if (!str_contains($contents, "'jwt'")) {
            $blocks[] = "\t\t\t'jwt' => [\n"
                . "\t\t\t\t'keys' => [\n"
                . "\t\t\t\t\t'default' => [\n"
                . "\t\t\t\t\t\t[\n"
                . "\t\t\t\t\t\t\t'kid'    => '',\n"
                . "\t\t\t\t\t\t\t'alg'    => 'HS256',\n"
                . "\t\t\t\t\t\t\t'secret' => '',\n"
                . "\t\t\t\t\t\t],\n"
                . "\t\t\t\t\t],\n"
                . "\t\t\t\t],\n"
                . "\t\t\t\t'default_claims' => [\n"
                . "\t\t\t\t\t'iss' => '',\n"
                . "\t\t\t\t],\n"
                . "\t\t\t],";
        }

        if (empty($blocks)) {
            return;
        }

        // Find the shield plugin entry's closing bracket
        $shieldPos = strpos($contents, "'enlivenapp/flight-shield'");
        if ($shieldPos === false) {
            return;
        }

        $depth = 0;
        $openPos = strpos($contents, '[', $shieldPos);
        if ($openPos === false) {
            return;
        }

        $insertPos = false;
        for ($i = $openPos; $i < strlen($contents); $i++) {
            if ($contents[$i] === '[') {
                $depth++;
            } elseif ($contents[$i] === ']') {
                $depth--;
                if ($depth === 0) {
                    $insertPos = $i;
                    break;
                }
            }
        }

        if ($insertPos === false) {
            return;
        }

        $before = substr($contents, 0, $insertPos);
        $trimmed = rtrim($before);
        if (!str_ends_with($trimmed, ',')) {
            $trimmed .= ',';
        }

        $contents = $trimmed . "\n" . implode("\n", $blocks) . "\n\t\t" . substr($contents, $insertPos);

        file_put_contents($configFile, $contents);
    }
}
