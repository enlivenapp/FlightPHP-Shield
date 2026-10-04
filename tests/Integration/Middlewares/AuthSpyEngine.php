<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use flight\Engine;

/**
 * Spy engine for the auth middlewares.
 *
 * Captures redirect(), halt() and json()/jsonHalt() calls instead of sending
 * output or exiting, and hands the middleware a real Auth facade.
 */
class AuthSpyEngine extends Engine
{
    public ?Auth $authStub = null;

    /** @var string[] */
    public array $redirects = [];

    public bool $haltCalled = false;
    public int $haltCode = 0;

    /** @var array<int, array{data: mixed, code: int}> */
    public array $jsonCalls = [];

    private array $store = [];

    public function auth(): Auth
    {
        return $this->authStub;
    }

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }

    public function redirect(string $url, int $code = 303): void
    {
        $this->redirects[] = $url;
    }

    public function halt(int $code = 200, string $message = '', bool $actuallyExit = true): void
    {
        $this->haltCalled = true;
        $this->haltCode   = $code;
    }

    public function json($data, int $code = 200, bool $encode = true, string $charset = 'utf-8', int $option = 0): void
    {
        $this->jsonCalls[] = ['data' => $data, 'code' => $code];
    }

    public function jsonHalt($data, int $code = 200, bool $encode = true, string $charset = 'utf-8', int $option = 0): void
    {
        $this->jsonCalls[] = ['data' => $data, 'code' => $code];
    }
}
