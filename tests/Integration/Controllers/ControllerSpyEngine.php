<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Controllers;

use Enlivenapp\FlightShield\Auth;
use flight\Engine;

/**
 * Spy engine for the auth controllers: captures render() and redirect()
 * instead of emitting output, and hands in a request stub.
 */
class ControllerSpyEngine extends Engine
{
    public ?Auth $authStub = null;
    public mixed $requestStub = null;

    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $rendered = [];

    /** @var string[] */
    public array $redirects = [];

    public bool $haltCalled = false;

    public ?int $haltCode = null;

    private array $store = [];

    public function auth(): Auth
    {
        return $this->authStub;
    }

    public function request(): mixed
    {
        return $this->requestStub;
    }

    public function db(): mixed
    {
        return \Flight::db();
    }

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }

    public function render(string $file, ?array $data = null, ?string $key = null): void
    {
        $this->rendered[] = ['template' => $file, 'data' => $data ?? []];
    }

    public function redirect(string $url, int $code = 303): void
    {
        $this->redirects[] = $url;
    }

    public function halt(int $code = 200, string $message = '', bool $actuallyExit = true): void
    {
        $this->haltCalled = true;
        $this->haltCode = $code;
    }

    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $viewFetched = [];

    public function view(): object
    {
        return new class(fn (string $template, array $data) => $this->viewFetched[] = ['template' => $template, 'data' => $data]) {
            /** @var callable */
            private $record;

            public function __construct(callable $record)
            {
                $this->record = $record;
            }

            public function fetch(string $template, array $data = []): string
            {
                ($this->record)($template, $data);

                return '';
            }
        };
    }
}
