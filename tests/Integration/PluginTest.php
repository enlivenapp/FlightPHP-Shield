<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Exceptions\SecurityException;
use Enlivenapp\FlightShield\Plugin;
use Enlivenapp\FlightShield\Tests\Integration\Controllers\ControllerSpyEngine;
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\net\Router;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Plugin bootstrap and the HTTPS policy it enforces.
 */
#[CoversClass(Plugin::class)]
class PluginTest extends TestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    /**
     * @return array<string, mixed>
     */
    private function config(): array
    {
        return TestHelper::getConfig();
    }

    #[Test]
    public function registerBindsTheAuthService(): void
    {
        // A plain Engine: the spy engines define auth() as a real method,
        // which would clash with register('auth', ...).
        $app = new \flight\Engine();
        $app->set('flight.force_https', false);

        (new Plugin())->register($app, new Router(), $this->config());

        $this->assertTrue(method_exists(Auth::class, 'verifyCredentials'));
    }

    #[Test]
    public function enforceHttpsRequiresAnExplicitSetting(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();
        // flight.force_https is not set -> null

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('flight.force_https');

        $method->invoke($plugin, $app, $this->config());
    }

    #[Test]
    public function enforceHttpsAllowsPlainHttpWhenExplicitlyDisabled(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();
        $app->set('flight.force_https', false);

        $method->invoke($plugin, $app, $this->config());

        $this->assertTrue(true);
    }

    #[Test]
    public function enforceHttpsRejectsAnInsecureRequest(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();
        $app->set('flight.force_https', true);
        $app->requestStub = (object) ['secure' => false];

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('HTTPS is required');

        $method->invoke($plugin, $app, $this->config());
    }

    #[Test]
    public function enforceHttpsAcceptsASecureRequest(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();
        $app->set('flight.force_https', true);
        $app->requestStub = (object) ['secure' => true];

        $method->invoke($plugin, $app, $this->config());

        $this->assertTrue(true);
    }

    // -----------------------------------------------------------------
    // ensureAppConfig()
    // -----------------------------------------------------------------

    /**
     * Write a config scaffold and define PROJECT_ROOT for the isolated run.
     */
    private function scaffoldConfig(string $body): string
    {
        $dir = sys_get_temp_dir() . '/shield-app-' . uniqid();
        mkdir($dir . '/app/config', 0777, true);
        file_put_contents($dir . '/app/config/config.php', $body);

        if (! defined('PROJECT_ROOT')) {
            define('PROJECT_ROOT', $dir);
        }

        return $dir;
    }

    private function removeScaffold(string $dir): void
    {
        @unlink($dir . '/app/config/config.php');
        @rmdir($dir . '/app/config');
        @rmdir($dir . '/app');
        @rmdir($dir);
    }

    private function runEnsureAppConfig(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'ensureAppConfig');
        $method->setAccessible(true);
        $method->invoke($plugin);
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function ensureAppConfigAddsTheMissingBlocks(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = (string) file_get_contents($dir . '/app/config/config.php');
        $this->assertStringContainsString("'hmac'", $contents);
        $this->assertStringContainsString("'jwt'", $contents);
        $this->assertStringContainsString("'routePrepend' => 'auth'", $contents);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function ensureAppConfigLeavesAConfigThatAlreadyHasTheBlocksAlone(): void
    {
        $body = "<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'hmac' => [],\n\t\t'jwt' => [],\n\t],\n];\n";
        $dir = $this->scaffoldConfig($body);

        $this->runEnsureAppConfig();

        $this->assertSame($body, file_get_contents($dir . '/app/config/config.php'));

        $this->removeScaffold($dir);
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function ensureAppConfigDoesNothingWithoutAShieldEntry(): void
    {
        $body = "<?php\nreturn [\n\t'other' => [],\n];\n";
        $dir = $this->scaffoldConfig($body);

        $this->runEnsureAppConfig();

        $this->assertSame($body, file_get_contents($dir . '/app/config/config.php'));

        $this->removeScaffold($dir);
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function ensureAppConfigDoesNothingWhenTheFileIsMissing(): void
    {
        define('PROJECT_ROOT', sys_get_temp_dir() . '/shield-missing-' . uniqid());

        // No exception, no file written.
        $this->runEnsureAppConfig();

        $this->assertTrue(true);
    }
}
