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
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The exact text Plugin::ensureAppConfig() writes, and the Auth service
 * registration it performs.
 */
#[CoversClass(Plugin::class)]
class PluginConfigDetailTest extends TestCase
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

    private function scaffoldConfig(string $body): string
    {
        $dir = sys_get_temp_dir() . '/shield-detail-' . uniqid();
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

    private function readConfig(string $dir): string
    {
        return (string) file_get_contents($dir . '/app/config/config.php');
    }

    // -----------------------------------------------------------------
    // register()
    // -----------------------------------------------------------------

    #[Test]
    public function registerBindsAuthWithTheAppAndConfig(): void
    {
        $app = new \flight\Engine();
        $app->set('flight.force_https', false);

        $config = TestHelper::getConfig();
        (new Plugin())->register($app, new Router(), $config);

        $auth = $app->auth();

        $this->assertInstanceOf(Auth::class, $auth);
    }

    #[Test]
    public function registerLoadsTheAuthHelper(): void
    {
        $app = new \flight\Engine();
        $app->set('flight.force_https', false);

        (new Plugin())->register($app, new Router(), TestHelper::getConfig());

        $this->assertTrue(function_exists('auth'));
    }

    #[Test]
    public function registerSkipsTheHttpsCheckUnderCli(): void
    {
        $app = new \flight\Engine();
        // flight.force_https deliberately left unset: under CLI the check
        // must not run, so no SecurityException is thrown.
        (new Plugin())->register($app, new Router(), TestHelper::getConfig());

        $this->assertInstanceOf(Auth::class, $app->auth());
    }

    // -----------------------------------------------------------------
    // enforceHttps() messages
    // -----------------------------------------------------------------

    #[Test]
    public function theMissingSettingMessageNamesTheSetting(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();

        try {
            $method->invoke($plugin, $app, TestHelper::getConfig());
            $this->fail('Expected a SecurityException.');
        } catch (SecurityException $e) {
            $this->assertStringContainsString('flight.force_https', $e->getMessage());
            $this->assertStringContainsString('Set to true for production or false for development.', $e->getMessage());
        }
    }

    #[Test]
    public function theInsecureRequestMessageExplainsTheEscapeHatch(): void
    {
        $plugin = new Plugin();
        $method = new \ReflectionMethod($plugin, 'enforceHttps');
        $method->setAccessible(true);

        $app = new ControllerSpyEngine();
        $app->set('flight.force_https', true);
        $app->requestStub = (object) ['secure' => false];

        try {
            $method->invoke($plugin, $app, TestHelper::getConfig());
            $this->fail('Expected a SecurityException.');
        } catch (SecurityException $e) {
            $this->assertStringContainsString('HTTPS is required.', $e->getMessage());
            $this->assertStringContainsString('Set "flight.force_https" to false', $e->getMessage());
        }
    }

    // -----------------------------------------------------------------
    // ensureAppConfig() output
    // -----------------------------------------------------------------

    #[Test]
    #[RunInSeparateProcess]
    public function theHmacBlockIsWrittenInFull(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringContainsString("'hmac' => [", $contents);
        $this->assertStringContainsString("'encryption_keys' => [],", $contents);
        $this->assertStringContainsString("'encryption_current_key' => '',", $contents);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function theJwtBlockIsWrittenInFull(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringContainsString("'jwt' => [", $contents);
        $this->assertStringContainsString("'keys' => [", $contents);
        $this->assertStringContainsString("'default' => [", $contents);
        $this->assertStringContainsString("'kid'    => '',", $contents);
        $this->assertStringContainsString("'alg'    => 'HS256',", $contents);
        $this->assertStringContainsString("'secret' => '',", $contents);
        $this->assertStringContainsString("'default_claims' => [", $contents);
        $this->assertStringContainsString("'iss' => '',", $contents);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function theInsertedBlocksKeepTheOriginalEntryIntact(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringContainsString("'routePrepend' => 'auth',", $contents);
        $this->assertStringContainsString("'enlivenapp/flight-shield' => [", $contents);

        // The result must still be valid PHP that returns an array.
        $result = eval('?>' . $contents);
        $this->assertIsArray($result);
        $this->assertArrayHasKey('enlivenapp/flight-shield', $result);
        $this->assertArrayHasKey('hmac', $result['enlivenapp/flight-shield']);
        $this->assertArrayHasKey('jwt', $result['enlivenapp/flight-shield']);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function aMissingTrailingCommaIsAdded(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth'\n\t]\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $result = eval('?>' . $contents);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('hmac', $result['enlivenapp/flight-shield']);
        $this->assertArrayHasKey('jwt', $result['enlivenapp/flight-shield']);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function anExistingTrailingCommaIsNotDoubled(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringNotContainsString(',,', $contents);

        $result = eval('?>' . $contents);
        $this->assertIsArray($result);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function onlyTheMissingBlockIsAdded(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'hmac' => [],\n\t\t'routePrepend' => 'auth',\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringContainsString("'jwt' => [", $contents);
        $this->assertSame(1, substr_count($contents, "'hmac' => ["));

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function aNestedArrayInTheEntryIsHandled(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'nested' => [\n\t\t\t'deep' => [\n\t\t\t\t'value' => 1,\n\t\t\t],\n\t\t],\n\t],\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $result = eval('?>' . $contents);

        $this->assertIsArray($result);
        $this->assertSame(1, $result['enlivenapp/flight-shield']['nested']['deep']['value']);
        $this->assertArrayHasKey('hmac', $result['enlivenapp/flight-shield']);
        $this->assertArrayHasKey('jwt', $result['enlivenapp/flight-shield']);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function anUnclosedEntryStillGetsTheBlocks(): void
    {
        $dir = $this->scaffoldConfig("<?php\nreturn [\n\t'enlivenapp/flight-shield' => [\n\t\t'routePrepend' => 'auth',\n];\n");

        $this->runEnsureAppConfig();

        $contents = $this->readConfig($dir);
        $this->assertStringContainsString("'hmac' => [", $contents);
        $this->assertStringContainsString("'jwt' => [", $contents);

        $this->removeScaffold($dir);
    }

    #[Test]
    #[RunInSeparateProcess]
    public function anEntryWithNoOpeningBracketIsLeftAlone(): void
    {
        $body = "<?php\nreturn [\n\t'enlivenapp/flight-shield' => 'auth',\n];\n";
        $dir = $this->scaffoldConfig($body);

        $this->runEnsureAppConfig();

        $this->assertSame($body, $this->readConfig($dir));

        $this->removeScaffold($dir);
    }
}
