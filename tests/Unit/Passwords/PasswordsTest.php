<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Passwords\CompositionValidator;
use Enlivenapp\FlightShield\Passwords\DictionaryValidator;
use Enlivenapp\FlightShield\Passwords\NothingPersonalValidator;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Passwords::class)]
class PasswordsTest extends TestCase
{
    private Passwords $passwords;

    protected function setUp(): void
    {
        // cost=4 for speed in tests
        $this->passwords = new Passwords(['cost' => 4]);
    }

    #[Test]
    public function hashReturnsNonEmptyString(): void
    {
        $hash = $this->passwords->hash('correct-horse-battery-staple');

        $this->assertIsString($hash);
        $this->assertNotEmpty($hash);
    }

    #[Test]
    public function verifyReturnsTrueWithCorrectPassword(): void
    {
        $password = 'correct-horse-battery-staple';
        $hash = $this->passwords->hash($password);

        $this->assertTrue($this->passwords->verify($password, (string) $hash));
    }

    #[Test]
    public function verifyReturnsFalseWithWrongPassword(): void
    {
        $hash = $this->passwords->hash('correct-horse-battery-staple');

        $this->assertFalse($this->passwords->verify('wrong-password', (string) $hash));
    }

    #[Test]
    public function needsRehashReturnsTrueWithDifferentCost(): void
    {
        $passwords = new Passwords(['cost' => 4]);
        $hash = $passwords->hash('my-secret-password');

        // Rehashing needed if cost changes
        $higherCost = new Passwords(['cost' => 5]);

        $this->assertTrue($higherCost->needsRehash((string) $hash));
    }

    #[Test]
    public function needsRehashReturnsFalseWithSameCost(): void
    {
        $passwords = new Passwords(['cost' => 4]);
        $hash = $passwords->hash('my-secret-password');

        $sameCost = new Passwords(['cost' => 4]);

        $this->assertFalse($sameCost->needsRehash((string) $hash));
    }

    #[Test]
    public function checkWithEmptyPasswordReturnsFailure(): void
    {
        $result = $this->passwords->check('');

        $this->assertFalse($result->isOK());
        $this->assertSame('Password cannot be empty.', $result->reason());
    }

    #[Test]
    public function checkWithValidPasswordAndNoUserReturnsSuccess(): void
    {
        // All 3 default validators: Composition, NothingPersonal, Dictionary
        // Use a password that passes all three
        $result = $this->passwords->check('Xk7!mQ2vP9nR4wLs');

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function checkWithShortPasswordFailsCompositionValidator(): void
    {
        $result = $this->passwords->check('short');

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('characters', (string) $result->reason());
    }

    #[Test]
    public function checkWithTooLongPasswordFails(): void
    {
        $longPassword = str_repeat('a', 129);
        $result = $this->passwords->check($longPassword);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password must not exceed 128 characters.', $result->reason());
    }

    #[Test]
    public function checkRunsAllThreeDefaultValidators(): void
    {
        // Verify that the default validators list contains all three classes
        $passwords = new Passwords(['cost' => 4]);

        // Access via reflection to check config
        $reflection = new \ReflectionClass($passwords);
        $configProp = $reflection->getProperty('config');
        $configProp->setAccessible(true);
        $config = $configProp->getValue($passwords);

        $this->assertContains(CompositionValidator::class, $config['validators']);
        $this->assertContains(NothingPersonalValidator::class, $config['validators']);
        $this->assertContains(DictionaryValidator::class, $config['validators']);
        $this->assertCount(3, $config['validators']);
    }

    #[Test]
    public function checkPassesUserToValidators(): void
    {
        $user = $this->createMock(\Enlivenapp\FlightShield\Models\User::class);
        $user->username = 'johnsmith';
        $user->method('isHydrated')->willReturn(false);

        // A password that doesn't relate to the username and passes composition/dictionary
        $result = $this->passwords->check('Xk7!mQ2vP9nR4wLs', $user);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function constructorDefaultsAreApplied(): void
    {
        $passwords = new Passwords();

        $reflection = new \ReflectionClass($passwords);
        $configProp = $reflection->getProperty('config');
        $configProp->setAccessible(true);
        $config = $configProp->getValue($passwords);

        $this->assertSame(PASSWORD_DEFAULT, $config['algorithm']);
        $this->assertSame(12, $config['cost']);
        $this->assertSame(8, $config['min_length']);
        $this->assertSame(50, $config['max_similarity']);
    }

    #[Test]
    public function constructorMergesCustomConfig(): void
    {
        $passwords = new Passwords(['cost' => 4, 'min_length' => 10]);

        $reflection = new \ReflectionClass($passwords);
        $configProp = $reflection->getProperty('config');
        $configProp->setAccessible(true);
        $config = $configProp->getValue($passwords);

        $this->assertSame(4, $config['cost']);
        $this->assertSame(10, $config['min_length']);
        // Default still applied for unoverridden keys
        $this->assertSame(PASSWORD_DEFAULT, $config['algorithm']);
    }

    #[Test]
    public function argon2idOptionsProduceAHash(): void
    {
        if (! defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('PASSWORD_ARGON2ID not available on this platform.');
        }

        $passwords = new Passwords([
            'algorithm'   => PASSWORD_ARGON2ID,
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 1,
        ]);

        $hash = $passwords->hash('my-secret-password-long');

        $this->assertIsString($hash);
        $this->assertNotEmpty($hash);
        $this->assertTrue($passwords->verify('my-secret-password-long', (string) $hash));
    }
}
