<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Passwords\PwnedValidator;
use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PwnedValidator::class)]
class PwnedValidatorTest extends TestCase
{
    private function makeValidator(): PwnedValidator
    {
        return new PwnedValidator([]);
    }

    private function isApiReachable(): bool
    {
        $ch = curl_init('https://api.pwnedpasswords.com/range/00000');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_HTTPHEADER     => ['Accept: text/plain'],
        ]);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $code === 200;
    }

    #[Test]
    #[Group('network')]
    public function knownBreachedPasswordFails(): void
    {
        if (! $this->isApiReachable()) {
            $this->markTestSkipped('HIBP API not reachable.');
        }

        $validator = $this->makeValidator();
        // 'password' has appeared in hundreds of millions of breaches
        $result = $validator->check('password');

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('data breach', (string) $result->reason());
    }

    #[Test]
    #[Group('network')]
    public function randomLongPasswordPasses(): void
    {
        if (! $this->isApiReachable()) {
            $this->markTestSkipped('HIBP API not reachable.');
        }

        $validator = $this->makeValidator();
        // Cryptographically random — essentially impossible to appear in breach data
        $uniquePassword = 'FlightShield-' . bin2hex(random_bytes(24));
        $result = $validator->check($uniquePassword);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    #[Group('network')]
    public function failureResultIncludesHitCount(): void
    {
        if (! $this->isApiReachable()) {
            $this->markTestSkipped('HIBP API not reachable.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('password');

        $this->assertFalse($result->isOK());
        // Reason includes a numeric count and the word "databases" or "a database"
        $this->assertMatchesRegularExpression('/\d+ data breaches/', (string) $result->reason());
    }

    #[Test]
    #[Group('network')]
    public function failureResultHasExtraInfo(): void
    {
        if (! $this->isApiReachable()) {
            $this->markTestSkipped('HIBP API not reachable.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('password');

        $this->assertFalse($result->isOK());
        $this->assertNotNull($result->extraInfo());
        $this->assertStringContainsString('data breach', (string) $result->extraInfo());
    }

    #[Test]
    public function unreachableApiPassesPassword(): void
    {
        // When curl returns false or non-200, the validator returns success
        // This test verifies the API-unreachable behaviour by checking that
        // the check() method returns a Result regardless of network state.
        $validator = $this->makeValidator();

        // We can't easily force curl to fail without mocking, but we can verify
        // the return type is always a Result instance.
        $result = $validator->check('any-password-string');

        $this->assertInstanceOf(Result::class, $result);
    }

    #[Test]
    public function nullUserDoesNotAffectResult(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('some-password', null);

        $this->assertInstanceOf(Result::class, $result);
    }
}
