<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Passwords\CompositionValidator;
use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompositionValidator::class)]
class CompositionValidatorTest extends TestCase
{
    private function makeValidator(array $config = []): CompositionValidator
    {
        return new CompositionValidator(array_merge(['min_length' => 8], $config));
    }

    #[Test]
    public function passwordUnderMinLengthFails(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('short');

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('at least 8 characters', (string) $result->reason());
    }

    #[Test]
    public function passwordAtMinLengthPasses(): void
    {
        $validator = $this->makeValidator();
        // Exactly 8 characters
        $result = $validator->check('exactly8');

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function passwordOver128CharsFails(): void
    {
        $validator = $this->makeValidator();
        $longPassword = str_repeat('a', 129);
        $result = $validator->check($longPassword);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password must not exceed 128 characters.', $result->reason());
    }

    #[Test]
    public function passwordAt128CharsPasses(): void
    {
        $validator = $this->makeValidator();
        $maxPassword = str_repeat('a', 128);
        $result = $validator->check($maxPassword);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function customMinLengthIsRespected(): void
    {
        $validator = $this->makeValidator(['min_length' => 12]);

        $tooShort = $validator->check('onlyeleven!');
        $this->assertFalse($tooShort->isOK());
        $this->assertStringContainsString('at least 12 characters', (string) $tooShort->reason());

        $longEnough = $validator->check('twelvechars!');
        $this->assertTrue($longEnough->isOK());
    }

    #[Test]
    public function shortPasswordErrorIncludesExtraInfo(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('tiny');

        $this->assertNotNull($result->extraInfo());
        $this->assertStringContainsString('Longer passwords', (string) $result->extraInfo());
    }

    #[Test]
    public function passwordBetweenMinAndMaxPasses(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('a-perfectly-fine-password');

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function nullUserDoesNotCauseError(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('validpassword', null);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function minLengthDefaultsTo8WhenNotInConfig(): void
    {
        // Config without min_length uses the ?? 8 fallback inside the validator
        $validator = new CompositionValidator([]);

        $result = $validator->check('short');
        $this->assertFalse($result->isOK());

        $result = $validator->check('exactly8');
        $this->assertTrue($result->isOK());
    }
}
