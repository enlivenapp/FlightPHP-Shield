<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Passwords\DictionaryValidator;
use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DictionaryValidator::class)]
class DictionaryValidatorTest extends TestCase
{
    private bool $dictionaryExists;

    protected function setUp(): void
    {
        $this->dictionaryExists = file_exists(
            __DIR__ . '/../../../src/Passwords/_dictionary.txt'
        );
    }

    private function makeValidator(): DictionaryValidator
    {
        return new DictionaryValidator([]);
    }

    #[Test]
    public function commonPasswordFailsWhenDictionaryExists(): void
    {
        if (! $this->dictionaryExists) {
            $this->markTestSkipped('Dictionary file not present — validator always passes.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('password');

        $this->assertFalse($result->isOK());
        $this->assertSame('This password is too common.', $result->reason());
    }

    #[Test]
    public function uncommonPasswordAlwaysPasses(): void
    {
        $validator = $this->makeValidator();
        // Randomly generated — extremely unlikely to be in any dictionary
        $result = $validator->check('Xk7!mQ2vP9nR4wLs-unique-2026');

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function checkIsCaseInsensitiveWhenDictionaryExists(): void
    {
        if (! $this->dictionaryExists) {
            $this->markTestSkipped('Dictionary file not present — validator always passes.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('PASSWORD');

        $this->assertFalse($result->isOK());
        $this->assertSame('This password is too common.', $result->reason());
    }

    #[Test]
    public function checkIsCaseInsensitiveMixedCase(): void
    {
        if (! $this->dictionaryExists) {
            $this->markTestSkipped('Dictionary file not present — validator always passes.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('Password');

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function failureResultHasExtraInfo(): void
    {
        if (! $this->dictionaryExists) {
            $this->markTestSkipped('Dictionary file not present — validator always passes.');
        }

        $validator = $this->makeValidator();
        $result = $validator->check('password');

        $this->assertNotNull($result->extraInfo());
        $this->assertStringContainsString('less common', (string) $result->extraInfo());
    }

    #[Test]
    public function nullUserDoesNotAffectResult(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('Xk7!mQ2vP9nR4wLs-unique-2026', null);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function anotherCommonPasswordFails(): void
    {
        if (! $this->dictionaryExists) {
            $this->markTestSkipped('Dictionary file not present — validator always passes.');
        }

        $validator = $this->makeValidator();
        // '123456' is universally in common-password dictionaries
        $result = $validator->check('123456');

        $this->assertFalse($result->isOK());
    }
}
