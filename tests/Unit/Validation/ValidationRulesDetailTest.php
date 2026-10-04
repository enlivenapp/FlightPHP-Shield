<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Validation;

use Enlivenapp\FlightShield\Validation\ValidationRules;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The exact rule arrays and error strings, plus the multibyte length
 * handling that the existing tests do not pin down.
 */
#[CoversClass(ValidationRules::class)]
class ValidationRulesDetailTest extends TestCase
{
    private ValidationRules $rules;

    protected function setUp(): void
    {
        $this->rules = new ValidationRules();
    }

    // -------------------------------------------------------------------------
    // Rule arrays in full
    // -------------------------------------------------------------------------

    #[Test]
    public function theRegistrationEmailRulesAreExact(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertSame(['required' => true, 'email' => true, 'max_length' => 254], $rules['email']);
    }

    #[Test]
    public function theRegistrationPasswordRulesAreExact(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertSame(['required' => true, 'min_length' => 8], $rules['password']);
    }

    #[Test]
    public function theRegistrationConfirmRulesAreExact(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertSame(['required' => true, 'matches' => 'password'], $rules['password_confirm']);
    }

    #[Test]
    public function theLoginEmailRulesAreExact(): void
    {
        $rules = $this->rules->getLoginRules();

        $this->assertSame(['required' => true, 'email' => true, 'max_length' => 254], $rules['email']);
    }

    #[Test]
    public function theLoginPasswordRulesAreExact(): void
    {
        $rules = $this->rules->getLoginRules();

        $this->assertSame(['required' => true], $rules['password']);
    }

    #[Test]
    public function thePasswordRulesAreExact(): void
    {
        $this->assertSame(['required' => true, 'min_length' => 8], $this->rules->getPasswordRules());
    }

    #[Test]
    public function thePasswordConfirmRulesAreExact(): void
    {
        $this->assertSame(['required' => true, 'matches' => 'password'], $this->rules->getPasswordConfirmRules());
    }

    #[Test]
    public function aZeroMinLengthIsHonoured(): void
    {
        $rules = new ValidationRules(['min_length' => 0]);

        $this->assertSame(0, $rules->getPasswordRules()['min_length']);
        $this->assertSame(0, $rules->getRegistrationRules()['password']['min_length']);
    }

    // -------------------------------------------------------------------------
    // Error strings
    // -------------------------------------------------------------------------

    #[Test]
    public function theRequiredMessageCapitalisesTheFieldName(): void
    {
        $errors = $this->rules->validate([], ['email' => ['required' => true]]);

        $this->assertSame('Email is required.', $errors['email']);
    }

    #[Test]
    public function theMinLengthMessageNamesTheLimit(): void
    {
        $errors = $this->rules->validate(['password' => 'abc'], ['password' => ['min_length' => 8]]);

        $this->assertSame('Password must be at least 8 characters.', $errors['password']);
    }

    #[Test]
    public function theMaxLengthMessageNamesTheLimit(): void
    {
        $errors = $this->rules->validate(['email' => 'abcdefghijk'], ['email' => ['max_length' => 10]]);

        $this->assertSame('Email must be no more than 10 characters.', $errors['email']);
    }

    #[Test]
    public function thePatternMessageCapitalisesTheFieldName(): void
    {
        $errors = $this->rules->validate(
            ['username' => 'bad!'],
            ['username' => ['pattern' => '/^[a-z]+$/']]
        );

        $this->assertSame('Username contains invalid characters.', $errors['username']);
    }

    #[Test]
    public function theMatchesMessageNamesTheOtherField(): void
    {
        $errors = $this->rules->validate(
            ['password' => 'one', 'password_confirm' => 'two'],
            ['password_confirm' => ['matches' => 'password']]
        );

        $this->assertSame('Password_confirm does not match password.', $errors['password_confirm']);
    }

    // -------------------------------------------------------------------------
    // Length boundaries
    // -------------------------------------------------------------------------

    #[Test]
    public function aValueOneBelowMinLengthFails(): void
    {
        $errors = $this->rules->validate(['password' => 'abcdefg'], ['password' => ['min_length' => 8]]);

        $this->assertArrayHasKey('password', $errors);
    }

    #[Test]
    public function aValueOneOverMaxLengthFails(): void
    {
        $errors = $this->rules->validate(['email' => 'abcdefghijk'], ['email' => ['max_length' => 10]]);

        $this->assertArrayHasKey('email', $errors);
    }

    #[Test]
    public function aMultibyteValueIsMeasuredInCharacters(): void
    {
        // Four 4-byte emoji: 16 bytes, 4 characters.
        $value = str_repeat("\u{1F600}", 4);

        $errors = $this->rules->validate(['name' => $value], ['name' => ['min_length' => 5]]);
        $this->assertArrayHasKey('name', $errors);

        $errors = $this->rules->validate(['name' => $value], ['name' => ['min_length' => 4]]);
        $this->assertArrayNotHasKey('name', $errors);
    }

    #[Test]
    public function aMultibyteValueOverMaxLengthFails(): void
    {
        $value = str_repeat("\u{1F600}", 4);

        $errors = $this->rules->validate(['name' => $value], ['name' => ['max_length' => 3]]);

        $this->assertArrayHasKey('name', $errors);
    }

    #[Test]
    public function aMultibyteValueWithinMaxLengthPasses(): void
    {
        // Four emoji: 16 bytes, 4 characters. A byte-based check would
        // reject this against a limit of 10.
        $value = str_repeat("\u{1F600}", 4);

        $errors = $this->rules->validate(['name' => $value], ['name' => ['max_length' => 10]]);

        $this->assertArrayNotHasKey('name', $errors);
    }

    #[Test]
    public function anEmptyOptionalFieldDoesNotStopLaterFields(): void
    {
        $errors = $this->rules->validate(
            ['nickname' => '', 'email' => ''],
            [
                'nickname' => ['min_length' => 3],
                'email'    => ['required' => true],
            ]
        );

        $this->assertArrayNotHasKey('nickname', $errors);
        $this->assertArrayHasKey('email', $errors);
    }

    // -------------------------------------------------------------------------
    // Rule ordering and short-circuiting
    // -------------------------------------------------------------------------

    #[Test]
    public function aRequiredFailureStopsTheOtherRulesForThatField(): void
    {
        $errors = $this->rules->validate(
            ['email' => ''],
            ['email' => ['required' => true, 'email' => true, 'max_length' => 5]]
        );

        $this->assertSame('Email is required.', $errors['email']);
    }

    #[Test]
    public function aLaterRuleOverwritesAnEarlierErrorForTheSameField(): void
    {
        $errors = $this->rules->validate(
            ['email' => 'not-an-email-and-far-too-long'],
            ['email' => ['email' => true, 'max_length' => 5]]
        );

        $this->assertSame('Email must be no more than 5 characters.', $errors['email']);
    }

    #[Test]
    public function aZeroMaxLengthIsIgnored(): void
    {
        $errors = $this->rules->validate(['name' => 'anything'], ['name' => ['max_length' => 0]]);

        $this->assertArrayNotHasKey('name', $errors);
    }

    #[Test]
    public function aZeroMinLengthIsIgnored(): void
    {
        $errors = $this->rules->validate(['name' => 'a'], ['name' => ['min_length' => 0]]);

        $this->assertArrayNotHasKey('name', $errors);
    }

    #[Test]
    public function aNullValueSkipsTheOptionalRules(): void
    {
        $errors = $this->rules->validate(['name' => null], ['name' => ['min_length' => 5]]);

        $this->assertArrayNotHasKey('name', $errors);
    }

    #[Test]
    public function aMissingMatchFieldFailsTheMatch(): void
    {
        $errors = $this->rules->validate(
            ['password_confirm' => 'secret'],
            ['password_confirm' => ['matches' => 'password']]
        );

        $this->assertArrayHasKey('password_confirm', $errors);
    }

    #[Test]
    public function anEmptyRuleSetReturnsNoErrors(): void
    {
        $this->assertSame([], $this->rules->validate(['anything' => 'value'], []));
    }

    #[Test]
    public function aFieldWithNoRulesIsSkipped(): void
    {
        $this->assertSame([], $this->rules->validate(['anything' => 'value'], ['anything' => []]));
    }

    #[Test]
    public function everyFailingFieldGetsItsOwnError(): void
    {
        $errors = $this->rules->validate(
            ['a' => '', 'b' => '', 'c' => ''],
            [
                'a' => ['required' => true],
                'b' => ['required' => true],
                'c' => ['required' => true],
            ]
        );

        $this->assertSame(['a', 'b', 'c'], array_keys($errors));
    }
}
