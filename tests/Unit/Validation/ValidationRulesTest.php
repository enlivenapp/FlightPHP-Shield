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

#[CoversClass(ValidationRules::class)]
class ValidationRulesTest extends TestCase
{
    private ValidationRules $rules;

    protected function setUp(): void
    {
        $this->rules = new ValidationRules();
    }

    // -------------------------------------------------------------------------
    // Rule getter structure
    // -------------------------------------------------------------------------

    #[Test]
    public function getRegistrationRulesHasRequiredKeys(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertArrayHasKey('username', $rules);
        $this->assertArrayHasKey('email', $rules);
        $this->assertArrayHasKey('password', $rules);
        $this->assertArrayHasKey('password_confirm', $rules);
    }

    #[Test]
    public function getLoginRulesHasRequiredKeys(): void
    {
        $rules = $this->rules->getLoginRules();

        $this->assertArrayHasKey('email', $rules);
        $this->assertArrayHasKey('password', $rules);
        $this->assertCount(2, $rules);
    }

    #[Test]
    public function getPasswordRulesHasRequiredAndMinLength(): void
    {
        $rules = $this->rules->getPasswordRules();

        $this->assertArrayHasKey('required', $rules);
        $this->assertTrue($rules['required']);
        $this->assertArrayHasKey('min_length', $rules);
        $this->assertSame(8, $rules['min_length']);
    }

    #[Test]
    public function getPasswordConfirmRulesHasRequiredAndMatches(): void
    {
        $rules = $this->rules->getPasswordConfirmRules();

        $this->assertArrayHasKey('required', $rules);
        $this->assertTrue($rules['required']);
        $this->assertArrayHasKey('matches', $rules);
        $this->assertSame('password', $rules['matches']);
    }

    #[Test]
    public function customMinLengthAppliedToRegistrationRules(): void
    {
        $rules = new ValidationRules(['min_length' => 12]);
        $regRules = $rules->getRegistrationRules();

        $this->assertSame(12, $regRules['password']['min_length']);
    }

    #[Test]
    public function customMinLengthAppliedToPasswordRules(): void
    {
        $rules = new ValidationRules(['min_length' => 10]);
        $pwRules = $rules->getPasswordRules();

        $this->assertSame(10, $pwRules['min_length']);
    }

    #[Test]
    public function registrationRulesUsernameHasPatternRule(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertArrayHasKey('pattern', $rules['username']);
        $this->assertStringContainsString('a-zA-Z0-9', $rules['username']['pattern']);
    }

    #[Test]
    public function registrationRulesPasswordConfirmMatchesPassword(): void
    {
        $rules = $this->rules->getRegistrationRules();

        $this->assertArrayHasKey('matches', $rules['password_confirm']);
        $this->assertSame('password', $rules['password_confirm']['matches']);
    }

    // -------------------------------------------------------------------------
    // validate(): required fields
    // -------------------------------------------------------------------------

    #[Test]
    public function requiredFieldMissingProducesError(): void
    {
        $rules = ['email' => ['required' => true, 'email' => true]];
        $errors = $this->rules->validate([], $rules);

        $this->assertArrayHasKey('email', $errors);
        $this->assertStringContainsString('required', strtolower($errors['email']));
    }

    #[Test]
    public function requiredFieldEmptyStringProducesError(): void
    {
        $rules = ['email' => ['required' => true]];
        $errors = $this->rules->validate(['email' => ''], $rules);

        $this->assertArrayHasKey('email', $errors);
    }

    #[Test]
    public function requiredFieldPresentAndNonEmptyPassesRequired(): void
    {
        $rules = ['email' => ['required' => true]];
        $errors = $this->rules->validate(['email' => 'user@example.com'], $rules);

        $this->assertArrayNotHasKey('email', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): email
    // -------------------------------------------------------------------------

    #[Test]
    public function invalidEmailProducesError(): void
    {
        $rules = ['email' => ['required' => true, 'email' => true]];
        $errors = $this->rules->validate(['email' => 'not-an-email'], $rules);

        $this->assertArrayHasKey('email', $errors);
        $this->assertSame('Invalid email address.', $errors['email']);
    }

    #[Test]
    public function validEmailPassesEmailRule(): void
    {
        $rules = ['email' => ['required' => true, 'email' => true]];
        $errors = $this->rules->validate(['email' => 'user@example.com'], $rules);

        $this->assertArrayNotHasKey('email', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): min_length
    // -------------------------------------------------------------------------

    #[Test]
    public function valueBelowMinLengthProducesError(): void
    {
        $rules = ['password' => ['required' => true, 'min_length' => 8]];
        $errors = $this->rules->validate(['password' => 'short'], $rules);

        $this->assertArrayHasKey('password', $errors);
        $this->assertStringContainsString('at least 8 characters', $errors['password']);
    }

    #[Test]
    public function valueAtMinLengthPasses(): void
    {
        $rules = ['password' => ['required' => true, 'min_length' => 8]];
        $errors = $this->rules->validate(['password' => 'exactly8'], $rules);

        $this->assertArrayNotHasKey('password', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): max_length
    // -------------------------------------------------------------------------

    #[Test]
    public function valueOverMaxLengthProducesError(): void
    {
        $rules = ['email' => ['required' => true, 'max_length' => 10]];
        $errors = $this->rules->validate(['email' => 'this-is-way-too-long@example.com'], $rules);

        $this->assertArrayHasKey('email', $errors);
        $this->assertStringContainsString('no more than 10 characters', $errors['email']);
    }

    #[Test]
    public function valueAtMaxLengthPasses(): void
    {
        $rules = ['name' => ['required' => true, 'max_length' => 5]];
        $errors = $this->rules->validate(['name' => 'abcde'], $rules);

        $this->assertArrayNotHasKey('name', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): pattern
    // -------------------------------------------------------------------------

    #[Test]
    public function valueFailingPatternProducesError(): void
    {
        $rules = ['username' => ['required' => true, 'pattern' => '/^[a-zA-Z0-9.]+$/']];
        $errors = $this->rules->validate(['username' => 'bad username!'], $rules);

        $this->assertArrayHasKey('username', $errors);
        $this->assertStringContainsString('invalid characters', $errors['username']);
    }

    #[Test]
    public function valueMatchingPatternPasses(): void
    {
        $rules = ['username' => ['required' => true, 'pattern' => '/^[a-zA-Z0-9.]+$/']];
        $errors = $this->rules->validate(['username' => 'valid.username123'], $rules);

        $this->assertArrayNotHasKey('username', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): matches
    // -------------------------------------------------------------------------

    #[Test]
    public function nonMatchingConfirmationProducesError(): void
    {
        $rules = [
            'password'         => ['required' => true],
            'password_confirm' => ['required' => true, 'matches' => 'password'],
        ];
        $errors = $this->rules->validate([
            'password'         => 'secret123',
            'password_confirm' => 'different',
        ], $rules);

        $this->assertArrayHasKey('password_confirm', $errors);
        $this->assertStringContainsString('does not match', $errors['password_confirm']);
    }

    #[Test]
    public function matchingConfirmationPasses(): void
    {
        $rules = [
            'password'         => ['required' => true],
            'password_confirm' => ['required' => true, 'matches' => 'password'],
        ];
        $errors = $this->rules->validate([
            'password'         => 'secret123',
            'password_confirm' => 'secret123',
        ], $rules);

        $this->assertArrayNotHasKey('password_confirm', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): full registration pass
    // -------------------------------------------------------------------------

    #[Test]
    public function allValidRegistrationDataReturnsEmptyErrors(): void
    {
        $rules = $this->rules->getRegistrationRules();
        $errors = $this->rules->validate([
            'username'         => 'john.doe',
            'email'            => 'john@example.com',
            'password'         => 'secretpassword',
            'password_confirm' => 'secretpassword',
        ], $rules);

        $this->assertEmpty($errors);
    }

    // -------------------------------------------------------------------------
    // validate(): multiple errors at once
    // -------------------------------------------------------------------------

    #[Test]
    public function multipleInvalidFieldsProduceMultipleErrors(): void
    {
        $rules = $this->rules->getRegistrationRules();
        $errors = $this->rules->validate([
            'username'         => '',
            'email'            => 'not-an-email',
            'password'         => 'short',
            'password_confirm' => 'mismatch',
        ], $rules);

        $this->assertArrayHasKey('username', $errors);
        $this->assertArrayHasKey('email', $errors);
        $this->assertArrayHasKey('password', $errors);
        $this->assertGreaterThanOrEqual(3, count($errors));
    }

    // -------------------------------------------------------------------------
    // validate(): non-required empty field is skipped
    // -------------------------------------------------------------------------

    #[Test]
    public function nonRequiredEmptyFieldSkipsValidation(): void
    {
        $rules = [
            'nickname' => [
                'min_length' => 3,
                'max_length' => 20,
                'pattern'    => '/^[a-z]+$/',
            ],
        ];

        // Field absent — no error expected because it's not required
        $errors = $this->rules->validate([], $rules);
        $this->assertArrayNotHasKey('nickname', $errors);

        // Field empty string — same behaviour
        $errors = $this->rules->validate(['nickname' => ''], $rules);
        $this->assertArrayNotHasKey('nickname', $errors);
    }

    // -------------------------------------------------------------------------
    // validate(): login rules
    // -------------------------------------------------------------------------

    #[Test]
    public function allValidLoginDataReturnsEmptyErrors(): void
    {
        $rules = $this->rules->getLoginRules();
        $errors = $this->rules->validate([
            'email'    => 'user@example.com',
            'password' => 'mypassword',
        ], $rules);

        $this->assertEmpty($errors);
    }

    #[Test]
    public function loginMissingEmailProducesError(): void
    {
        $rules = $this->rules->getLoginRules();
        $errors = $this->rules->validate([
            'password' => 'mypassword',
        ], $rules);

        $this->assertArrayHasKey('email', $errors);
    }

    #[Test]
    public function loginMissingPasswordProducesError(): void
    {
        $rules = $this->rules->getLoginRules();
        $errors = $this->rules->validate([
            'email' => 'user@example.com',
        ], $rules);

        $this->assertArrayHasKey('password', $errors);
    }
}
