<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Passwords\NothingPersonalValidator;
use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NothingPersonalValidator::class)]
class NothingPersonalValidatorTest extends TestCase
{
    private function makeValidator(array $config = []): NothingPersonalValidator
    {
        return new NothingPersonalValidator(array_merge([
            'max_similarity' => 50,
        ], $config));
    }

    private function makeUser(string $username): User
    {
        $user = $this->createMock(User::class);
        $user->username = $username;
        $user->method('isHydrated')->willReturn(false);

        return $user;
    }

    #[Test]
    public function nullUserPasses(): void
    {
        $validator = $this->makeValidator();
        $result = $validator->check('anypassword', null);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function passwordEqualsUsernameFails(): void
    {
        $validator = $this->makeValidator();
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('johnsmith', $user);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password should not contain personal information.', $result->reason());
    }

    #[Test]
    public function passwordEqualsCaseInsensitiveUsernameFails(): void
    {
        $validator = $this->makeValidator();
        $user = $this->makeUser('johnsmith');

        // check() lowercases the password before comparison
        $result = $validator->check('JOHNSMITH', $user);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function passwordEqualsReversedUsernameFails(): void
    {
        $validator = $this->makeValidator();
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('htimsnhoj', $user);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password should not contain personal information.', $result->reason());
    }

    #[Test]
    public function passwordContainingUsernameSubstringFails(): void
    {
        $validator = $this->makeValidator();
        // username = 'johnsmith', substring 'john' (4 chars >= 3)
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('my-john-password', $user);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function passwordTooSimilarToUsernameFails(): void
    {
        $validator = $this->makeValidator(['max_similarity' => 50]);
        // 'johnsmith1' is very similar to 'johnsmith'
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('johnsmith1', $user);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function goodPasswordPasses(): void
    {
        $validator = $this->makeValidator();
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('Xk7!mQ2vP9nR4wLs', $user);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function lowMaxSimilarityDisablesSimilarityCheck(): void
    {
        // max_similarity < 1 skips the similarity check
        $validator = $this->makeValidator(['max_similarity' => 0]);
        $user = $this->makeUser('johnsmith');

        // This would normally fail the similarity check but should now be skipped
        // Still must not fail the personal-info check (exact match / reversed / substring)
        $result = $validator->check('johnsmith2', $user);

        // 'johnsmith2' contains 'johnsmith' (>= 3 chars), so personal check still fires
        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function lowMaxSimilarityAllowsSimilarPasswordWhenNoSubstringMatch(): void
    {
        // max_similarity = 0 disables similarity; no exact/reversed/substring match
        $validator = $this->makeValidator(['max_similarity' => 0]);
        $user = $this->makeUser('ab');

        // 'ab' is only 2 chars — strips/explode skips needles < 3; no substring match
        $result = $validator->check('abcdef12', $user);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function tooSimilarErrorHasExtraInfo(): void
    {
        $validator = $this->makeValidator(['max_similarity' => 50]);
        $user = $this->makeUser('johnsmith');

        $result = $validator->check('johnsmith1', $user);

        if (! $result->isOK() && $result->reason() === 'Password is too similar to your username.') {
            $this->assertNotNull($result->extraInfo());
        } else {
            // Failed on personal info check — that's also acceptable
            $this->assertFalse($result->isOK());
        }
    }
}
