<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Passwords;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Passwords\NothingPersonalValidator;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The needle/haystack merge, the domain guard, the similarity clamp, and
 * the multibyte floor.
 */
#[CoversClass(NothingPersonalValidator::class)]
class NothingPersonalValidatorMergeTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'jonathan@example.com', 'Str0ng!Passw0rd', 'jonathan', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    /**
     * @param array<string, mixed> $config
     */
    private function validator(array $config = ['max_similarity' => 50]): NothingPersonalValidator
    {
        return new NothingPersonalValidator($config);
    }

    private function reloadUser(): User
    {
        $user = (new User($this->pdo))->findById($this->user->id);
        $this->assertNotNull($user);

        return $user;
    }

    // -----------------------------------------------------------------
    // The username needles survive the email merge
    // -----------------------------------------------------------------

    #[Test]
    public function theUsernameNeedleSurvivesWhenAnEmailIsPresent(): void
    {
        // The email local part differs from the username, so the username
        // needle is the only thing that can catch this.
        $this->pdo->exec("UPDATE auth_identities SET secret = 'jsmith@example.com' WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->validator()->check('jonathan9!Xyk', $this->reloadUser())->isOK());
    }

    #[Test]
    public function theUsernameNeedleSurvivesWithAMultiPartEmail(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET secret = 'j.smith@sub.example.com' WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->validator()->check('jonathan9!Xyk', $this->reloadUser())->isOK());
    }

    #[Test]
    public function theEmailLocalPartIsStillCaughtAfterTheMerge(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET secret = 'jon.smith@example.com' WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->validator()->check('smith9!Xyk', $this->reloadUser())->isOK());
    }

    // -----------------------------------------------------------------
    // The domain guard
    // -----------------------------------------------------------------

    #[Test]
    public function aDomainIsAddedAsANeedle(): void
    {
        // The password splits to 'example', which is under the floor, so the
        // whole domain is what catches it.
        $this->assertFalse($this->validator()->check('example.com', $this->user)->isOK());
    }

    #[Test]
    public function anEmptyDomainIsNotAdded(): void
    {
        // 'jonathan@' has an empty domain, so only the local part counts.
        $this->pdo->exec("UPDATE auth_identities SET secret = 'jonathan@' WHERE user_id = {$this->user->id}");

        $this->assertTrue($this->validator()->check('Purple!Harbour9', $this->reloadUser())->isOK());
    }

    #[Test]
    public function aMultiPartDomainIsAddedWhole(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET secret = 'jonathan@sub.example.com' WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->validator()->check('sub.example.com9', $this->reloadUser())->isOK());
    }

    // -----------------------------------------------------------------
    // The similarity clamp
    // -----------------------------------------------------------------

    #[Test]
    public function aThresholdAboveOneHundredIsClamped(): void
    {
        // 150 clamps to 100, which accepts a merely similar password.
        $this->assertTrue($this->validator(['max_similarity' => 150])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aThresholdOfExactlyOneHundredIsNotClamped(): void
    {
        $this->assertTrue($this->validator(['max_similarity' => 100])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aThresholdOfExactlyOneStillChecks(): void
    {
        $this->assertFalse($this->validator(['max_similarity' => 1])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aThresholdOfZeroSkipsTheCheck(): void
    {
        $this->assertTrue($this->validator(['max_similarity' => 0])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aStringThresholdIsCastToFloat(): void
    {
        $this->assertTrue($this->validator(['max_similarity' => '100'])->check('jonath0n', $this->user)->isOK());
    }

    // -----------------------------------------------------------------
    // The multibyte floor
    // -----------------------------------------------------------------

    #[Test]
    public function aThreeCharacterMultibyteNeedleIsCaught(): void
    {
        // Three emoji: 12 bytes, 3 characters. The floor is characters.
        $this->pdo->exec("UPDATE users SET username = 'abc' WHERE id = {$this->user->id}");
        $user = $this->reloadUser();

        $this->assertFalse($this->validator()->check('abc9!Xyk', $user)->isOK());
    }

    #[Test]
    public function aTwoCharacterMultibyteNeedleIsIgnored(): void
    {
        $this->pdo->exec("UPDATE users SET username = 'ab' WHERE id = {$this->user->id}");
        $user = $this->reloadUser();

        $this->assertTrue($this->validator()->check('ab9!Xyk', $user)->isOK());
    }

    #[Test]
    public function aThreeCharacterMultibyteHaystackIsCompared(): void
    {
        // The password splits to a 3-character multibyte part.
        $this->pdo->exec("UPDATE users SET username = 'abc' WHERE id = {$this->user->id}");
        $user = $this->reloadUser();

        $this->assertFalse($this->validator()->check('abc', $user)->isOK());
    }

    // -----------------------------------------------------------------
    // The reversed username
    // -----------------------------------------------------------------

    #[Test]
    public function theReversedUsernameIsRejected(): void
    {
        $this->assertFalse($this->validator()->check('nahtanoj', $this->user)->isOK());
    }

    #[Test]
    public function theReversedUsernameIsCaseInsensitive(): void
    {
        $this->assertFalse($this->validator()->check('NAHTANOJ', $this->user)->isOK());
    }

    // -----------------------------------------------------------------
    // The email itself
    // -----------------------------------------------------------------

    #[Test]
    public function theWholeEmailIsRejected(): void
    {
        $this->assertFalse($this->validator()->check('jonathan@example.com', $this->user)->isOK());
    }

    #[Test]
    public function theEmailIsLowercasedBeforeComparison(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET secret = 'JONATHAN@EXAMPLE.COM' WHERE user_id = {$this->user->id}");

        $this->assertFalse($this->validator()->check('jonathan@example.com', $this->reloadUser())->isOK());
    }
}
