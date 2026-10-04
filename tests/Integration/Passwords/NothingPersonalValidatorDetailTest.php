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
 * The validator's internals: the fragment splitting, the three-character
 * floor, the similarity threshold edges, and the exact failure reasons.
 */
#[CoversClass(NothingPersonalValidator::class)]
class NothingPersonalValidatorDetailTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected NothingPersonalValidator $validator;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'jonathan@example.com', 'Str0ng!Passw0rd', 'jonathan', true);
        $this->validator = new NothingPersonalValidator(['max_similarity' => 50]);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    /**
     * @param array<string, mixed> $config
     */
    private function validator(array $config = []): NothingPersonalValidator
    {
        return new NothingPersonalValidator($config);
    }

    private function stripExplode(string $value): array
    {
        $method = new \ReflectionMethod($this->validator, 'stripExplode');
        $method->setAccessible(true);

        return $method->invoke($this->validator, $value);
    }

    // -----------------------------------------------------------------
    // stripExplode()
    // -----------------------------------------------------------------

    #[Test]
    public function stripExplodeSplitsOnNonWordCharacters(): void
    {
        $this->assertSame(['jon.smith', 'jon', 'smith'], $this->stripExplode('jon.smith'));
    }

    #[Test]
    public function stripExplodeKeepsTheOriginalWhenItIsNotAWholePart(): void
    {
        $parts = $this->stripExplode('jon.smith');

        $this->assertSame('jon.smith', $parts[0]);
    }

    #[Test]
    public function stripExplodeDoesNotDuplicateAWholePart(): void
    {
        $this->assertSame(['jon'], $this->stripExplode('jon'));
    }

    #[Test]
    public function stripExplodeTreatsUnderscoresAsSeparators(): void
    {
        $this->assertSame(['jon_smith', 'jon', 'smith'], $this->stripExplode('jon_smith'));
    }

    #[Test]
    public function stripExplodeOnAnEmptyStringReturnsOneEmptyPart(): void
    {
        $this->assertSame([''], $this->stripExplode(''));
    }

    // -----------------------------------------------------------------
    // The three-character floor
    // -----------------------------------------------------------------

    #[Test]
    public function aTwoCharacterUsernameFragmentIsIgnored(): void
    {
        $this->pdo->exec("UPDATE users SET username = 'jo' WHERE id = {$this->user->id}");
        $user = (new User($this->pdo))->findById($this->user->id);

        $this->assertTrue($this->validator->check('jo9!Xyk', $user)->isOK());
    }

    #[Test]
    public function aThreeCharacterUsernameFragmentIsCaught(): void
    {
        $this->pdo->exec("UPDATE users SET username = 'jon' WHERE id = {$this->user->id}");
        $user = (new User($this->pdo))->findById($this->user->id);

        $this->assertFalse($this->validator->check('jon9!Xyk', $user)->isOK());
    }

    #[Test]
    public function aTwoCharacterPasswordFragmentIsIgnored(): void
    {
        // The password splits to 'jo', which is under the floor.
        $this->assertTrue($this->validator->check('jo', $this->user)->isOK());
    }

    #[Test]
    public function aMultibyteFragmentIsMeasuredInCharacters(): void
    {
        // Three emoji: 12 bytes, 3 characters. A byte-based floor would
        // treat this as long enough to compare.
        $password = str_repeat("\u{1F600}", 3);

        $this->assertTrue($this->validator->check($password, $this->user)->isOK());
    }

    // -----------------------------------------------------------------
    // Email handling
    // -----------------------------------------------------------------

    #[Test]
    public function theEmailDomainIsAWholeNeedle(): void
    {
        // 'example' alone is not a needle; the full domain is.
        $this->assertTrue($this->validator->check('example9!Xyk', $this->user)->isOK());
    }

    #[Test]
    public function aPasswordContainingTheDomainIsRejected(): void
    {
        $this->assertFalse($this->validator->check('myexample.com9', $this->user)->isOK());
    }

    #[Test]
    public function anEmailWithoutAnAtSignIsIgnored(): void
    {
        $this->pdo->exec("UPDATE auth_identities SET secret = 'not-an-email' WHERE user_id = {$this->user->id}");

        $this->assertTrue($this->validator->check('Purple!Harbour9', $this->user)->isOK());
    }

    #[Test]
    public function anUnhydratedUserSkipsTheEmailLookup(): void
    {
        $detached = new User();
        $detached->username = 'jonathan';

        // No database row, so only the username is checked.
        $this->assertFalse($this->validator->check('jonathan', $detached)->isOK());
        $this->assertTrue($this->validator->check('Purple!Harbour9', $detached)->isOK());
    }

    // -----------------------------------------------------------------
    // Similarity threshold
    // -----------------------------------------------------------------

    #[Test]
    public function aThresholdOfOneRejectsAlmostAnything(): void
    {
        $this->assertFalse($this->validator(['max_similarity' => 1])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aThresholdOfOneHundredAcceptsAMerelySimilarPassword(): void
    {
        $this->assertTrue($this->validator(['max_similarity' => 100])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aNegativeThresholdSkipsTheSimilarityCheck(): void
    {
        $this->assertTrue($this->validator(['max_similarity' => -5])->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aMissingThresholdFallsBackToFifty(): void
    {
        // 'jonath0n' is well over 50% similar to 'jonathan'.
        $this->assertFalse($this->validator()->check('jonath0n', $this->user)->isOK());
    }

    #[Test]
    public function aUserWithoutAUsernameSkipsTheSimilarityCheck(): void
    {
        $this->pdo->exec("UPDATE users SET username = NULL WHERE id = {$this->user->id}");
        $user = (new User($this->pdo))->findById($this->user->id);

        $this->assertTrue($this->validator->check('jonath0n', $user)->isOK());
    }

    // -----------------------------------------------------------------
    // Failure reasons
    // -----------------------------------------------------------------

    #[Test]
    public function thePersonalFailureCarriesTheReasonAndHint(): void
    {
        $result = $this->validator->check('jonathan', $this->user);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password should not contain personal information.', $result->reason());
        $this->assertSame('Do not use your name, email, or username in your password.', $result->extraInfo());
    }

    #[Test]
    public function theSimilarityFailureCarriesTheReasonAndHint(): void
    {
        $result = $this->validator->check('jonath0n', $this->user);

        $this->assertFalse($result->isOK());
        $this->assertSame('Password is too similar to your username.', $result->reason());
        $this->assertSame('Choose a password that is different from your username.', $result->extraInfo());
    }

    #[Test]
    public function aPassingCheckReturnsSuccess(): void
    {
        $result = $this->validator->check('Purple!Harbour9', $this->user);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function thePasswordIsLowercasedBeforeComparison(): void
    {
        $this->assertFalse($this->validator->check('JONATHAN', $this->user)->isOK());
    }

    #[Test]
    public function theUsernameIsLowercasedBeforeComparison(): void
    {
        $this->pdo->exec("UPDATE users SET username = 'JONATHAN' WHERE id = {$this->user->id}");
        $user = (new User($this->pdo))->findById($this->user->id);

        $this->assertFalse($this->validator->check('jonathan', $user)->isOK());
    }
}
