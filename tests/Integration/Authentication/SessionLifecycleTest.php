<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\ConditionalActionInterface;
use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A conditional action used to exercise actionApplies().
 */
class AdminOnlyConditionalAction implements ConditionalActionInterface
{
    public function appliesTo(User $user): bool
    {
        return $user->username === 'admin';
    }
}

/**
 * The session authenticator's lifecycle: login, logout, active date,
 * action checking and the pending state.
 */
#[CoversClass(Session::class)]
class SessionLifecycleTest extends TestCase
{
    protected PDO $pdo;
    protected Session $auth;
    protected array $config;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $this->config = TestHelper::getConfig();
        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);
        $this->auth = new Session(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_COOKIE['remember']);
    }

    private function makeAuth(array $overrides = []): Session
    {
        return new Session(\Flight::app(), array_merge($this->config, $overrides));
    }

    private function seedCodeIdentity(User $user, string $rawToken, string $expires = '+1 hour'): UserIdentity
    {
        $now = new \DateTimeImmutable();

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->name       = 'login';
        $identity->secret     = hash('sha256', $rawToken);
        $identity->expires    = $now->modify($expires)->format('Y-m-d H:i:s');
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();

        return $identity;
    }

    private function lastActive(): mixed
    {
        return $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
    }

    // -----------------------------------------------------------------
    // Login / logout
    // -----------------------------------------------------------------

    #[Test]
    public function loginStoresTheUserInTheSession(): void
    {
        $this->auth->login($this->user);

        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
        $this->assertSame($this->user->id, $_SESSION['user']);
    }

    #[Test]
    public function loginByIdLoadsAndLogsInTheUser(): void
    {
        $this->auth->loginById($this->user->id);

        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loginByIdRejectsAnUnknownUser(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->auth->loginById(999);
    }

    #[Test]
    public function loggedInIsFalseForAnonymousVisitors(): void
    {
        $this->assertFalse($this->auth->loggedIn());
        $this->assertNull($this->auth->getUser());
    }

    #[Test]
    public function logoutClearsTheSessionAndTheUser(): void
    {
        $this->auth->login($this->user);

        $this->auth->logout();

        $this->assertFalse($this->auth->loggedIn());
        $this->assertNull($this->auth->getUser());
        $this->assertArrayNotHasKey('user', $_SESSION);
    }

    // -----------------------------------------------------------------
    // recordActiveDate()
    // -----------------------------------------------------------------

    #[Test]
    public function recordActiveDateUpdatesAnActiveUser(): void
    {
        $this->auth->login($this->user);
        $this->auth->recordActiveDate();

        $this->assertNotNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateIsSkippedWhenDisabled(): void
    {
        $auth = $this->makeAuth(['record_active_date' => false]);
        $auth->login($this->user);

        $auth->recordActiveDate();

        $this->assertNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateSkipsABannedUser(): void
    {
        $this->user->status = 'banned';
        $this->auth->login($this->user);

        $this->auth->recordActiveDate();

        $this->assertNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateDoesNothingWhenLoggedOut(): void
    {
        $this->auth->recordActiveDate();

        $this->assertNull($this->lastActive());
    }

    // -----------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------

    #[Test]
    public function checkActionAcceptsTheMatchingTokenAndBurnsIt(): void
    {
        $identity = $this->seedCodeIdentity($this->user, 'correct-token');

        $this->assertTrue($this->auth->checkAction($identity, 'correct-token'));
        $this->assertSame(
            0,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE type = 'email_2fa'")->fetchColumn()
        );
    }

    #[Test]
    public function checkActionRejectsAMissingToken(): void
    {
        $identity = $this->seedCodeIdentity($this->user, 'correct-token');

        $this->assertFalse($this->auth->checkAction($identity, null));
        $this->assertFalse($this->auth->checkAction(null, 'correct-token'));
    }

    #[Test]
    public function checkActionRejectsAWrongToken(): void
    {
        $identity = $this->seedCodeIdentity($this->user, 'correct-token');

        $this->assertFalse($this->auth->checkAction($identity, 'wrong-token'));
    }

    #[Test]
    public function checkActionRejectsAnExpiredIdentity(): void
    {
        $identity = $this->seedCodeIdentity($this->user, 'stale-token', '-1 hour');

        $this->assertFalse($this->auth->checkAction($identity, 'stale-token'));
    }

    #[Test]
    public function hasActionReflectsTheSessionMarker(): void
    {
        $this->assertFalse($this->auth->hasAction($this->user->id));

        $this->auth->startAction(Email2FA::class, $this->user);

        $this->assertTrue($this->auth->hasAction($this->user->id));
    }

    #[Test]
    public function completeActionClearsTheMarkerAndMarksLoggedIn(): void
    {
        $this->auth->startAction(Email2FA::class, $this->user);

        $this->auth->completeAction();

        $this->assertFalse($this->auth->hasAction($this->user->id));
        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function actionAppliesHonoursTheConditionalInterface(): void
    {
        $this->assertTrue($this->auth->actionApplies(Email2FA::class, $this->user));

        $this->user->username = 'admin';
        $this->assertTrue($this->auth->actionApplies(AdminOnlyConditionalAction::class, $this->user));

        $this->user->username = 'bob';
        $this->assertFalse($this->auth->actionApplies(AdminOnlyConditionalAction::class, $this->user));
    }

    #[Test]
    public function getPendingUserResolvesFromTheSession(): void
    {
        $this->auth->startAction(Email2FA::class, $this->user);

        $this->assertTrue($this->auth->isPending());
        $this->assertSame($this->user->id, $this->auth->getPendingUser()->id);
    }
}
