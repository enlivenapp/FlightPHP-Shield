<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The session authenticator's remaining branches: the rehash write, the
 * pending-user lookup, the action lifecycle, and the remember-me purge.
 */
#[CoversClass(Session::class)]
class SessionBranchDetailTest extends TestCase
{
    protected PDO $pdo;
    protected Session $auth;

    /** @var array<string, mixed> */
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        unset($_COOKIE['remember']);

        $this->config = TestHelper::getConfig();
        $this->auth = new Session(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_COOKIE['remember']);
    }

    private function storedHash(string $email): string
    {
        $stmt = $this->pdo->prepare('SELECT secret2 FROM auth_identities WHERE secret = ?');
        $stmt->execute([$email]);

        return (string) $stmt->fetchColumn();
    }

    private function setStoredHash(string $email, string $password, int $cost): void
    {
        $stmt = $this->pdo->prepare('UPDATE auth_identities SET secret2 = ? WHERE secret = ?');
        $stmt->execute([password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]), $email]);
    }

    // -----------------------------------------------------------------
    // The rehash write
    // -----------------------------------------------------------------

    #[Test]
    public function theRehashPersistsTheNewHash(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->setStoredHash('user@example.com', 'Str0ng!Passw0rd', 10);

        $this->config['passwords']['cost'] = 4;
        $auth = new Session(\Flight::app(), $this->config);

        $auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertStringStartsWith('$2y$04$', $this->storedHash('user@example.com'));
    }

    #[Test]
    public function theRehashUpdatesTheTimestamp(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->setStoredHash('user@example.com', 'Str0ng!Passw0rd', 10);
        $this->pdo->exec("UPDATE auth_identities SET updated_at = '2000-01-01 00:00:00' WHERE secret = 'user@example.com'");

        $this->config['passwords']['cost'] = 4;
        $auth = new Session(\Flight::app(), $this->config);

        $auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $updatedAt = (string) $this->pdo->query("SELECT updated_at FROM auth_identities WHERE secret = 'user@example.com'")->fetchColumn();
        $this->assertNotSame('2000-01-01 00:00:00', $updatedAt);
    }

    #[Test]
    public function aMatchingCostSkipsTheRehash(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $before = $this->storedHash('user@example.com');

        $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertSame($before, $this->storedHash('user@example.com'));
    }

    // -----------------------------------------------------------------
    // getPendingUser()
    // -----------------------------------------------------------------

    #[Test]
    public function getPendingUserReturnsTheUserFromTheSession(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $pending = $this->auth->getPendingUser();

        $this->assertNotNull($pending);
        $this->assertSame($user->id, $pending->id);
    }

    #[Test]
    public function getPendingUserReturnsNullWithoutASessionEntry(): void
    {
        $this->assertNull($this->auth->getPendingUser());
    }

    #[Test]
    public function getPendingUserUsesTheConfiguredSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['field'] = 'auth_user';
        $auth = new Session(\Flight::app(), $this->config);

        $auth->startAction('SomeAction', $user);

        $this->assertSame($user->id, $_SESSION['auth_user']);
        $this->assertSame($user->id, $auth->getPendingUser()->id);
    }

    // -----------------------------------------------------------------
    // isPending()
    // -----------------------------------------------------------------

    #[Test]
    public function isPendingIsTrueAfterStartAction(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $this->assertTrue($this->auth->isPending());
    }

    #[Test]
    public function isPendingIsFalseForALoggedInUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $this->assertFalse($this->auth->isPending());
    }

    #[Test]
    public function isPendingIsFalseWhenLoggedOut(): void
    {
        $this->assertFalse($this->auth->isPending());
    }

    // -----------------------------------------------------------------
    // startAction() and completeAction()
    // -----------------------------------------------------------------

    #[Test]
    public function startActionUsesTheConfiguredSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['field'] = 'auth_user';
        $auth = new Session(\Flight::app(), $this->config);

        $auth->startAction('SomeAction', $user);

        $this->assertSame($user->id, $_SESSION['auth_user']);
        $this->assertSame('SomeAction', $_SESSION['auth_action']);
    }

    #[Test]
    public function completeActionClearsTheActionMarker(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $this->auth->completeAction();

        $this->assertArrayNotHasKey('auth_action', $_SESSION);
        $this->assertFalse($this->auth->isPending());
    }

    #[Test]
    public function completeActionClearsTheTwoFactorMarker(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);
        $_SESSION['2fa_code_sent'] = true;

        $this->auth->completeAction();

        $this->assertArrayNotHasKey('2fa_code_sent', $_SESSION);
    }

    #[Test]
    public function completeActionLeavesTheUserLoggedIn(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $this->auth->completeAction();

        $this->assertTrue($this->auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // checkAction()
    // -----------------------------------------------------------------

    #[Test]
    public function checkActionRejectsANullIdentity(): void
    {
        $this->assertFalse($this->auth->checkAction(null, 'token'));
    }

    #[Test]
    public function checkActionRejectsANullToken(): void
    {
        $identity = new UserIdentity($this->pdo);

        $this->assertFalse($this->auth->checkAction($identity, null));
    }

    #[Test]
    public function checkActionRejectsAnExpiredIdentity(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->secret     = hash('sha256', 'token');
        $identity->expires    = (new \DateTimeImmutable('-1 hour'))->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $this->assertFalse($this->auth->checkAction($identity, 'token'));
    }

    #[Test]
    public function checkActionRejectsAWrongToken(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->secret     = hash('sha256', 'right-token');
        $identity->expires    = (new \DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $this->assertFalse($this->auth->checkAction($identity, 'wrong-token'));
    }

    #[Test]
    public function checkActionAcceptsTheRightTokenAndCompletes(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->secret     = hash('sha256', 'right-token');
        $identity->expires    = (new \DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $this->assertTrue($this->auth->checkAction($identity, 'right-token'));
        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function checkActionDeletesTheIdentity(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->secret     = hash('sha256', 'right-token');
        $identity->expires    = (new \DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $this->auth->checkAction($identity, 'right-token');

        $this->assertSame(
            0,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE type = '" . Session::ID_TYPE_EMAIL_2FA . "'")->fetchColumn()
        );
    }

    // -----------------------------------------------------------------
    // getAction()
    // -----------------------------------------------------------------

    #[Test]
    public function getActionReturnsNullWithoutAnAction(): void
    {
        $this->assertNull($this->auth->getAction());
    }

    #[Test]
    public function getActionReturnsNullForAnUnknownClass(): void
    {
        $_SESSION['auth_action'] = 'Not\\A\\Real\\Class';

        $this->assertNull($this->auth->getAction());
    }

    #[Test]
    public function getActionReturnsNullForAClassNotInTheConfig(): void
    {
        $_SESSION['auth_action'] = \stdClass::class;

        $this->assertNull($this->auth->getAction());
    }

    #[Test]
    public function getActionReturnsTheConfiguredAction(): void
    {
        $this->config['actions']['login'] = \stdClass::class;
        $auth = new Session(\Flight::app(), $this->config);

        $_SESSION['auth_action'] = \stdClass::class;

        $this->assertInstanceOf(\stdClass::class, $auth->getAction());
    }

    #[Test]
    public function getActionFindsAnActionConfiguredOnlyForRegister(): void
    {
        $this->config['actions']['login'] = null;
        $this->config['actions']['register'] = \stdClass::class;
        $auth = new Session(\Flight::app(), $this->config);

        $_SESSION['auth_action'] = \stdClass::class;

        $this->assertInstanceOf(\stdClass::class, $auth->getAction());
    }

    #[Test]
    public function getActionFindsAnActionConfiguredOnlyForLogin(): void
    {
        $this->config['actions']['login'] = \stdClass::class;
        $this->config['actions']['register'] = null;
        $auth = new Session(\Flight::app(), $this->config);

        $_SESSION['auth_action'] = \stdClass::class;

        $this->assertInstanceOf(\stdClass::class, $auth->getAction());
    }

    #[Test]
    public function getActionReturnsNullWhenNeitherActionIsConfigured(): void
    {
        $this->config['actions']['login'] = null;
        $this->config['actions']['register'] = null;
        $auth = new Session(\Flight::app(), $this->config);

        $_SESSION['auth_action'] = \stdClass::class;

        $this->assertNull($auth->getAction());
    }

    #[Test]
    public function theSessionStoreIsReusedAcrossCalls(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->login($user);
        $this->auth->login($user);

        $this->assertSame($user->id, $_SESSION['user']);
    }

    #[Test]
    public function aSessionWithoutConfigStillResolvesAStore(): void
    {
        $config = $this->config;
        unset($config['session']);

        $auth = new Session(\Flight::app(), $config);
        $auth->login(TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true));

        $this->assertTrue($auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // hasAction()
    // -----------------------------------------------------------------

    #[Test]
    public function hasActionIsFalseWithoutAnAction(): void
    {
        $this->assertFalse($this->auth->hasAction(1));
    }

    #[Test]
    public function hasActionIsTrueWithAnAction(): void
    {
        $_SESSION['auth_action'] = 'SomeAction';

        $this->assertTrue($this->auth->hasAction(1));
    }

    // -----------------------------------------------------------------
    // recordActiveDate()
    // -----------------------------------------------------------------

    #[Test]
    public function recordActiveDateIsSkippedWhenDisabled(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['record_active_date'] = false;
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->recordActiveDate();

        $this->assertNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateIsSkippedForABannedUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");

        // Reload so the in-memory status matches the row.
        $banned = (new User($this->pdo))->findById($user->id);
        $this->assertNotNull($banned);

        $this->auth->login($banned);
        $this->auth->recordActiveDate();

        $this->assertNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateIsSkippedForAnInactiveUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $this->auth->login($user);
        $this->auth->recordActiveDate();

        $this->assertNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateWritesForAnActiveUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->login($user);
        $this->auth->recordActiveDate();

        $this->assertNotNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$user->id}")->fetchColumn()
        );
    }

    // -----------------------------------------------------------------
    // completePendingLoginMethod()
    // -----------------------------------------------------------------

    #[Test]
    public function aPendingMagicLinkLoginSetsTheMarker(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->setPendingLoginMethod(Session::ID_TYPE_MAGIC_LINK);
        $this->auth->login($user);

        $this->assertTrue($_SESSION[Session::MAGIC_LOGIN_TEMP_DATA] ?? false);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
    }

    #[Test]
    public function aPendingNonMagicLoginSetsNoMarker(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->setPendingLoginMethod('something-else');
        $this->auth->login($user);

        $this->assertArrayNotHasKey(Session::MAGIC_LOGIN_TEMP_DATA, $_SESSION);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
    }

    #[Test]
    public function noPendingMethodLeavesTheSessionAlone(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->login($user);

        $this->assertArrayNotHasKey(Session::MAGIC_LOGIN_TEMP_DATA, $_SESSION);
    }

    // -----------------------------------------------------------------
    // logout()
    // -----------------------------------------------------------------

    #[Test]
    public function logoutClearsTheActionMarker(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->startAction('SomeAction', $user);

        $this->auth->logout();

        $this->assertArrayNotHasKey('auth_action', $_SESSION);
    }

    #[Test]
    public function logoutClearsTheUserFromTheSession(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $this->auth->logout();

        $this->assertArrayNotHasKey('user', $_SESSION);
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function logoutDeletesTheRememberTokenForTheCookie(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);
        $this->auth->remember();

        $token = $this->pdo->query('SELECT * FROM auth_remember_tokens')->fetch(PDO::FETCH_ASSOC);
        $this->assertIsArray($token);

        $_COOKIE['remember'] = $token['selector'] . ':' . str_repeat('a', 40);

        $this->auth->logout();

        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM auth_remember_tokens')->fetchColumn());
    }

    #[Test]
    public function logoutIgnoresAnUnknownRememberCookie(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $_COOKIE['remember'] = 'ghost-selector:validator';

        $this->auth->logout();

        $this->assertFalse($this->auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // loggedIn() and getUser()
    // -----------------------------------------------------------------

    #[Test]
    public function loggedInIsTrueAfterLogin(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsFalseWhenLoggedOut(): void
    {
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function getUserReturnsNullWhenLoggedOut(): void
    {
        $this->assertNull($this->auth->getUser());
    }

    #[Test]
    public function getUserReturnsTheUserAfterLogin(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $this->assertSame($user->id, $this->auth->getUser()->id);
    }

    // -----------------------------------------------------------------
    // loginById()
    // -----------------------------------------------------------------

    #[Test]
    public function loginByIdLogsInTheUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->loginById($user->id);

        $this->assertSame($user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loginByIdRejectsAnUnknownUser(): void
    {
        $this->expectException(\Enlivenapp\FlightShield\Exceptions\AuthenticationException::class);

        $this->auth->loginById(999);
    }
}
