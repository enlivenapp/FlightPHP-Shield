<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\RememberToken;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Remember-me: issuing a token, restoring a session from the cookie, and the
 * rejection paths that clear it.
 */
#[CoversClass(Session::class)]
class SessionRememberMeTest extends TestCase
{
    protected PDO $pdo;
    protected Session $auth;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        unset($_COOKIE['remember']);

        $this->auth = new Session(\Flight::app(), TestHelper::getConfig());
        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_COOKIE['remember']);
    }

    /**
     * Insert a remember token and return the cookie value.
     */
    private function seedRememberCookie(User $user, string $expires = '+1 day', ?string $validatorOverride = null): string
    {
        $selector  = bin2hex(random_bytes(12));
        $validator = $validatorOverride ?? bin2hex(random_bytes(20));
        $now = new \DateTimeImmutable();

        $token = new RememberToken($this->pdo);
        $token->selector         = $selector;
        $token->hashed_validator = hash('sha256', $validator);
        $token->user_id          = $user->id;
        $token->expires          = $now->modify($expires)->format('Y-m-d H:i:s');
        $token->created_at       = $now->format('Y-m-d H:i:s');
        $token->updated_at       = $now->format('Y-m-d H:i:s');
        $token->insert();

        return $selector . ':' . $validator;
    }

    private function tokenCount(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM auth_remember_tokens')->fetchColumn();
    }

    // -----------------------------------------------------------------
    // remember()
    // -----------------------------------------------------------------

    #[Test]
    public function rememberDoesNothingWithoutAUser(): void
    {
        $this->auth->remember();

        $this->assertSame(0, $this->tokenCount());
    }

    #[Test]
    public function rememberStoresATokenForTheLoggedInUser(): void
    {
        $this->auth->login($this->user);

        $this->auth->remember();

        $this->assertSame(1, $this->tokenCount());
        $stored = $this->pdo->query("SELECT user_id FROM auth_remember_tokens")->fetchColumn();
        $this->assertSame((string) $this->user->id, (string) $stored);
    }

    // -----------------------------------------------------------------
    // Restore from cookie
    // -----------------------------------------------------------------

    #[Test]
    public function aValidCookieRestoresTheSession(): void
    {
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user);

        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function restoringRotatesTheToken(): void
    {
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user);

        $this->auth->loggedIn();

        // The old token is deleted and a fresh one issued.
        $this->assertSame(1, $this->tokenCount());
    }

    // -----------------------------------------------------------------
    // Rejection paths
    // -----------------------------------------------------------------

    #[Test]
    public function aMalformedCookieIsCleared(): void
    {
        $_COOKIE['remember'] = 'no-colon-here';

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function anUnknownSelectorIsRejected(): void
    {
        $_COOKIE['remember'] = 'deadbeef:deadbeef';

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function aWrongValidatorPurgesTheUsersTokens(): void
    {
        $cookie = $this->seedRememberCookie($this->user);

        // Keep the selector but send the wrong validator.
        $selector = explode(':', $cookie)[0];
        $_COOKIE['remember'] = $selector . ':' . bin2hex(random_bytes(20));

        $this->assertFalse($this->auth->loggedIn());
        $this->assertSame(0, $this->tokenCount());
    }

    #[Test]
    public function anExpiredTokenIsRejected(): void
    {
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user, '-1 day');

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function aBannedUserIsRejected(): void
    {
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user);

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function anInactiveUserIsRejected(): void
    {
        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$this->user->id}");
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user);

        $this->assertFalse($this->auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // logout() with a remember cookie present
    // -----------------------------------------------------------------

    #[Test]
    public function logoutDeletesTheRememberTokensWhenTheCookieIsPresent(): void
    {
        $_COOKIE['remember'] = $this->seedRememberCookie($this->user);

        $this->auth->logout();

        $this->assertSame(0, $this->tokenCount());
    }

    #[Test]
    public function logoutToleratesAMalformedRememberCookie(): void
    {
        $_COOKIE['remember'] = 'garbage-without-a-selector';

        $this->auth->logout();

        $this->assertNull($this->auth->getUser());
    }

    #[Test]
    public function logoutWithoutACookieIsStillClean(): void
    {
        $this->auth->login($this->user);

        $this->auth->logout();

        $this->assertFalse($this->auth->loggedIn());
    }
}
