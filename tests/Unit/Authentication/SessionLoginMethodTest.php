<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\ConditionalActionInterface;
use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\User;
use flight\Engine;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class AdminOnlyAction implements ConditionalActionInterface
{
    public function appliesTo(User $user): bool
    {
        return $user->username === 'admin';
    }
}

#[CoversClass(Session::class)]
class SessionLoginMethodTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    private function makeAuthenticator(array $config = []): Session
    {
        $app = new Engine();

        $defaults = [
            'actions'   => [],
            'session'   => ['field' => 'user'],
            'passwords' => [],
        ];

        // Merge actions array level-by-level so individual keys can be set
        $actions = array_merge([], $config['actions'] ?? []);
        $merged = array_merge($defaults, $config);
        $merged['actions'] = $actions;

        return new Session($app, $merged);
    }

    private function makeUser(string $username, int $id = 0): User
    {
        $user = new User();
        $user->username = $username;
        $user->id = $id;

        return $user;
    }

    // -----------------------------------------------------------------
    // Empty / null action class disables the action
    // -----------------------------------------------------------------

    #[Test]
    public function emptyActionClassDisablesTheAction(): void
    {
        $auth = $this->makeAuthenticator(['actions' => ['login' => '']]);
        $user = $this->makeUser('staff');

        $this->assertFalse($auth->startUpAction('login', $user));
        $this->assertArrayNotHasKey('auth_action', $_SESSION);
    }

    #[Test]
    public function nullActionClassDisablesTheAction(): void
    {
        $auth = $this->makeAuthenticator(['actions' => ['login' => null]]);
        $user = $this->makeUser('staff');

        $this->assertFalse($auth->startUpAction('login', $user));
    }

    // -----------------------------------------------------------------
    // Conditional actions
    // -----------------------------------------------------------------

    #[Test]
    public function conditionalActionThatDoesNotApplyIsSkipped(): void
    {
        $auth = $this->makeAuthenticator(['actions' => ['login' => AdminOnlyAction::class]]);
        $user = $this->makeUser('staff');

        $this->assertFalse($auth->startUpAction('login', $user));
        $this->assertArrayNotHasKey('auth_action', $_SESSION);
        $this->assertFalse($auth->isPending());
    }

    #[Test]
    public function conditionalActionThatAppliesStartsAction(): void
    {
        $auth = $this->makeAuthenticator(['actions' => ['login' => AdminOnlyAction::class]]);
        $user = $this->makeUser('admin');

        $this->assertTrue($auth->startUpAction('login', $user));
        $this->assertSame(AdminOnlyAction::class, $_SESSION['auth_action']);
        $this->assertTrue($auth->isPending());
    }

    #[Test]
    public function unconditionalActionAppliesToEveryUser(): void
    {
        $auth = $this->makeAuthenticator(['actions' => ['login' => Email2FA::class]]);

        $this->assertTrue($auth->actionApplies(Email2FA::class, $this->makeUser('anyone')));

        $this->assertTrue($auth->startUpAction('login', $this->makeUser('anyone')));
        $this->assertSame(Email2FA::class, $_SESSION['auth_action']);
    }

    // -----------------------------------------------------------------
    // Passwordless login method markers
    // -----------------------------------------------------------------

    #[Test]
    public function magicLinkLoginCompletesAndSetsMagicLoginMarker(): void
    {
        $auth = $this->makeAuthenticator();
        $user = $this->makeUser('staff', 42);

        $auth->setPendingLoginMethod(Session::ID_TYPE_MAGIC_LINK);
        $auth->login($user);

        $this->assertTrue($_SESSION[Session::MAGIC_LOGIN_TEMP_DATA] ?? false);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
        $this->assertSame(42, $_SESSION['user']);
    }

    #[Test]
    public function nonMagicLoginCompletesWithoutMarker(): void
    {
        $auth = $this->makeAuthenticator();
        $user = $this->makeUser('staff', 7);

        $auth->setPendingLoginMethod(Session::ID_TYPE_EMAIL_PASSWORD);
        $auth->login($user);

        $this->assertArrayNotHasKey(Session::MAGIC_LOGIN_TEMP_DATA, $_SESSION);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
    }

    #[Test]
    public function completeActionCompletesMagicLinkLogin(): void
    {
        $auth = $this->makeAuthenticator();
        $user = $this->makeUser('staff', 9);

        $auth->startAction(Email2FA::class, $user);
        $auth->setPendingLoginMethod(Session::ID_TYPE_MAGIC_LINK);
        $auth->completeAction();

        $this->assertTrue($_SESSION[Session::MAGIC_LOGIN_TEMP_DATA] ?? false);
        $this->assertArrayNotHasKey('auth_action', $_SESSION);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
    }

    #[Test]
    public function noPendingMethodLeavesNoMarkers(): void
    {
        $auth = $this->makeAuthenticator();
        $user = $this->makeUser('staff', 3);

        $auth->login($user);

        $this->assertArrayNotHasKey(Session::MAGIC_LOGIN_TEMP_DATA, $_SESSION);
        $this->assertArrayNotHasKey(Session::PENDING_LOGIN_METHOD, $_SESSION);
    }
}