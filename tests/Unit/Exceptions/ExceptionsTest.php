<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Exceptions;

use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Exceptions\AuthorizationException;
use Enlivenapp\FlightShield\Exceptions\BaseException;
use Enlivenapp\FlightShield\Exceptions\GroupException;
use Enlivenapp\FlightShield\Exceptions\InvalidArgumentException;
use Enlivenapp\FlightShield\Exceptions\LogicException;
use Enlivenapp\FlightShield\Exceptions\PermissionException;
use Enlivenapp\FlightShield\Exceptions\RuntimeException;
use Enlivenapp\FlightShield\Exceptions\SecurityException;
use Enlivenapp\FlightShield\Exceptions\UserNotFoundException;
use Enlivenapp\FlightShield\Exceptions\ValidationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthenticationException::class)]
#[CoversClass(AuthorizationException::class)]
#[CoversClass(BaseException::class)]
#[CoversClass(GroupException::class)]
#[CoversClass(InvalidArgumentException::class)]
#[CoversClass(LogicException::class)]
#[CoversClass(PermissionException::class)]
#[CoversClass(RuntimeException::class)]
#[CoversClass(SecurityException::class)]
#[CoversClass(UserNotFoundException::class)]
#[CoversClass(ValidationException::class)]
class ExceptionsTest extends TestCase
{
    // -----------------------------------------------------------------
    // BaseException
    // -----------------------------------------------------------------

    #[Test]
    public function baseExceptionIsInterface(): void
    {
        $this->assertTrue(interface_exists(BaseException::class));
    }

    #[Test]
    public function baseExceptionExtendsThrowable(): void
    {
        $parents = class_implements(BaseException::class);
        $this->assertContains(\Throwable::class, $parents);
    }

    // -----------------------------------------------------------------
    // RuntimeException
    // -----------------------------------------------------------------

    #[Test]
    public function runtimeExceptionExtendsPhpRuntimeException(): void
    {
        $e = new RuntimeException('test');
        $this->assertInstanceOf(\RuntimeException::class, $e);
    }

    #[Test]
    public function runtimeExceptionImplementsBaseException(): void
    {
        $e = new RuntimeException('test');
        $this->assertInstanceOf(BaseException::class, $e);
    }

    #[Test]
    public function runtimeExceptionCanBeThrown(): void
    {
        $this->expectException(RuntimeException::class);
        throw new RuntimeException('boom');
    }

    // -----------------------------------------------------------------
    // SecurityException
    // -----------------------------------------------------------------

    #[Test]
    public function securityExceptionExtendsRuntimeException(): void
    {
        $e = new SecurityException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function securityExceptionCanBeThrown(): void
    {
        $this->expectException(SecurityException::class);
        throw new SecurityException('security fail');
    }

    // -----------------------------------------------------------------
    // AuthenticationException — inheritance
    // -----------------------------------------------------------------

    #[Test]
    public function authenticationExceptionExtendsRuntimeException(): void
    {
        $e = new AuthenticationException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function authenticationExceptionDefaultHttpCodeIs403(): void
    {
        $e = new AuthenticationException('test');
        $this->assertSame(403, $e->getHttpCode());
    }

    // -----------------------------------------------------------------
    // AuthenticationException — static factories
    // -----------------------------------------------------------------

    #[Test]
    public function forUnknownAuthenticatorIncludesAlias(): void
    {
        $e = AuthenticationException::forUnknownAuthenticator('jwt');
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertStringContainsString('jwt', $e->getMessage());
    }

    #[Test]
    public function forInvalidUserReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forInvalidUser();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    #[Test]
    public function forBannedUserReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forBannedUser();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertStringContainsStringIgnoringCase('ban', $e->getMessage());
    }

    #[Test]
    public function forInvalidCredentialsReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forInvalidCredentials();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    #[Test]
    public function forNoPasswordReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forNoPassword();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    #[Test]
    public function forNoEntityProvidedReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forNoEntityProvided();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    #[Test]
    public function forUnsetPasswordLengthReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forUnsetPasswordLength();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    #[Test]
    public function forHIBPCurlFailWrapsThrowable(): void
    {
        $cause = new \RuntimeException('curl error');
        $e     = AuthenticationException::forHIBPCurlFail($cause);

        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertSame($cause, $e->getPrevious());
        $this->assertStringContainsString('curl error', $e->getMessage());
    }

    #[Test]
    public function forTooManyRequestsHttpCodeIs429(): void
    {
        $e = AuthenticationException::forTooManyRequests();
        $this->assertSame(429, $e->getHttpCode());
    }

    #[Test]
    public function forTooManyRequestsReturnsAuthenticationException(): void
    {
        $e = AuthenticationException::forTooManyRequests();
        $this->assertInstanceOf(AuthenticationException::class, $e);
        $this->assertNotEmpty($e->getMessage());
    }

    // -----------------------------------------------------------------
    // AuthorizationException
    // -----------------------------------------------------------------

    #[Test]
    public function authorizationExceptionExtendsRuntimeException(): void
    {
        $e = new AuthorizationException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function authorizationExceptionCanBeThrown(): void
    {
        $this->expectException(AuthorizationException::class);
        throw new AuthorizationException('not allowed');
    }

    // -----------------------------------------------------------------
    // GroupException
    // -----------------------------------------------------------------

    #[Test]
    public function groupExceptionExtendsRuntimeException(): void
    {
        $e = new GroupException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function groupExceptionCanBeThrown(): void
    {
        $this->expectException(GroupException::class);
        throw new GroupException('bad group');
    }

    // -----------------------------------------------------------------
    // LogicException
    // -----------------------------------------------------------------

    #[Test]
    public function logicExceptionExtendsPhpLogicException(): void
    {
        $e = new LogicException('test');
        $this->assertInstanceOf(\LogicException::class, $e);
    }

    #[Test]
    public function logicExceptionImplementsBaseException(): void
    {
        $e = new LogicException('test');
        $this->assertInstanceOf(BaseException::class, $e);
    }

    #[Test]
    public function logicExceptionCanBeThrown(): void
    {
        $this->expectException(LogicException::class);
        throw new LogicException('logic fail');
    }

    // -----------------------------------------------------------------
    // InvalidArgumentException
    // -----------------------------------------------------------------

    #[Test]
    public function invalidArgumentExceptionExtendsLogicException(): void
    {
        $e = new InvalidArgumentException('test');
        $this->assertInstanceOf(LogicException::class, $e);
    }

    #[Test]
    public function invalidArgumentExceptionImplementsBaseException(): void
    {
        $e = new InvalidArgumentException('test');
        $this->assertInstanceOf(BaseException::class, $e);
    }

    #[Test]
    public function invalidArgumentExceptionCanBeThrown(): void
    {
        $this->expectException(InvalidArgumentException::class);
        throw new InvalidArgumentException('bad arg');
    }

    // -----------------------------------------------------------------
    // PermissionException
    // -----------------------------------------------------------------

    #[Test]
    public function permissionExceptionExtendsRuntimeException(): void
    {
        $e = new PermissionException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function permissionExceptionCanBeThrown(): void
    {
        $this->expectException(PermissionException::class);
        throw new PermissionException('no permission');
    }

    // -----------------------------------------------------------------
    // UserNotFoundException
    // -----------------------------------------------------------------

    #[Test]
    public function userNotFoundExceptionExtendsRuntimeException(): void
    {
        $e = new UserNotFoundException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function userNotFoundExceptionCanBeThrown(): void
    {
        $this->expectException(UserNotFoundException::class);
        throw new UserNotFoundException('user not found');
    }

    // -----------------------------------------------------------------
    // ValidationException
    // -----------------------------------------------------------------

    #[Test]
    public function validationExceptionExtendsRuntimeException(): void
    {
        $e = new ValidationException('test');
        $this->assertInstanceOf(RuntimeException::class, $e);
    }

    #[Test]
    public function validationExceptionCanBeThrown(): void
    {
        $this->expectException(ValidationException::class);
        throw new ValidationException('validation failed');
    }

    // -----------------------------------------------------------------
    // All exception classes can be caught as BaseException
    // -----------------------------------------------------------------

    #[Test]
    public function allRuntimeBasedExceptionsAreCatchableAsBaseException(): void
    {
        $classes = [
            RuntimeException::class,
            SecurityException::class,
            AuthenticationException::class,
            AuthorizationException::class,
            GroupException::class,
            PermissionException::class,
            UserNotFoundException::class,
            ValidationException::class,
        ];

        foreach ($classes as $class) {
            $caught = false;
            try {
                throw new $class('test');
            } catch (BaseException) {
                $caught = true;
            }
            $this->assertTrue($caught, "{$class} must be catchable as BaseException");
        }
    }

    #[Test]
    public function logicBasedExceptionsAreCatchableAsBaseException(): void
    {
        $classes = [
            LogicException::class,
            InvalidArgumentException::class,
        ];

        foreach ($classes as $class) {
            $caught = false;
            try {
                throw new $class('test');
            } catch (BaseException) {
                $caught = true;
            }
            $this->assertTrue($caught, "{$class} must be catchable as BaseException");
        }
    }
}
