<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests;

use flight\Engine;
use PDO;

class PdoHolder
{
    public static ?PDO $pdo = null;
}

class TestHelper
{
    /**
     * Create a SQLite in-memory database with the full shield schema.
     */
    public static function createDatabase(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(30) DEFAULT NULL,
            status VARCHAR(255) DEFAULT NULL,
            status_message VARCHAR(255) DEFAULT NULL,
            active BOOLEAN DEFAULT 0,
            last_active DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL,
            deleted_at DATETIME DEFAULT NULL
        )');

        $pdo->exec('CREATE TABLE auth_identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type VARCHAR(255) NOT NULL,
            name VARCHAR(255) DEFAULT NULL,
            secret VARCHAR(255) NOT NULL,
            secret2 VARCHAR(255) DEFAULT NULL,
            expires DATETIME DEFAULT NULL,
            extra TEXT DEFAULT NULL,
            force_reset BOOLEAN DEFAULT 0,
            last_used_at DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )');

        $pdo->exec('CREATE TABLE auth_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address VARCHAR(255) NOT NULL,
            user_agent VARCHAR(255) DEFAULT NULL,
            id_type VARCHAR(255) NOT NULL,
            identifier VARCHAR(255) NOT NULL,
            user_id INTEGER DEFAULT NULL,
            date DATETIME NOT NULL,
            success BOOLEAN NOT NULL
        )');

        $pdo->exec('CREATE TABLE auth_token_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address VARCHAR(255) NOT NULL,
            user_agent VARCHAR(255) DEFAULT NULL,
            id_type VARCHAR(255) NOT NULL,
            identifier VARCHAR(255) NOT NULL,
            user_id INTEGER DEFAULT NULL,
            date DATETIME NOT NULL,
            success BOOLEAN NOT NULL
        )');

        $pdo->exec('CREATE TABLE auth_remember_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            selector VARCHAR(255) NOT NULL,
            hashed_validator VARCHAR(255) NOT NULL,
            user_id INTEGER NOT NULL,
            expires DATETIME NOT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )');

        $pdo->exec('CREATE TABLE auth_groups_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_alias VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )');

        $pdo->exec('CREATE TABLE auth_permissions_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            permission VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )');

        $pdo->exec('CREATE TABLE auth_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias VARCHAR(255) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description VARCHAR(255) DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL
        )');

        $pdo->exec('CREATE TABLE auth_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias VARCHAR(255) NOT NULL,
            description VARCHAR(255) DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL
        )');

        $pdo->exec('CREATE TABLE auth_group_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_alias VARCHAR(255) NOT NULL,
            permission_alias VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT NULL
        )');

        return $pdo;
    }

    /**
     * Get the default shield config for tests.
     */
    public static function getConfig(): array
    {
        return [
            'default_authenticator' => 'session',
            'authenticators' => [
                'session' => \Enlivenapp\FlightShield\Authentication\Authenticators\Session::class,
                'tokens'  => \Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens::class,
                'hmac'    => \Enlivenapp\FlightShield\Authentication\Authenticators\HmacSha256::class,
            ],
            'authentication_chain' => ['session', 'tokens', 'hmac'],
            'session' => [
                'field'                => 'user',
                'allow_remembering'    => true,
                'remember_cookie_name' => 'remember',
                'remember_length'      => 30 * 86400,
            ],
            'passwords' => [
                'algorithm'      => PASSWORD_BCRYPT,
                'cost'           => 4, // low cost for fast tests
                'min_length'     => 8,
                'max_similarity' => 50,
                'validators'     => [
                    \Enlivenapp\FlightShield\Passwords\CompositionValidator::class,
                    \Enlivenapp\FlightShield\Passwords\NothingPersonalValidator::class,
                    \Enlivenapp\FlightShield\Passwords\DictionaryValidator::class,
                ],
            ],
            'token_header'          => 'Authorization',
            'hmac_header'           => 'Authorization',
            'unused_token_lifetime' => 3600 * 24 * 90,
            'rate_limiting' => [
                'enabled'         => true,
                'max_attempts'    => 10,
                'decay_minutes'   => 30,
                'lockout_minutes' => 30,
            ],
            'record_login_attempt' => 'all',
            'record_active_date'   => true,
            'allow_registration'   => true,
            'allow_magic_link'     => true,
            'magic_link_lifetime'  => 3600,
            'email_sender'         => null,
            'actions' => [
                'login'    => null,
                'register' => null,
            ],
            'valid_login_fields' => ['email'],
            'personal_fields'    => [],
            'default_group'      => 'user',
            'redirects' => [
                'login'             => '/auth/login',
                'logout'            => '/',
                'after_login'       => '/',
                'after_register'    => '/',
                'after_logout'      => '/auth/login',
                'force_reset'       => '/auth/reset-password',
                'permission_denied' => '/auth/login',
                'group_denied'      => '/auth/login',
            ],
        ];
    }

    /**
     * Create a test user in the database and return the user entity.
     */
    public static function createUser(
        PDO $pdo,
        string $email = 'test@example.com',
        string $password = 'password123',
        string $username = 'testuser',
        bool $active = true
    ): \Enlivenapp\FlightShield\Models\User {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $stmt = $pdo->prepare('INSERT INTO users (username, active, created_at, updated_at) VALUES (?, ?, ?, ?)');
        $stmt->execute([$username, $active ? 1 : 0, $now, $now]);
        $userId = (int) $pdo->lastInsertId();

        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
        $stmt = $pdo->prepare(
            'INSERT INTO auth_identities (user_id, type, secret, secret2, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $userId,
            \Enlivenapp\FlightShield\Models\UserIdentity::TYPE_EMAIL_PASSWORD,
            $email,
            $passwordHash,
            $now,
            $now,
        ]);

        $user = new \Enlivenapp\FlightShield\Models\User($pdo);
        $user->eq('id', $userId)->find();

        return $user;
    }

    /**
     * Register the PDO connection with Flight's static class.
     */
    public static function registerFlightDb(PDO $pdo): void
    {
        // Store the PDO in a static so the callback can access it
        PdoHolder::$pdo = $pdo;

        // Flight::register expects (name, className, params, callback)
        // We register PDO itself and use the callback to swap in our instance
        \Flight::register('db', PDO::class, ['sqlite::memory:'], function ($db) use ($pdo) {
            // This callback receives the auto-constructed instance but we ignore it
            // and replace via the loader's shared instances
        });

        // Directly set the instance in Flight's loader via the map method
        $app = \Flight::app();
        $app->set('db', $pdo);

        // Also store so Flight::db() returns our PDO
        // Use the Engine's __call → loader->load which checks instances first
        // We need to prime the loader's instance cache
        $loaderRef = new \ReflectionProperty($app, 'loader');
        $loaderRef->setAccessible(true);
        $loader = $loaderRef->getValue($app);

        $instancesRef = new \ReflectionProperty($loader, 'instances');
        $instancesRef->setAccessible(true);
        $instances = $instancesRef->getValue($loader);
        $instances['db'] = $pdo;
        $instancesRef->setValue($loader, $instances);
    }

    /**
     * Reset Flight state between tests.
     */
    public static function resetFlight(): void
    {
        $app = \Flight::app();
        $loaderRef = new \ReflectionProperty($app, 'loader');
        $loaderRef->setAccessible(true);
        $loader = $loaderRef->getValue($app);

        $instancesRef = new \ReflectionProperty($loader, 'instances');
        $instancesRef->setAccessible(true);
        $instancesRef->setValue($loader, []);
    }
}
