<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Services;

use Enlivenapp\FlightShield\Models\AuthGroup;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Result;

/**
 * High-level user administration API.
 *
 * The one-stop shop for app-level user management: listing, finding,
 * creating, profile updates, activation toggling, and soft deletes.
 * All password hashing/validation and identity handling use the
 * configured Shield settings.
 *
 * Models are an implementation detail here - calling code should never
 * need to instantiate Shield models directly.
 */
class UserManagement
{
    private const USERNAME_MAX_LENGTH = 30;
    private const USERNAME_MIN_LENGTH = 3;

    protected \PDO $pdo;
    /** @var array<string, mixed> */
    protected array $config;
    protected Passwords $passwords;
    private bool $ownsTransaction = false;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(\PDO $pdo, array $config = [])
    {
        $this->pdo = $pdo;
        $this->config = $config;
        $this->passwords = new Passwords($config['passwords'] ?? []);
    }

    /**
     * PDO::inTransaction() is a getter whose value changes as a transaction
     * is begun, committed, or rolled back. Marking this wrapper impure stops
     * PHPStan folding every call to the first result.
     *
     * @phpstan-impure
     */
    private function hasActiveTransaction(): bool
    {
        return $this->pdo->inTransaction();
    }

    /**
     * Begin a transaction unless one is already active. Returns true when
     * this call owns the transaction it started, so the caller knows whether
     * it may roll back.
     *
     * @phpstan-impure
     */
    private function beginTransactionIfNeeded(): bool
    {
        if ($this->hasActiveTransaction()) {
            return false;
        }

        $this->pdo->beginTransaction();

        return true;
    }

    /**
     * Roll back the transaction when this call started it and it is still
     * active. Taking the flag as a parameter keeps PHPStan from treating it
     * as a constant.
     *
     * @phpstan-impure
     */
    private function rollBackIfOwned(bool $owns): void
    {
        if ($owns && $this->hasActiveTransaction()) {
            $this->pdo->rollBack();
        }
    }

    // -----------------------------------------------------------------
    // Reading users
    // -----------------------------------------------------------------

    /**
     * Paginated list of non-deleted users.
     *
     * When $includeSuperadmins is false, users in the superadmin group
     * are excluded. Pass the current user's inGroup('superadmin') result
     * so superadmins see everyone and admins see only non-superadmins.
     *
     * @return User[]
     */
    public function paginated(int $page = 1, int $perPage = 20, bool $includeSuperadmins = false): array
    {
        return (new User($this->pdo))
            ->findAllPaginated($page, $perPage, $includeSuperadmins);
    }

    /**
     * Count non-deleted users.
     *
     * See paginated() for the $includeSuperadmins contract.
     */
    public function count(bool $includeSuperadmins = false): int
    {
        return (new User($this->pdo))->countAll($includeSuperadmins);
    }

    /**
     * Find a single non-deleted user by ID.
     *
     * When $includeSuperadmins is false and the target is a superadmin,
     * returns null - as if the user doesn't exist.
     */
    public function find(int|string $id, bool $includeSuperadmins = true): ?User
    {
        return (new User($this->pdo))->findById($id, $includeSuperadmins);
    }

    /**
     * The user's login email address.
     */
    public function getEmail(User $user): ?string
    {
        $identity = $this->getEmailIdentity($user);

        return $identity?->secret;
    }

    // -----------------------------------------------------------------
    // Creating users
    // -----------------------------------------------------------------

    /**
     * Create a user with an email/password identity and group membership.
     *
     * Validates password strength against the configured validators and
     * rejects duplicate email addresses.
     *
     * When $username is empty a unique one is derived from the email local
     * part. A supplied username is used as-is and rejected when taken.
     *
     * When $requiresActivation is true the user is created inactive; the
     * caller is responsible for sending an activation link and activating
     * the account later.
     *
     * On success the created User is returned via extraInfo().
     */
    public function create(
        string $username,
        string $email,
        string $password,
        ?string $group = null,
        bool $requiresActivation = false
    ): Result {
        $username = trim($username);
        $email = trim($email);

        if ($email === '' || ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->fail('A valid email address is required.');
        }

        $existing = (new UserIdentity($this->pdo))
            ->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

        if ($existing !== null) {
            return $this->fail('Email address is already in use.');
        }

        $derived = $username === '';
        $base    = $derived ? $this->deriveUsername($email) : $username;

        if ($derived) {
            $username = $this->uniqueUsername($base);
        } elseif ($this->usernameExists($username)) {
            return $this->fail('Username is already in use.');
        }

        $tempUser = new User();
        $tempUser->username = $username;

        $passResult = $this->passwords->check($password, $tempUser);
        if (! $passResult->isOK()) {
            return $this->fail($passResult->reason() ?? 'Password does not meet requirements.');
        }

        $groupAlias = $group ?? $this->config['default_group'] ?? 'user';

        $groupInfo = (new AuthGroup($this->pdo))
            ->eq('alias', strtolower($groupAlias))
            ->find();

        if (! $groupInfo->isHydrated()) {
            return $this->fail("Group '{$groupAlias}' does not exist.");
        }

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        // A derived username can still lose a race with a concurrent signup,
        // so retry it with a suffix. An explicit username gets a plain error.
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->ownsTransaction = $this->beginTransactionIfNeeded();

            try {
                $user = new User($this->pdo);
                $user->username   = $username;
                $user->active     = ! $requiresActivation;
                $user->created_at = $now;
                $user->updated_at = $now;
                $user->insert();

                (new UserIdentity($this->pdo))->createEmailIdentity($user, [
                    'email'         => $email,
                    'password_hash' => $this->passwords->hash($password),
                ]);

                $user->addGroup($groupAlias);

                if ($this->ownsTransaction) {
                    $this->pdo->commit();
                }

                return (new Result())
                    ->setSuccess(true)
                    ->setExtraInfo($user);
            } catch (\Exception $e) {
                $this->rollBackIfOwned($this->ownsTransaction);

                if (! $derived) {
                    return $this->fail('Username is already in use.');
                }

                $username = $this->suffixedUsername($base, $attempt + 2);
            }
        }

        return $this->fail('Account could not be created. Please try again.');
    }

    // -----------------------------------------------------------------
    // Updating users
    // -----------------------------------------------------------------

    /**
     * Update a user's profile: username, email, and/or password.
     *
     * Only provided keys are applied. An empty password value leaves the
     * current password untouched. Password changes run through the
     * configured strength validators before hashing.
     *
     * Note: identity saves are issued unconditionally (never gated on
     * ActiveRecord::isDirty()) because writes to the models' declared
     * typed properties do not register in ActiveRecord's dirty tracker.
     *
     * Accepted $data keys: 'username', 'email', 'password'.
     */
    /**
     * @param array<string, mixed> $data
     */
    public function updateProfile(User $user, array $data): Result
    {
        $hasEmail = isset($data['email']);
        $hasPassword = isset($data['password']) && $data['password'] !== '';

        if (array_key_exists('username', $data)) {
            $username = trim((string) $data['username']);

            if ($username === '') {
                return $this->fail('Username cannot be empty.');
            }

            if ($username !== $user->username && $this->usernameExists($username)) {
                return $this->fail('Username is already in use.');
            }

            $user->username = $username;
        }

        if (!$hasEmail && !$hasPassword) {
            return $this->saveProfile($user, null);
        }

        $identity = $this->getEmailIdentity($user);

        if ($identity === null) {
            return $this->fail('User has no email/password identity to update.');
        }

        if ($hasEmail) {
            $email = trim((string) $data['email']);

            if ($email === '' || ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return $this->fail('A valid email address is required.');
            }

            $existing = (new UserIdentity($this->pdo))
                ->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

            if ($existing !== null && $existing->user_id !== $user->id) {
                return $this->fail('Email address is already in use.');
            }

            $identity->secret = $email;
        }

        if ($hasPassword) {
            $passResult = $this->passwords->check($data['password'], $user);
            if (! $passResult->isOK()) {
                return $this->fail($passResult->reason() ?? 'Password does not meet requirements.');
            }

            $identity->secret2 = $this->passwords->hash($data['password']);
        }

        return $this->saveProfile($user, $identity);
    }

    /**
     * Activate or deactivate a user.
     *
     * Inactive users cannot log in. A database failure comes back as a
     * normal error rather than escaping as a server error.
     *
     * Note: 'active' is pushed through dirty() explicitly - boolean flips
     * (true -> false) on entities created via insert() are otherwise
     * invisible to ActiveRecord's loose property/data comparison.
     */
    public function setActive(User $user, bool $active): Result
    {
        if ($active) {
            $user->activate();
        } else {
            $user->deactivate();
        }

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->updated_at = $now;
        $user->dirty(['active' => $user->active, 'updated_at' => $now]);

        try {
            $user->save();
        } catch (\Exception $e) {
            return $this->fail('The account status could not be saved. Please try again.');
        }

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    /**
     * Soft-delete a user. The record is preserved but excluded
     * from all future queries. A database failure comes back as a normal
     * error rather than escaping as a server error.
     */
    public function delete(User $user): Result
    {
        try {
            $user->softDelete();
        } catch (\Exception $e) {
            return $this->fail('The account could not be deleted. Please try again.');
        }

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    /**
     * Write a user's profile changes.
     *
     * A database failure comes back as a normal error rather than escaping
     * as a server error.
     */
    protected function saveProfile(User $user, ?UserIdentity $identity): Result
    {
        $this->ownsTransaction = $this->beginTransactionIfNeeded();

        try {
            $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

            if ($identity !== null) {
                $identity->updated_at = $now;
                $identity->save();
            }

            $user->updated_at = $now;
            $user->save();

            if ($this->ownsTransaction) {
                $this->pdo->commit();
            }
        } catch (\Exception $e) {
            $this->rollBackIfOwned($this->ownsTransaction);

            return $this->fail('The profile could not be saved. Please try again.');
        }

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    // -----------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------

    /**
     * Whether any account already uses this username.
     *
     * Soft-deleted rows count here: the unique index still covers them.
     */
    protected function usernameExists(string $username): bool
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM users WHERE username = ?');
        $stmt->execute([$username]);

        return (int) $stmt->fetchColumn() > 0;
    }

    /**
     * Build an allowed username from the email local part.
     */
    protected function deriveUsername(string $email): string
    {
        $local = strstr($email, '@', true);
        $local = $local === false ? $email : $local;

        $base = preg_replace('/[^a-zA-Z0-9.]/', '', $local);
        $base = is_string($base) ? trim($base, '.') : '';

        if (strlen($base) < self::USERNAME_MIN_LENGTH) {
            $base = 'user' . $base;
        }

        return substr($base, 0, self::USERNAME_MAX_LENGTH);
    }

    /**
     * Append a number to a derived username until it is free.
     */
    protected function uniqueUsername(string $base): string
    {
        $candidate = $base;

        for ($suffix = 2; $this->usernameExists($candidate); $suffix++) {
            $candidate = $this->suffixedUsername($base, $suffix);
        }

        return $candidate;
    }

    protected function suffixedUsername(string $base, int $suffix): string
    {
        $tail = (string) $suffix;

        return substr($base, 0, self::USERNAME_MAX_LENGTH - strlen($tail)) . $tail;
    }

    protected function getEmailIdentity(User $user): ?UserIdentity
    {
        return (new UserIdentity($this->pdo))->getEmailIdentity($user);
    }

    protected function fail(string $reason): Result
    {
        return (new Result())
            ->setSuccess(false)
            ->setReason($reason);
    }
}
