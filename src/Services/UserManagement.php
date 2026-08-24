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
 * Models are an implementation detail here — calling code should never
 * need to instantiate Shield models directly.
 */
class UserManagement
{
    protected \PDO $pdo;
    protected array $config;
    protected Passwords $passwords;

    public function __construct(\PDO $pdo, array $config = [])
    {
        $this->pdo = $pdo;
        $this->config = $config;
        $this->passwords = new Passwords($config['passwords'] ?? []);
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
     * returns null — as if the user doesn't exist.
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
     * On success the created User is returned via extraInfo().
     */
    public function create(
        string $username,
        string $email,
        string $password,
        ?string $group = null
    ): Result {
        $username = trim($username);
        $email = trim($email);

        if ($username === '') {
            return $this->fail('Username is required.');
        }

        if ($email === '' || ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->fail('A valid email address is required.');
        }

        $existing = (new UserIdentity($this->pdo))
            ->getIdentityBySecret(UserIdentity::TYPE_EMAIL_PASSWORD, $email);

        if ($existing !== null) {
            return $this->fail('Email address is already in use.');
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

        $user = new User($this->pdo);
        $user->username   = $username;
        $user->active     = true;
        $user->created_at = $now;
        $user->updated_at = $now;
        $user->insert();

        (new UserIdentity($this->pdo))->createEmailIdentity($user, [
            'email'         => $email,
            'password_hash' => $this->passwords->hash($password),
        ]);

        $user->addGroup($groupAlias);

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
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
    public function updateProfile(User $user, array $data): Result
    {
        $hasEmail = isset($data['email']);
        $hasPassword = isset($data['password']) && $data['password'] !== '';

        if (array_key_exists('username', $data)) {
            $username = trim((string) $data['username']);
            if ($username === '') {
                return $this->fail('Username cannot be empty.');
            }
            $user->username = $username;
        }

        if (!$hasEmail && !$hasPassword) {
            $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
            $user->save();

            return (new Result())
                ->setSuccess(true)
                ->setExtraInfo($user);
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

        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->save();

        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->save();

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    /**
     * Activate or deactivate a user.
     *
     * Inactive users cannot log in.
     *
     * Note: 'active' is pushed through dirty() explicitly — boolean flips
     * (true -> false) on entities created via insert() are otherwise
     * invisible to ActiveRecord's loose property/data comparison.
     */
    public function setActive(User $user, bool $active): void
    {
        if ($active) {
            $user->activate();
        } else {
            $user->deactivate();
        }

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->updated_at = $now;
        $user->dirty(['active' => $user->active, 'updated_at' => $now]);
        $user->save();
    }

    /**
     * Soft-delete a user. The record is preserved but excluded
     * from all future queries.
     */
    public function delete(User $user): void
    {
        $user->softDelete();
    }

    // -----------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------

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
