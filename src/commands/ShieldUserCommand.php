<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use flight\commands\AbstractBaseCommand;

class ShieldUserCommand extends AbstractBaseCommand
{
    public function __construct(array $config)
    {
        parent::__construct('shield:user', 'Manage Shield users', $config);

        $this
            ->argument('[action]', 'Action: create, activate, deactivate, delete, password, changename, changeemail, list, addgroup, removegroup')
            ->option('-n --name', 'Username')
            ->option('-e --email', 'User email')
            ->option('-g --group', 'Group name')
            ->option('--new-name', 'New username (for changename)')
            ->option('--new-email', 'New email (for changeemail)')
            ->usage(
                '<bold>  shield:user create</end> <comment>-n admin -e admin@example.com -g superadmin</end><eol/>' .
                '<bold>  shield:user activate</end> <comment>-e user@example.com</end><eol/>' .
                '<bold>  shield:user deactivate</end> <comment>-n username</end><eol/>' .
                '<bold>  shield:user delete</end> <comment>-e user@example.com</end><eol/>' .
                '<bold>  shield:user password</end> <comment>-n username</end><eol/>' .
                '<bold>  shield:user changename</end> <comment>-n username --new-name newusername</end><eol/>' .
                '<bold>  shield:user changeemail</end> <comment>-n username --new-email new@example.com</end><eol/>' .
                '<bold>  shield:user list</end><eol/>' .
                '<bold>  shield:user addgroup</end> <comment>-n username -g admin</end><eol/>' .
                '<bold>  shield:user removegroup</end> <comment>-n username -g admin</end>'
            );
    }

    public function execute(
        ?string $action = null,
        ?string $name = null,
        ?string $email = null,
        ?string $group = null,
        ?string $newName = null,
        ?string $newEmail = null
    ): void {
        $io = $this->app()->io();

        if ($action === null) {
            $this->showHelp();
            return;
        }

        match ($action) {
            'create'      => $this->createUser($io, $name, $email, $group),
            'activate'    => $this->setActive($io, $name, $email, true),
            'deactivate'  => $this->setActive($io, $name, $email, false),
            'delete'      => $this->deleteUser($io, $name, $email),
            'password'    => $this->changePassword($io, $name, $email),
            'changename'  => $this->changeName($io, $name, $email, $newName),
            'changeemail' => $this->changeEmail($io, $name, $email, $newEmail),
            'list'        => $this->listUsers($io),
            'addgroup'    => $this->modifyGroup($io, $name, $email, $group, 'add'),
            'removegroup' => $this->modifyGroup($io, $name, $email, $group, 'remove'),
            default       => $io->error("Unknown action: {$action}", true),
        };
    }

    protected function createUser($io, ?string $name, ?string $email, ?string $group): void
    {
        if ($name === null) {
            $io->write('Username: ', false);
            $name = trim(fgets(STDIN) ?: '');
        }
        if ($email === null) {
            $io->write('Email: ', false);
            $email = trim(fgets(STDIN) ?: '');
        }

        system('stty -echo');
        $io->write('Password: ', false);
        $password = trim(fgets(STDIN) ?: '');

        $io->write('Confirm password: ', false);
        $confirm = trim(fgets(STDIN) ?: '');
        system('stty echo');
        $io->write('', true);

        if ($password !== $confirm) {
            $io->error('Passwords do not match.', true);
            return;
        }

        $group = $group ?? 'user';

        $passwords = new Passwords();
        $hash = $passwords->hash($password);

        $user = new User(\Flight::db());
        $user->username   = $name ?: null;
        $user->active     = true;
        $user->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->insert();

        $identity = new UserIdentity(\Flight::db());
        $identity->user_id    = $user->id;
        $identity->type       = UserIdentity::TYPE_EMAIL_PASSWORD;
        $identity->secret     = $email;
        $identity->secret2    = $hash;
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $user->addGroup($group);

        $io->info("User \"{$name}\" created and added to group \"{$group}\".", true);
    }

    protected function setActive($io, ?string $name, ?string $email, bool $active): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        $user->active     = $active;
        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->save();

        $status = $active ? 'activated' : 'deactivated';
        $io->info("User \"{$user->username}\" {$status}.", true);
    }

    protected function deleteUser($io, ?string $name, ?string $email): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        $user->deleted_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->save();

        $io->info("User \"{$user->username}\" deleted (soft).", true);
    }

    protected function changePassword($io, ?string $name, ?string $email): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        system('stty -echo');
        $io->write('New password: ', false);
        $password = trim(fgets(STDIN) ?: '');

        $io->write('Confirm password: ', false);
        $confirm = trim(fgets(STDIN) ?: '');
        system('stty echo');
        $io->write('', true);

        if ($password !== $confirm) {
            $io->error('Passwords do not match.', true);
            return;
        }

        $passwords = new Passwords();

        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getEmailIdentity($user);

        if ($identity === null) {
            $io->error('No email identity found for this user.', true);
            return;
        }

        $identity->secret2    = $passwords->hash($password);
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->save();

        $io->info("Password updated for \"{$user->username}\".", true);
    }

    protected function changeName($io, ?string $name, ?string $email, ?string $newName): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        if ($newName === null) {
            $io->error('New username is required (--new-name newusername).', true);
            return;
        }

        $oldName = $user->username;
        $user->username   = $newName;
        $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $user->save();

        $io->info("Username changed from \"{$oldName}\" to \"{$newName}\".", true);
    }

    protected function changeEmail($io, ?string $name, ?string $email, ?string $newEmail): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        if ($newEmail === null) {
            $io->error('New email is required (--new-email new@example.com).', true);
            return;
        }

        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getEmailIdentity($user);

        if ($identity === null) {
            $io->error('No email identity found for this user.', true);
            return;
        }

        $oldEmail = $identity->secret;
        $identity->secret     = $newEmail;
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->save();

        $io->info("Email changed from \"{$oldEmail}\" to \"{$newEmail}\".", true);
    }

    protected function listUsers($io): void
    {
        $users = (new User(\Flight::db()))->isNull('deleted_at')->findAll();

        $io->bold('ID	Username	Active', true);
        foreach ($users as $user) {
            $active = $user->active ? 'Yes' : 'No';
            $io->write("{$user->id}	{$user->username}	{$active}", true);
        }
    }

    protected function modifyGroup($io, ?string $name, ?string $email, ?string $group, string $action): void
    {
        $user = $this->findUser($io, $name, $email);
        if ($user === null) return;

        if ($group === null) {
            $io->error('Group is required (-g groupname).', true);
            return;
        }

        if ($action === 'add') {
            $user->addGroup($group);
            $io->info("User \"{$user->username}\" added to group \"{$group}\".", true);
        } else {
            $user->removeGroup($group);
            $io->info("User \"{$user->username}\" removed from group \"{$group}\".", true);
        }
    }

    protected function findUser($io, ?string $name, ?string $email): ?User
    {
        $userModel = new User(\Flight::db());

        if ($name !== null) {
            $user = $userModel->findByCredentials(['username' => $name]);
        } elseif ($email !== null) {
            $user = $userModel->findByCredentials(['email' => $email]);
        } else {
            $io->error('Specify -n username or -e email.', true);
            return null;
        }

        if ($user === null) {
            $io->error('User not found.', true);
        }

        return $user;
    }
}
