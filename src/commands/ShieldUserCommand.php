<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Cycle\ORM\EntityManager;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use Enlivenapp\FlightShield\Repositories\UserRepository;
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

        $orm = $this->getOrm();

        match ($action) {
            'create'      => $this->createUser($orm, $io, $name, $email, $group),
            'activate'    => $this->setActive($orm, $io, $name, $email, true),
            'deactivate'  => $this->setActive($orm, $io, $name, $email, false),
            'delete'      => $this->deleteUser($orm, $io, $name, $email),
            'password'    => $this->changePassword($orm, $io, $name, $email),
            'changename'  => $this->changeName($orm, $io, $name, $email, $newName),
            'changeemail' => $this->changeEmail($orm, $io, $name, $email, $newEmail),
            'list'        => $this->listUsers($orm, $io),
            'addgroup'    => $this->modifyGroup($orm, $io, $name, $email, $group, 'add'),
            'removegroup' => $this->modifyGroup($orm, $io, $name, $email, $group, 'remove'),
            default       => $io->error("Unknown action: {$action}", true),
        };
    }

    protected function createUser($orm, $io, ?string $name, ?string $email, ?string $group): void
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

        $user = new User();
        $user->username   = $name ?: null;
        $user->active     = true;
        $user->created_at = new \DateTimeImmutable();
        $user->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($user)->run();

        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_EMAIL_PASSWORD;
        $identity->secret  = $email;
        $identity->secret2 = $hash;
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        $user->addGroup($group, $orm);

        $io->info("User \"{$name}\" created and added to group \"{$group}\".", true);
    }

    protected function setActive($orm, $io, ?string $name, ?string $email, bool $active): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
        if ($user === null) return;

        $user->active = $active;
        $user->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($user)->run();

        $status = $active ? 'activated' : 'deactivated';
        $io->info("User \"{$user->username}\" {$status}.", true);
    }

    protected function deleteUser($orm, $io, ?string $name, ?string $email): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
        if ($user === null) return;

        $user->deleted_at = new \DateTimeImmutable();
        $user->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($user)->run();

        $io->info("User \"{$user->username}\" deleted (soft).", true);
    }

    protected function changePassword($orm, $io, ?string $name, ?string $email): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
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

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $orm->getRepository(UserIdentity::class);
        $identity = $identityRepo->getEmailIdentity($user);

        if ($identity === null) {
            $io->error('No email identity found for this user.', true);
            return;
        }

        $identity->secret2 = $passwords->hash($password);
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        $io->info("Password updated for \"{$user->username}\".", true);
    }

    protected function changeName($orm, $io, ?string $name, ?string $email, ?string $newName): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
        if ($user === null) return;

        if ($newName === null) {
            $io->error('New username is required (--new-name newusername).', true);
            return;
        }

        $oldName = $user->username;
        $user->username = $newName;
        $user->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($user)->run();

        $io->info("Username changed from \"{$oldName}\" to \"{$newName}\".", true);
    }

    protected function changeEmail($orm, $io, ?string $name, ?string $email, ?string $newEmail): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
        if ($user === null) return;

        if ($newEmail === null) {
            $io->error('New email is required (--new-email new@example.com).', true);
            return;
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $orm->getRepository(UserIdentity::class);
        $identity = $identityRepo->getEmailIdentity($user);

        if ($identity === null) {
            $io->error('No email identity found for this user.', true);
            return;
        }

        $oldEmail = $identity->secret;
        $identity->secret = $newEmail;
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        $io->info("Email changed from \"{$oldEmail}\" to \"{$newEmail}\".", true);
    }

    protected function listUsers($orm, $io): void
    {
        /** @var UserRepository $repo */
        $repo = $orm->getRepository(User::class);
        $users = $repo->select()->where('deleted_at', null)->fetchAll();

        $io->bold('ID	Username	Active', true);
        foreach ($users as $user) {
            $active = $user->active ? 'Yes' : 'No';
            $io->write("{$user->id}	{$user->username}	{$active}", true);
        }
    }

    protected function modifyGroup($orm, $io, ?string $name, ?string $email, ?string $group, string $action): void
    {
        $user = $this->findUser($orm, $io, $name, $email);
        if ($user === null) return;

        if ($group === null) {
            $io->error('Group is required (-g groupname).', true);
            return;
        }

        if ($action === 'add') {
            $user->addGroup($group, $orm);
            $io->info("User \"{$user->username}\" added to group \"{$group}\".", true);
        } else {
            $user->removeGroup($group, $orm);
            $io->info("User \"{$user->username}\" removed from group \"{$group}\".", true);
        }
    }

    protected function findUser($orm, $io, ?string $name, ?string $email): ?User
    {
        /** @var UserRepository $repo */
        $repo = $orm->getRepository(User::class);

        if ($name !== null) {
            $user = $repo->findByCredentials(['username' => $name]);
        } elseif ($email !== null) {
            $user = $repo->findByCredentials(['email' => $email]);
        } else {
            $io->error('Specify -n username or -e email.', true);
            return null;
        }

        if ($user === null) {
            $io->error('User not found.', true);
        }

        return $user;
    }

    protected function getOrm(): \Cycle\ORM\ORMInterface
    {
        return \Flight::app()->orm();
    }
}
