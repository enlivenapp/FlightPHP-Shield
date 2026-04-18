<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Cycle\ORM\EntityManager;
use Cycle\ORM\ORMInterface;
use Enlivenapp\FlightShield\Entities\AuthPermission;
use flight\commands\AbstractBaseCommand;

class ShieldPermissionCommand extends AbstractBaseCommand
{
    public function __construct(array $config)
    {
        parent::__construct('shield:permission', 'Manage Shield permissions', $config);

        $this
            ->argument('[action]', 'Action: list, create, update, delete')
            ->option('-a --alias', 'Permission alias')
            ->option('-d --description', 'Permission description')
            ->usage(
                '<bold>  shield:permission list</end><eol/>' .
                '<bold>  shield:permission create</end> <comment>-a posts.create -d "Create posts"</end><eol/>' .
                '<bold>  shield:permission update</end> <comment>-a posts.create -d "Create blog posts"</end><eol/>' .
                '<bold>  shield:permission delete</end> <comment>-a posts.create</end>'
            );
    }

    public function execute(?string $action = null, ?string $alias = null, ?string $description = null): void
    {
        $io = $this->app()->io();

        if ($action === null) {
            $this->showHelp();
            return;
        }

        $orm = $this->getOrm();

        match ($action) {
            'list'   => $this->listPermissions($orm, $io),
            'create' => $this->createPermission($orm, $io, $alias, $description),
            'update' => $this->updatePermission($orm, $io, $alias, $description),
            'delete' => $this->deletePermission($orm, $io, $alias),
            default  => $io->error("Unknown action: {$action}", true),
        };
    }

    protected function listPermissions(ORMInterface $orm, $io): void
    {
        $repo = $orm->getRepository(AuthPermission::class);
        $all = $repo->select()->orderBy('alias')->fetchAll();

        if (empty($all)) {
            $io->write('No permissions found.', true);
            return;
        }

        $io->bold('Alias			Description', true);
        foreach ($all as $perm) {
            $io->write("{$perm->alias}			{$perm->description}", true);
        }
    }

    protected function createPermission(ORMInterface $orm, $io, ?string $alias, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $repo = $orm->getRepository(AuthPermission::class);
        $existing = $repo->select()->where('alias', $alias)->fetchOne();

        if ($existing !== null) {
            $io->error("Permission \"{$alias}\" already exists.", true);
            return;
        }

        $perm = new AuthPermission();
        $perm->alias = $alias;
        $perm->description = $description;
        $perm->created_at = new \DateTimeImmutable();
        $perm->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($perm)->run();

        $io->info("Permission \"{$alias}\" created.", true);
    }

    protected function updatePermission(ORMInterface $orm, $io, ?string $alias, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $repo = $orm->getRepository(AuthPermission::class);
        $perm = $repo->select()->where('alias', $alias)->fetchOne();

        if ($perm === null) {
            $io->error("Permission \"{$alias}\" not found.", true);
            return;
        }

        if ($description !== null) {
            $perm->description = $description;
        }

        $perm->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($perm)->run();

        $io->info("Permission \"{$alias}\" updated.", true);
    }

    protected function deletePermission(ORMInterface $orm, $io, ?string $alias): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $repo = $orm->getRepository(AuthPermission::class);
        $perm = $repo->select()->where('alias', $alias)->fetchOne();

        if ($perm === null) {
            $io->error("Permission \"{$alias}\" not found.", true);
            return;
        }

        $em = new EntityManager($orm);
        $em->delete($perm)->run();

        $io->info("Permission \"{$alias}\" deleted.", true);
    }

    protected function getOrm(): ORMInterface
    {
        return \Flight::app()->orm();
    }
}
