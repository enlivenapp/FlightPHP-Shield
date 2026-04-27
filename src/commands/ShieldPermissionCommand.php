<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Enlivenapp\FlightShield\Models\AuthPermission;
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

        match ($action) {
            'list'   => $this->listPermissions($io),
            'create' => $this->createPermission($io, $alias, $description),
            'update' => $this->updatePermission($io, $alias, $description),
            'delete' => $this->deletePermission($io, $alias),
            default  => $io->error("Unknown action: {$action}", true),
        };
    }

    protected function listPermissions($io): void
    {
        $all = (new AuthPermission(\Flight::db()))->order('alias ASC')->findAll();

        if (empty($all)) {
            $io->write('No permissions found.', true);
            return;
        }

        $io->bold('Alias			Description', true);
        foreach ($all as $perm) {
            $io->write("{$perm->alias}			{$perm->description}", true);
        }
    }

    protected function createPermission($io, ?string $alias, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $existing = (new AuthPermission(\Flight::db()))->eq('alias', $alias)->find();
        if ($existing->isHydrated()) {
            $io->error("Permission \"{$alias}\" already exists.", true);
            return;
        }

        $perm = new AuthPermission(\Flight::db());
        $perm->alias       = $alias;
        $perm->description = $description;
        $perm->created_at  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $perm->updated_at  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $perm->insert();

        $io->info("Permission \"{$alias}\" created.", true);
    }

    protected function updatePermission($io, ?string $alias, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $perm = (new AuthPermission(\Flight::db()))->eq('alias', $alias)->find();

        if (! $perm->isHydrated()) {
            $io->error("Permission \"{$alias}\" not found.", true);
            return;
        }

        if ($description !== null) {
            $perm->description = $description;
        }

        $perm->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $perm->save();

        $io->info("Permission \"{$alias}\" updated.", true);
    }

    protected function deletePermission($io, ?string $alias): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $perm = (new AuthPermission(\Flight::db()))->eq('alias', $alias)->find();

        if (! $perm->isHydrated()) {
            $io->error("Permission \"{$alias}\" not found.", true);
            return;
        }

        $perm->delete();

        $io->info("Permission \"{$alias}\" deleted.", true);
    }
}
