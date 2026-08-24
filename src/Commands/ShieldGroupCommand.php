<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Enlivenapp\FlightShield\Authorization\Groups;
use Enlivenapp\FlightShield\Authorization\Permissions;
use Enlivenapp\FlightShield\Models\AuthGroup;
use flight\commands\AbstractBaseCommand;

class ShieldGroupCommand extends AbstractBaseCommand
{
    public function __construct(array $config)
    {
        parent::__construct('shield:group', 'Manage Shield groups', $config);

        $this
            ->argument('[action]', 'Action: list, info, create, update, delete, addpermission, removepermission, permissions, syncpermissions')
            ->option('-a --alias', 'Group alias')
            ->option('-t --title', 'Group title')
            ->option('-d --description', 'Group description')
            ->option('-p --permission', 'Permission alias (comma-separated list for syncpermissions)')
            ->usage(
                '<bold>  shield:group list</end><eol/>' .
                '<bold>  shield:group info</end> <comment>-a admin</end><eol/>' .
                '<bold>  shield:group create</end> <comment>-a editor -t Editor -d "Content editors"</end><eol/>' .
                '<bold>  shield:group update</end> <comment>-a editor -t "Senior Editor"</end><eol/>' .
                '<bold>  shield:group delete</end> <comment>-a editor</end><eol/>' .
                '<bold>  shield:group permissions</end> <comment>-a admin</end><eol/>' .
                '<bold>  shield:group addpermission</end> <comment>-a editor -p posts.create</end><eol/>' .
                '<bold>  shield:group removepermission</end> <comment>-a editor -p posts.create</end><eol/>' .
                '<bold>  shield:group syncpermissions</end> <comment>-a editor -p "posts.create, posts.edit"</end>'
            );
    }

    public function execute(
        ?string $action = null,
        ?string $alias = null,
        ?string $title = null,
        ?string $description = null,
        ?string $permission = null
    ): void {
        $io = $this->app()->io();

        if ($action === null) {
            $this->showHelp();
            return;
        }

        $groups = new Groups(\Flight::db());

        match ($action) {
            'list'             => $this->listGroups($groups, $io),
            'info'             => $this->groupInfo($groups, $io, $alias),
            'create'           => $this->createGroup($groups, $io, $alias, $title, $description),
            'update'           => $this->updateGroup($groups, $io, $alias, $title, $description),
            'delete'           => $this->deleteGroup($groups, $io, $alias),
            'permissions'      => $this->groupPermissions($groups, $io, $alias),
            'addpermission'    => $this->addPermission($groups, $io, $alias, $permission),
            'removepermission' => $this->removePermission($groups, $io, $alias, $permission),
            'syncpermissions'  => $this->syncPermissions($groups, $io, $alias, $permission),
            default            => $io->error("Unknown action: {$action}", true),
        };
    }

    protected function listGroups(Groups $groups, $io): void
    {
        $all = $groups->all();

        if (empty($all)) {
            $io->write('No groups found.', true);
            return;
        }

        $io->bold('Alias		Title		Description', true);
        foreach ($all as $group) {
            $io->write("{$group->alias}		{$group->title}		{$group->description}", true);
        }
    }

    protected function groupInfo(Groups $groups, $io, ?string $alias): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $io->write("Alias:       {$group->alias}", true);
        $io->write("Title:       {$group->title}", true);
        $io->write("Description: {$group->description}", true);
        $io->write("Created:     " . ($group->created_at ?? '-'), true);
        $io->write("Updated:     " . ($group->updated_at ?? '-'), true);

        $perms = $groups->permissions($alias);
        $io->write("Permissions: " . (empty($perms) ? 'none' : implode(', ', $perms)), true);
    }

    protected function createGroup(Groups $groups, $io, ?string $alias, ?string $title, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        if ($title === null) {
            $io->error('Title is required (-t title).', true);
            return;
        }

        $existing = $groups->info($alias);
        if ($existing !== null) {
            $io->error("Group \"{$alias}\" already exists.", true);
            return;
        }

        $group = new AuthGroup(\Flight::db());
        $group->alias       = strtolower($alias);
        $group->title       = $title;
        $group->description = $description;

        $groups->save($group);
        $io->info("Group \"{$alias}\" created.", true);
    }

    protected function updateGroup(Groups $groups, $io, ?string $alias, ?string $title, ?string $description): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        if ($title !== null) {
            $group->title = $title;
        }
        if ($description !== null) {
            $group->description = $description;
        }

        $groups->save($group);
        $io->info("Group \"{$alias}\" updated.", true);
    }

    protected function deleteGroup(Groups $groups, $io, ?string $alias): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $groups->delete($alias);
        $io->info("Group \"{$alias}\" deleted.", true);
    }

    protected function groupPermissions(Groups $groups, $io, ?string $alias): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $perms = $groups->permissions($alias);
        if (empty($perms)) {
            $io->write("Group \"{$alias}\" has no permissions.", true);
            return;
        }

        $io->bold("Permissions for \"{$alias}\":", true);
        foreach ($perms as $perm) {
            $io->write("  {$perm}", true);
        }
    }

    protected function addPermission(Groups $groups, $io, ?string $alias, ?string $permission): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }
        if ($permission === null) {
            $io->error('Permission is required (-p permission).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $groups->addPermission($alias, $permission);
        $io->info("Permission \"{$permission}\" added to group \"{$alias}\".", true);
    }

    protected function removePermission(Groups $groups, $io, ?string $alias, ?string $permission): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }
        if ($permission === null) {
            $io->error('Permission is required (-p permission).', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $groups->removePermission($alias, $permission);
        $io->info("Permission \"{$permission}\" removed from group \"{$alias}\".", true);
    }

    protected function syncPermissions(Groups $groups, $io, ?string $alias, ?string $permission): void
    {
        if ($alias === null) {
            $io->error('Alias is required (-a alias).', true);
            return;
        }
        if ($permission === null || trim($permission) === '') {
            $io->error('Permission list is required (-p "perm.one, perm.two").', true);
            return;
        }

        $group = $groups->info($alias);
        if ($group === null) {
            $io->error("Group \"{$alias}\" not found.", true);
            return;
        }

        $requested = array_values(array_filter(
            array_map('trim', explode(',', $permission)),
            fn (string $p): bool => $p !== ''
        ));

        // Split known from unknown so unknown aliases are reported
        // instead of silently skipped.
        $permissionsUtil = new Permissions(\Flight::db());
        $known = [];
        $unknown = [];
        foreach ($requested as $p) {
            if ($permissionsUtil->info(strtolower($p)) !== null) {
                $known[] = strtolower($p);
            } else {
                $unknown[] = $p;
            }
        }

        // Refuse to sync when nothing in the list exists — otherwise this
        // would silently strip every permission from the group.
        if ($known === []) {
            $io->error('No known permissions in the list; group left unchanged.', true);
            if ($unknown !== []) {
                $io->write('Unknown: ' . implode(', ', $unknown), true);
            }
            return;
        }

        $groups->syncPermissions($alias, $known);

        if ($unknown !== []) {
            $io->write('Skipped unknown permissions: ' . implode(', ', $unknown), true);
        }
        $io->info("Permissions synced for group \"{$alias}\".", true);
    }
}
