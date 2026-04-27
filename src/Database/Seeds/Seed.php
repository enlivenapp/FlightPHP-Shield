<?php

return [
    'install' => [
        [
            'table' => 'auth_groups',
            'rows'  => [
                ['alias' => 'superadmin', 'title' => 'Super Admin', 'description' => 'Full system access'],
                ['alias' => 'admin',      'title' => 'Admin',       'description' => 'Administrative access'],
                ['alias' => 'user',       'title' => 'User',        'description' => 'Standard user'],
            ],
        ],
        [
            'table' => 'auth_permissions',
            'rows'  => [
                ['alias' => 'admin.access',  'description' => 'Access admin panel'],
                ['alias' => 'users.list',    'description' => 'List users'],
                ['alias' => 'users.create',  'description' => 'Create users'],
                ['alias' => 'users.edit',    'description' => 'Edit users'],
                ['alias' => 'users.delete',  'description' => 'Delete users'],
                ['alias' => 'profile.edit',  'description' => 'Edit own profile'],
            ],
        ],
        [
            'table' => 'auth_group_permissions',
            'rows'  => [
                ['group_alias' => 'superadmin', 'permission_alias' => '*'],
                ['group_alias' => 'admin',      'permission_alias' => 'admin.access'],
                ['group_alias' => 'admin',      'permission_alias' => 'users.list'],
                ['group_alias' => 'admin',      'permission_alias' => 'users.create'],
                ['group_alias' => 'admin',      'permission_alias' => 'users.edit'],
                ['group_alias' => 'admin',      'permission_alias' => 'users.delete'],
                ['group_alias' => 'user',       'permission_alias' => 'profile.edit'],
            ],
        ],
    ],
];
