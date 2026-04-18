-- Flight Shield: Group & Permission definition tables
-- Moves group/permission definitions from config arrays into the database.

-- Groups definition table
CREATE TABLE IF NOT EXISTS `auth_groups` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `alias` VARCHAR(255) NOT NULL,
    `title` VARCHAR(255) NOT NULL,
    `description` VARCHAR(255) NULL DEFAULT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    `updated_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `alias` (`alias`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissions definition table
CREATE TABLE IF NOT EXISTS `auth_permissions` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `alias` VARCHAR(255) NOT NULL,
    `description` VARCHAR(255) NULL DEFAULT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    `updated_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `alias` (`alias`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Group-to-permission mapping (which permissions each group has)
CREATE TABLE IF NOT EXISTS `auth_group_permissions` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `group_alias` VARCHAR(255) NOT NULL,
    `permission_alias` VARCHAR(255) NOT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `group_permission` (`group_alias`, `permission_alias`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default groups
INSERT INTO `auth_groups` (`alias`, `title`, `description`, `created_at`, `updated_at`) VALUES
    ('superadmin', 'Super Admin', 'Full system access', NOW(), NOW()),
    ('admin', 'Admin', 'Administrative access', NOW(), NOW()),
    ('user', 'User', 'Standard user', NOW(), NOW());

-- Seed default permissions
INSERT INTO `auth_permissions` (`alias`, `description`, `created_at`, `updated_at`) VALUES
    ('admin.access', 'Access admin panel', NOW(), NOW()),
    ('users.list', 'List users', NOW(), NOW()),
    ('users.create', 'Create users', NOW(), NOW()),
    ('users.edit', 'Edit users', NOW(), NOW()),
    ('users.delete', 'Delete users', NOW(), NOW()),
    ('profile.edit', 'Edit own profile', NOW(), NOW());

-- Seed group-permission mappings (mirrors the old config matrix)
INSERT INTO `auth_group_permissions` (`group_alias`, `permission_alias`, `created_at`) VALUES
    ('superadmin', '*', NOW()),
    ('admin', 'admin.access', NOW()),
    ('admin', 'users.list', NOW()),
    ('admin', 'users.create', NOW()),
    ('admin', 'users.edit', NOW()),
    ('admin', 'users.delete', NOW()),
    ('user', 'profile.edit', NOW());
