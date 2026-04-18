-- Flight Shield: Auth Tables
-- Ported from CodeIgniter Shield migration

-- Users table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(30) NULL DEFAULT NULL,
    `status` VARCHAR(255) NULL DEFAULT NULL,
    `status_message` VARCHAR(255) NULL DEFAULT NULL,
    `active` TINYINT(1) NOT NULL DEFAULT 0,
    `last_active` DATETIME NULL DEFAULT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    `updated_at` DATETIME NULL DEFAULT NULL,
    `deleted_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Auth identities (email/password, tokens, 2FA codes, etc.)
CREATE TABLE IF NOT EXISTS `auth_identities` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `type` VARCHAR(255) NOT NULL,
    `name` VARCHAR(255) NULL DEFAULT NULL,
    `secret` VARCHAR(255) NOT NULL,
    `secret2` VARCHAR(255) NULL DEFAULT NULL,
    `expires` DATETIME NULL DEFAULT NULL,
    `extra` TEXT NULL DEFAULT NULL,
    `force_reset` TINYINT(1) NOT NULL DEFAULT 0,
    `last_used_at` DATETIME NULL DEFAULT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    `updated_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `type_secret` (`type`, `secret`),
    KEY `user_id` (`user_id`),
    CONSTRAINT `auth_identities_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login attempts
CREATE TABLE IF NOT EXISTS `auth_logins` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip_address` VARCHAR(255) NOT NULL,
    `user_agent` VARCHAR(255) NULL DEFAULT NULL,
    `id_type` VARCHAR(255) NOT NULL,
    `identifier` VARCHAR(255) NOT NULL,
    `user_id` INT(11) UNSIGNED NULL DEFAULT NULL,
    `date` DATETIME NOT NULL,
    `success` TINYINT(1) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `id_type_identifier` (`id_type`, `identifier`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Token login attempts (access tokens, HMAC)
CREATE TABLE IF NOT EXISTS `auth_token_logins` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip_address` VARCHAR(255) NOT NULL,
    `user_agent` VARCHAR(255) NULL DEFAULT NULL,
    `id_type` VARCHAR(255) NOT NULL,
    `identifier` VARCHAR(255) NOT NULL,
    `user_id` INT(11) UNSIGNED NULL DEFAULT NULL,
    `date` DATETIME NOT NULL,
    `success` TINYINT(1) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `id_type_identifier` (`id_type`, `identifier`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Remember-me tokens
CREATE TABLE IF NOT EXISTS `auth_remember_tokens` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `selector` VARCHAR(255) NOT NULL,
    `hashed_validator` VARCHAR(255) NOT NULL,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `expires` DATETIME NOT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    `updated_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_id` (`user_id`),
    CONSTRAINT `auth_remember_tokens_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Groups ↔ Users
CREATE TABLE IF NOT EXISTS `auth_groups_users` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `group` VARCHAR(255) NOT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `user_id` (`user_id`),
    CONSTRAINT `auth_groups_users_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissions ↔ Users
CREATE TABLE IF NOT EXISTS `auth_permissions_users` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `permission` VARCHAR(255) NOT NULL,
    `created_at` DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `user_id` (`user_id`),
    CONSTRAINT `auth_permissions_users_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
