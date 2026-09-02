[![Stable? Not Quite Yet](https://img.shields.io/badge/stable%3F-not%20quite%20yet-blue?style=for-the-badge)](https://packagist.org/packages/enlivenapp/flight-shield)
[![License](https://img.shields.io/packagist/l/enlivenapp/flight-shield?style=for-the-badge)](https://packagist.org/packages/enlivenapp/flight-shield)
[![PHP Version](https://img.shields.io/packagist/php-v/enlivenapp/flight-shield?style=for-the-badge)](https://packagist.org/packages/enlivenapp/flight-shield)
[![Monthly Downloads](https://img.shields.io/packagist/dm/enlivenapp/flight-shield?style=for-the-badge)](https://packagist.org/packages/enlivenapp/flight-shield)
[![Total Downloads](https://img.shields.io/packagist/dt/enlivenapp/flight-shield?style=for-the-badge)](https://packagist.org/packages/enlivenapp/flight-shield)
[![GitHub Issues](https://img.shields.io/github/issues/enlivenapp/FlightPHP-Shield?style=for-the-badge)](https://github.com/enlivenapp/FlightPHP-Shield/issues)
[![Contributors](https://img.shields.io/github/contributors/enlivenapp/FlightPHP-Shield?style=for-the-badge)](https://github.com/enlivenapp/FlightPHP-Shield/graphs/contributors)
[![Latest Release](https://img.shields.io/github/v/release/enlivenapp/FlightPHP-Shield?style=for-the-badge)](https://github.com/enlivenapp/FlightPHP-Shield/releases)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-blue?style=for-the-badge)](https://github.com/enlivenapp/FlightPHP-Shield/pulls)

# Flight Shield

**I noticed folks downloading some of these packages. I'm super grateful, Thank You! I would like to let folks know until this notice disappears I'm doing a lot of breaking changes without worrying about them. Once versions are up around 0.5.x things should settle down.**

Flight Shield is an authentication and authorization plugin for [FlightPHP](https://flightphp.com/). It was ported and adapted from [CodeIgniter4 Shield](https://github.com/codeigniter4/shield) around v1.2. We watch for security patches, and we've made significant functionality additions. It runs inside [FlightPHP](https://github.com/flightphp/core) as used by [Pubvana CMS v3](https://github.com/Pubvana-CMS/pubvana). It gives you session login, access token auth, HMAC-SHA256 request signing, JWT verification, role-based groups and permissions, password validation, and route-level middlewares.

---

## Features

- Database-backed sessions with AES-256-GCM encrypted payloads (via `enlivenapp/flight-sessions`)
- Session-based authentication (login, logout, remember me with token rotation)
- Access token authentication (Bearer tokens in the `Authorization` header)
- HMAC-SHA256 API authentication with AES-256-GCM encrypted secrets at rest and replay protection
- JWT authentication (requires `firebase/php-jwt`)
- Chain authentication - try multiple authenticators in order, first success wins
- Groups and permissions (role-based access control with wildcard support)
- Per-user direct permissions in addition to group-inherited permissions
- Email two-factor authentication (2FA) as an optional post-login action
- Email activation on registration as an optional post-register action
- Magic link login
- Password validators: composition (min/max length), nothing-personal, dictionary (65k common passwords), and pwned (Have I Been Pwned API)
- Automatic password rehashing when the cost parameters change
- Rate limiting on login, 2FA, and magic link endpoints (per-IP, database-backed)
- CSRF protection on all mutating auth routes via `enlivenapp/flight-csrf`
- Force-password-reset flow
- Login attempt recording (none, failures only, or all)
- CLI commands for managing users, groups, permissions, and HMAC keys
- Global helper functions `auth()` and `user_id()`
- View overrides - bundle views can be replaced per-app

---

## Requirements

- PHP 8.1+
- `flightphp/core` ^3.0
- `flightphp/active-record` >=0.7 - all Shield models extend `\flight\ActiveRecord`
- `enlivenapp/flight-csrf` ^0.2
- `enlivenapp/flight-sessions` ^0.1 - database-backed session storage (all session state lives in SQL with encrypted payloads)
- `firebase/php-jwt` ^6.0 *(optional, required only for JWT authentication)*

---

## Installation

**1. Install via Composer**

```bash
composer require enlivenapp/flight-shield
```

**2. Provide the override config**

Shield ships with sensible defaults in `src/Config/Config.php`. Create the override config file `app/config/shield.php` to set your own values (details in Configuration). At minimum it sets the route prefix, `'routePrepend' => 'auth'`, and you can add anything from the default config file to it.

```php
// app/config/shield.php
return [
    'routePrepend' => 'auth',
    // ... your overrides here
];
```

Start sessions before Shield so session state is ready at auth time. Start CSRF after both.

**3. Run the migrations**

Shield ships PHP migration classes under `Database/Migrations/` (plus seed data in `Database/Seeds/`). Run all pending migrations across every module with the `enlivenapp/migrations` runway command:

```bash
php runway migrate:all
```

This creates the following tables: `users`, `auth_identities`, `auth_logins`, `auth_token_logins`, `auth_remember_tokens`, `auth_groups_users`, `auth_permissions_users`, `auth_groups`, `auth_permissions`, `auth_group_permissions`. Apps that apply pending migrations during boot pick these up on the first request, so you can skip the CLI step.

**4. Seed default groups and permissions**

Default groups, permissions, and group-permission mappings are declared as seed data in `Plugin::$seeds` / the package `Seeds` directory. They apply automatically when migrations run, so there is no separate CLI step.

The seeds populate:

- `auth_groups` - `superadmin`, `admin`, `user`
- `auth_permissions` - `admin.access`, `users.list`, `users.create`, `users.edit`, `users.delete`, `profile.edit`
- `auth_group_permissions` - superadmin gets `*` (all), admin gets the admin/user management permissions, user gets `profile.edit`

---

## Quick Start

**Protect a route with session auth**

```php
use Enlivenapp\FlightShield\Middlewares\SessionAuthMiddleware;

Flight::route('/dashboard', function () {
    $user = auth()->user();
    echo 'Hello, ' . $user->username;
})->addMiddleware(new SessionAuthMiddleware(Flight::app()));
```

**Log a user in manually**

```php
$result = auth()->attempt(['email' => 'user@example.com', 'password' => 'secret']);

if ($result->isOK()) {
    Flight::redirect('/dashboard');
} else {
    echo $result->reason();
}
```

**Check a permission**

```php
$user = auth()->user();

if ($user->can('users.edit')) {
    // allowed
}

if ($user->inGroup('admin', 'superadmin')) {
    // allowed
}
```

Note: Superadmins *always* has access
```php
$user->can(*) = true
```

**Get the current user ID anywhere**

```php
$id = user_id(); // returns int|string|null
```

---

## Management APIs

For app-level administration (user/group/permission CRUD), Shield exposes management services through `Auth`. These services wrap the models and apply validation and consistency rules, so prefer them over calling the models directly.

| Accessor | Class | Purpose |
|----------|-------|---------|
| `auth()->users()` | `Services\UserManagement` | List/find/create users, profile updates (username/email/password with validation + hashing), activate/deactivate, soft delete |
| `auth()->groups()` | `Authorization\Groups` | Group CRUD, permission assignment/sync, delete with membership fallback to `user` |
| `auth()->permissions()` | `Authorization\Permissions` | Permission CRUD; deletes also clean group mappings and direct grants/denies |
| `auth()->stats()` | `Services\UserStats` | User/login statistics |

```php
$auth = Flight::auth();

// Superadmin visibility: superadmins see everyone,
// Superadmins are hidden from every other user group.
$isSuper = $auth->user()?->inGroup('superadmin') ?? false;

$result = $auth->users()->create($username, $email, $password, 'editor');
if ($result->isOK()) {
    $user = $result->extraInfo();
} else {
    echo $result->reason();
}

$auth->users()->paginated($page, 20, $isSuper);
$auth->users()->updateProfile($user, ['email' => $newEmail, 'password' => $newPassword]);
$auth->groups()->syncPermissions('editor', ['posts.create', 'posts.edit']);
$auth->permissions()->create('posts.create', 'Create blog posts');
```

`UserManagement::create()`, `updateProfile()`, and similar operations return a `Result` (`isOK()`, `reason()`, `extraInfo()`). Password changes run through the configured password validators before hashing; duplicate email addresses are rejected.

---

## How It Works

### Architecture overview

`Plugin::register()` registers `Auth` as a Flight service (`$app->auth()`). The `Auth` class delegates every call to the currently active `AuthenticatorInterface` instance. That instance comes from `Authentication::factory()`, which resolves the alias (`session`, `tokens`, `hmac`, `jwt`) against the `authenticators` map in config and returns a singleton per request. All models extend [`flightphp/active-record`](https://github.com/flightphp/active-record) (`\flight\ActiveRecord`).

The four authenticators are:

| Alias | Class | Transport |
|-------|-------|-----------|
| `session` | `Session` | PHP session + optional remember-me cookie |
| `tokens` | `AccessTokens` | `Authorization: Bearer <token>` header |
| `hmac` | `HmacSha256` | `Authorization: HMAC-SHA256 <key>:<sig>` + `X-Request-Timestamp` header |
| `jwt` | `JWT` | `Authorization: Bearer <jwt>` header |

JWT is not enabled by default (it is commented out in the default `authenticators` map). Add it explicitly and install `firebase/php-jwt` to use it.

`ChainAuthMiddleware` iterates the `authentication_chain` list (default: `['session', 'tokens', 'hmac']`) and stops at the first authenticator that reports `loggedIn() === true`. That lets a single route accept both browser sessions and API clients.

Authorization uses two parallel systems: **groups** (assigned via `auth_groups_users`) and **direct permissions** (assigned via `auth_permissions_users`). `User::can()` checks direct permissions first, then walks the user's groups and queries `auth_group_permissions` for each. Matching uses hierarchical wildcard semantics: a trailing `*` grants a node and all its descendants (`users.*` grants `users.create`, `users.create.team`, …), and a middle `*` matches exactly one segment (`admin.*.post`). A standalone `*` matches nothing — use `can()` on a user in the `superadmin` group instead (that group bypasses all permission checks).

Password validation is a pipeline of `ValidatorInterface` classes run in order. The first failure short-circuits the pipeline and returns an error.

---

## Session Authentication

Shield stores all session state in the database through [`enlivenapp/flight-sessions`](https://github.com/enlivenapp/FlightPHP-Sessions), not PHP's native file sessions. See that package's README for how the session storage works.

The `Session` authenticator stores the authenticated user's ID under `$config['session.field']` (default key: `user`). On login the session ID regenerates and the row binds to the user. On logout the session keys (`user`, `auth_action`) are removed, the user binding clears, and the session regenerates again.

### Remember me

When `session.allow_remembering` is `true` (the default), calling `auth('session')->getAuthenticator()->remember()` after login stores a split-token cookie. The cookie holds a `selector:validator` pair. The selector is stored in plain text in `auth_remember_tokens`; the validator is stored as `sha256(validator)`. On each request where no session exists, the remember cookie is checked:

1. Locate the token by selector.
2. Compare `sha256(cookie_validator)` against the stored hash using `hash_equals()`.
3. If a mismatch is detected (possible token theft), all remember tokens for that user are purged.
4. On success, the old token is deleted, the user is logged in, and a new token is issued (token rotation).

Expired tokens are purged probabilistically (20% of successful remember-me logins) to avoid a separate cleanup job.

### Post-login actions (2FA, email activation)

When `actions.login` is set to an action class (e.g. `Email2FA`), `attempt()` puts the session into a `STATE_PENDING` by storing the user ID and action class name in the session. The user isn't considered fully logged in until the action completes. The routes at `/auth/2fa` and `/auth/activate` drive this flow.

### Configuration

```php
'session' => [
    'field'                => 'user',         // Session key
    'allow_remembering'    => true,
    'remember_cookie_name' => 'remember',
    'remember_length'      => 30 * 86400,     // 30 days
],
```

---

## Access Token Authentication

The `AccessTokens` authenticator reads the `Authorization` header and strips the `Bearer ` prefix. It hashes the raw token with SHA-256, looks it up in `auth_identities` (type = `access_token`), and checks expiry and `unused_token_lifetime`. On success it touches `last_used_at`.

Tokens are stored as identities in `auth_identities`. Use the `shield:user` CLI or your own application code to generate them.

---

## HMAC Authentication

The `HmacSha256` authenticator authenticates API clients that sign each request instead of sending a reusable secret.

**Request format**

The client sends:

```
Authorization: HMAC-SHA256 <userKey>:<signature>
X-Request-Timestamp: <unix timestamp>
```

The signature is computed as:

```
HMAC-SHA256(secret, timestamp + "\n" + raw_request_body)
```

**Verification**

1. Parse `userKey` and `signature` from the header.
2. Look up the identity by `userKey` in `auth_identities` (type = `hmac_sha256`).
3. Reject the request if the timestamp is more than 300 seconds from `time()` (replay protection).
4. Decrypt the stored `secret2` and recompute the HMAC. Compare with `hash_equals()`.
5. Check `unused_token_lifetime`.
6. Touch `last_used_at`.

**HMAC secrets at rest**

Secrets are stored in `auth_identities.secret2` encrypted with AES-256-GCM. Encryption keys live in the `hmac.encryption_keys` override block (never in the database); the active key is identified by `hmac.encryption_current_key`. These are secrets, so prefer keeping them out of version control. Your host's `.env` loader can inject them into the config array at boot.

The `shield:hmac` CLI writes and rotates these keys in place into the same override config file described under Configuration. That file must already contain an empty `hmac` block. See the `shield:hmac` section below for the full workflow.

---

## JWT Authentication

The `JWT` authenticator is stateless. It reads `Authorization: Bearer <token>`, parses and verifies the JWT using `JWTManager` (which wraps `firebase/php-jwt`), extracts the `sub` claim as the user ID, and loads the user from the database.

JWT is not enabled by default. To enable it:

1. Install the dependency: `composer require firebase/php-jwt ^6.0`
2. Add `jwt` to the `authenticators` map in your plugin config:

```php
'authenticators' => [
    'session' => \Enlivenapp\FlightShield\Authentication\Authenticators\Session::class,
    'tokens'  => \Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens::class,
    'hmac'    => \Enlivenapp\FlightShield\Authentication\Authenticators\HmacSha256::class,
    'jwt'     => \Enlivenapp\FlightShield\Authentication\Authenticators\JWT::class,
],
```

3. Provide JWT keys in your config overrides (fill in the values):

```php
'jwt' => [
    'header'         => 'Authorization',
    'time_to_live'   => 3600,
    'default_claims' => ['iss' => 'https://example.com'],
    'keys' => [
        'default' => [
            ['kid' => '', 'alg' => 'HS256', 'secret' => 'your-256-bit-secret'],
        ],
    ],
],
```

To generate a token for a user, call `generateToken()` directly on the JWT authenticator instance:

```php
$jwt = auth('jwt')->getAuthenticator()->generateToken($user);
```

---

## Chain Authentication

`ChainAuthMiddleware` tries each authenticator in `authentication_chain` in order. The first one whose `loggedIn()` returns `true` grants access and records the active date. If all fail, the user is redirected to the configured login URL.

```php
use Enlivenapp\FlightShield\Middlewares\ChainAuthMiddleware;

Flight::route('/api/resource', function () {
    // accessible by session, Bearer token, or HMAC
})->addMiddleware(new ChainAuthMiddleware(Flight::app()));
```

Default chain: `['session', 'tokens', 'hmac']`. Override with `authentication_chain` in config.

---

## Groups and Permissions

### Data model

- `auth_groups` - group definitions (`alias`, `title`, `description`)
- `auth_permissions` - permission definitions (`alias`, `description`)
- `auth_group_permissions` - maps group aliases to permission aliases
- `auth_groups_users` - maps user IDs to group aliases
- `auth_permissions_users` - maps user IDs to permission aliases (direct grants)

### Permission resolution

`User::can(string $permission)` checks in this order:

1. Direct user permissions in `auth_permissions_users`
2. Group permissions from `auth_group_permissions` for each of the user's groups

Permission matching is hierarchical. A trailing `*` matches a node and every descendant (`users.*` grants `users.create`, `users.edit`, `users.edit.settings`, … but never `users` itself); a middle `*` matches exactly one segment (`admin.*.post` grants `admin.news.post` but not `admin.news.manage.post`). Wildcards are only allowed as whole segments, and a standalone `*` no longer matches everything — grant the `superadmin` group to bypass checks entirely.

### Superadmin visibility

Superadmin users are hidden from non-superadmin callers by default. That prevents lower-privilege admins from viewing, editing, or deleting superadmin accounts.

The `User` model methods that support this:

- `findAllPaginated(int $page, int $perPage, bool $includeSuperadmins = false)` - when `$includeSuperadmins` is `false`, users in the `superadmin` group are filtered out of results.
- `countAll(bool $includeSuperadmins = false)` - same filtering for counts.
- `findById(int $id, bool $includeSuperadmins = true)` - when `$includeSuperadmins` is `false`, returns `null` if the target user is in the `superadmin` group. Defaults to `true` for backward compatibility with internal auth lookups.

Pass `$currentUser->inGroup('superadmin')` as the flag so superadmins see everyone and non-superadmins see only non-superadmin users.

**Note:** Filtering happens post-fetch in PHP (not at the query level) due to ActiveRecord limitations with table-qualified column names in WHERE clauses. For paginated results, a page may contain fewer results than `$perPage` if superadmin users were in the batch.

### Default seeds

The following seed data is inserted automatically whenever migrations run (enlivenapp/migrations applies package seed classes alongside migrations):

**Groups:** `superadmin`, `admin`, `user`

**Permissions:** `admin.access`, `users.list`, `users.create`, `users.edit`, `users.delete`, `profile.edit`

**Group-permission mappings:**
- `superadmin` → `*` (all permissions)
- `admin` → `admin.access`, `users.list`, `users.create`, `users.edit`, `users.delete`
- `user` → `profile.edit`

### Working with groups and permissions in code

```php
$user = auth()->user();

// Check group membership
$user->inGroup('admin');               // true if in 'admin'
$user->inGroup('admin', 'superadmin'); // true if in either

// Check permission
$user->can('users.edit');

// Modify via the Authorizable trait (no ORM handle needed)
$user->addGroup('editor');
$user->removeGroup('editor');
$user->addPermission('posts.create');
$user->addPermission('posts.create', true); // explicit deny
$user->removePermission('posts.create');

// Or use the management services directly
auth()->groups()->syncPermissions('editor', ['posts.create', 'posts.edit']);
auth()->permissions()->create('posts.create', 'Create blog posts');
```

Note: typed-property assignments bypass ActiveRecord's change tracking, so Shield's trait methods use explicit `dirty([...])` calls internally.

---

## Password Validators

Validators run as a pipeline during registration and password changes. The default set is `CompositionValidator`, `NothingPersonalValidator`, `DictionaryValidator`. `PwnedValidator` is available but not enabled by default.

| Validator | What it checks |
|-----------|---------------|
| `CompositionValidator` | Min length (default 8, matching the NIST SP 800-63B minimum) and max length (128) |
| `NothingPersonalValidator` | Password must not contain or closely match the username, email address, or reversed username. Also checks similarity via `similar_text()` against `max_similarity` (default 50%) |
| `DictionaryValidator` | Password must not appear in the bundled 65,000-entry common-password list |
| `PwnedValidator` | Password must not appear in the Have I Been Pwned database (uses k-anonymity API, fails open if the API is unreachable) |

Configure in `passwords`:

```php
'passwords' => [
    'algorithm'      => PASSWORD_DEFAULT, // PASSWORD_BCRYPT or PASSWORD_ARGON2ID
    'cost'           => 12,
    'memory_cost'    => 65536,   // Argon2 only
    'time_cost'      => 4,       // Argon2 only
    'threads'        => 1,       // Argon2 only
    'min_length'     => 8,
    'max_similarity' => 50,
    'validators'     => [
        \Enlivenapp\FlightShield\Passwords\CompositionValidator::class,
        \Enlivenapp\FlightShield\Passwords\NothingPersonalValidator::class,
        \Enlivenapp\FlightShield\Passwords\DictionaryValidator::class,
        // \Enlivenapp\FlightShield\Passwords\PwnedValidator::class,
    ],
],
```

---

## Middlewares

Apply middlewares to routes or route groups using FlightPHP's `->addMiddleware()`.

### `SessionAuthMiddleware`

Requires an active session login. Redirects to the configured `login` URL if not authenticated. Records the active date on success.

```php
use Enlivenapp\FlightShield\Middlewares\SessionAuthMiddleware;

Flight::route('/dashboard', function () { ... })
    ->addMiddleware(new SessionAuthMiddleware(Flight::app()));
```

### `TokenAuthMiddleware`

Authenticates via a Bearer access token in the `Authorization` header. Halts with a redirect on failure.

```php
use Enlivenapp\FlightShield\Middlewares\TokenAuthMiddleware;

Flight::route('/api/data', function () { ... })
    ->addMiddleware(new TokenAuthMiddleware(Flight::app()));
```

### `HmacAuthMiddleware`

Authenticates via HMAC-SHA256 request signing. Reads the `Authorization` header, `X-Request-Timestamp` header, and the raw request body. Redirects on failure.

```php
use Enlivenapp\FlightShield\Middlewares\HmacAuthMiddleware;

Flight::route('POST /api/webhook', function () { ... })
    ->addMiddleware(new HmacAuthMiddleware(Flight::app()));
```

### `JWTAuthMiddleware`

Authenticates via a JWT Bearer token. Requires `firebase/php-jwt`. Redirects on failure.

```php
use Enlivenapp\FlightShield\Middlewares\JWTAuthMiddleware;

Flight::route('/api/secure', function () { ... })
    ->addMiddleware(new JWTAuthMiddleware(Flight::app()));
```

### `ChainAuthMiddleware`

Tries each authenticator in `authentication_chain` in order. Grants access on the first success. Redirects to the login URL if all fail.

```php
use Enlivenapp\FlightShield\Middlewares\ChainAuthMiddleware;

Flight::route('/mixed', function () { ... })
    ->addMiddleware(new ChainAuthMiddleware(Flight::app()));
```

### `GroupMiddleware`

Requires the authenticated user to belong to at least one of the specified groups. Redirects to `group_denied` URL on failure, `login` URL if not authenticated.

```php
use Enlivenapp\FlightShield\Middlewares\GroupMiddleware;

Flight::group('/admin', function () { ... }, [
    new GroupMiddleware(Flight::app(), 'admin', 'superadmin'),
]);
```

### `PermissionMiddleware`

Requires the authenticated user to hold at least one of the specified permissions (checked via `User::can()`). Redirects to `permission_denied` URL on failure.

```php
use Enlivenapp\FlightShield\Middlewares\PermissionMiddleware;

Flight::route('/posts/create', function () { ... })
    ->addMiddleware(new PermissionMiddleware(Flight::app(), 'posts.create'));
```

### `ForcePasswordResetMiddleware`

If the authenticated user's `requiresPasswordReset()` returns `true`, redirects to the configured `force_reset` URL. Passes through silently if the user isn't logged in.

```php
use Enlivenapp\FlightShield\Middlewares\ForcePasswordResetMiddleware;

Flight::route('/account', function () { ... })
    ->addMiddleware(new ForcePasswordResetMiddleware(Flight::app()));
```

### `RateLimitMiddleware`

Applied automatically to `POST /auth/login`, `POST /auth/magic-link`, `POST /auth/2fa/verify`, and `POST /auth/2fa/resend`. Can also be applied to custom routes.

Counts failed login attempts from the client IP across both `auth_logins` and `auth_token_logins` within the `decay_minutes` window. If `max_attempts` is reached and the most recent failure is still within the `lockout_minutes` window, the request is halted with HTTP 429 and a JSON error body.

```php
use Enlivenapp\FlightShield\Middlewares\RateLimitMiddleware;

Flight::route('POST /custom-auth', function () { ... })
    ->addMiddleware(new RateLimitMiddleware(Flight::app()));
```

---

## CLI Commands

Flight Shield uses the `runway` CLI provided by `flightphp/runway`.

### `shield`

Displays available sub-commands.

```bash
php runway shield
```

---

### `shield:user`

Manage users.

```bash
php runway shield:user create      -n admin -e admin@example.com -g superadmin
php runway shield:user list
php runway shield:user show        -n username
php runway shield:user activate    -e user@example.com
php runway shield:user deactivate  -n username
php runway shield:user delete      -e user@example.com
php runway shield:user password    -n username
php runway shield:user changename  -n username --new-name newusername
php runway shield:user changeemail -n username --new-email new@example.com
php runway shield:user addgroup    -n username -g admin
php runway shield:user removegroup -n username -g admin
```

Every `shield:user` command that changes a user runs through the same `Services\UserManagement` logic used by the HTTP layer. So CLI calls validate identically: duplicate emails are rejected, and passwords must pass the configured validator pipeline (min length, personal-info checks, dictionary, and so on). `show` prints full detail for one user: groups, direct permissions including denies, last login, and status.

---

### `shield:group`

Manage groups.

```bash
php runway shield:group list
php runway shield:group info             -a admin
php runway shield:group create           -a editor -t Editor -d "Content editors"
php runway shield:group update           -a editor -t "Senior Editor"
php runway shield:group delete           -a editor
php runway shield:group permissions      -a admin
php runway shield:group addpermission    -a editor -p posts.create
php runway shield:group removepermission -a editor -p posts.create
php runway shield:group syncpermissions  -a editor -p "posts.create,posts.edit"
```

`syncpermissions` replaces the group's permission set with the given comma-separated list. Aliases that don't exist are reported and skipped; if none of the provided aliases resolve, the command aborts and the group is left unchanged.

Deleting a group also removes all group-permission mappings and all user memberships. Any user left with no groups after deletion is automatically reassigned to the `user` group.

---

### `shield:permission`

Manage permissions.

```bash
php runway shield:permission list
php runway shield:permission create -a posts.create -d "Create posts"
php runway shield:permission update -a posts.create -d "Create blog posts"
php runway shield:permission delete -a posts.create
```

Deleting a permission also cleans up everything referencing it: group-permission mappings (`auth_group_permissions`) and direct user grants/denies (`auth_permissions_users`) are removed in the same operation, so no orphaned rows remain.

---

### `shield:hmac`

Manage HMAC encryption keys and token lifecycle.

```bash
# Initial setup
php runway shield:hmac init

# Key inspection
php runway shield:hmac listkeys

# Key rotation
php runway shield:hmac addkey
php runway shield:hmac reencrypt     # migrate all secrets to the active key
php runway shield:hmac removekey -k k1

# Bulk operations
php runway shield:hmac encrypt       # encrypt any unencrypted secrets
php runway shield:hmac decrypt       # remove encryption from all secrets
php runway shield:hmac invalidateAll # immediately expire all HMAC tokens
```

**Key rotation workflow:**

```
listkeys → addkey → reencrypt → removekey -k <old-key-id>
```

`init`, `addkey`, and `removekey` write to the host's `app/config/shield.php` override file. That file must already exist with an empty `hmac` block before you run them; otherwise the command reports that there is nothing to write to. The application merges this override file with the package defaults at load time.

---

## Configuration

All Shield options live inside the plugin's config. The plugin merges your overrides with its defaults from `src/Config/Config.php`, so you only need to include values you want to override.

Provide your overrides in the per-app override config file at `app/config/shield.php` (resolved from `PROJECT_ROOT`). The application merges it over the package defaults at load time:

```php
// app/config/shield.php - return the keys you want to override
return [
    'routePrepend' => 'auth',
    'default_authenticator' => 'session',
    // ... any other overrides
];
```

### Full default configuration

| Key | Default | Description |
|-----|---------|-------------|
| `default_authenticator` | `'session'` | Authenticator used when none is specified |
| `authentication_chain` | `['session', 'tokens', 'hmac']` | Order tried by `ChainAuthMiddleware` |
| `allow_registration` | `true` | Allow new user self-registration |
| `allow_magic_link` | `false` | Enable magic link login |
| `magic_link_lifetime` | `3600` | Magic link token TTL in seconds |
| `default_group` | `'user'` | Group assigned to newly registered users |
| `record_login_attempt` | `'all'` | Login attempt recording: `'none'`, `'failure'`, or `'all'` |
| `record_active_date` | `true` | Update `last_active` on every authenticated request |
| `unused_token_lifetime` | `7776000` | Access/HMAC token inactivity TTL in seconds (90 days) |
| `valid_login_fields` | `['email']` | Fields accepted as login identifier |
| `personal_fields` | `[]` | No-op in this port: `NothingPersonalValidator` pulls username/email from the identity record itself |
| `email_sender` | `null` | Callback for outbound emails (see Email Setup) |
| `actions.login` | `null` | Post-login action class (`Email2FA::class` or `null`) |
| `actions.register` | `null` | Post-register action class (`EmailActivator::class` or `null`) |
| `token_header` | `'Authorization'` | Header read by the `AccessTokens` authenticator |
| `hmac_header` | `'Authorization'` | Header read by the `HmacSha256` authenticator |

### Session settings

```php
'session' => [
    'field'                => 'user',
    'allow_remembering'    => true,
    'remember_cookie_name' => 'remember',
    'remember_length'      => 30 * 86400, // 30 days
],
```

### Password settings

```php
'passwords' => [
    'algorithm'      => PASSWORD_DEFAULT,
    'cost'           => 12,
    'memory_cost'    => 65536,
    'time_cost'      => 4,
    'threads'        => 1,
    'min_length'     => 8,
    'max_similarity' => 50,
    'validators'     => [
        \Enlivenapp\FlightShield\Passwords\CompositionValidator::class,
        \Enlivenapp\FlightShield\Passwords\NothingPersonalValidator::class,
        \Enlivenapp\FlightShield\Passwords\DictionaryValidator::class,
    ],
],
```

### HMAC settings

```php
'hmac' => [
    'encryption_keys'        => [],         // populated by shield:hmac init/addkey
    'encryption_current_key' => '',         // alias of the active key
    'encryption_cipher'      => 'aes-256-gcm',
    'secret2_storage_limit'  => 255,
],
```

### JWT settings

```php
'jwt' => [
    'header'         => 'Authorization',
    'time_to_live'   => 3600,
    'default_claims' => ['iss' => ''],
    'keys' => [
        'default' => [
            ['kid' => '', 'alg' => 'HS256', 'secret' => ''],
        ],
    ],
],
```

### Rate limiting settings

```php
'rate_limiting' => [
    'enabled'         => true,
    'max_attempts'    => 10,
    'decay_minutes'   => 30,
    'lockout_minutes' => 30,
],
```

### Redirect URLs

```php
'redirects' => [
    'login'             => '/auth/login',
    'logout'            => '/',
    'after_login'       => '/',
    'after_login_admin' => '/admin',
    'after_register'    => '/',
    'after_logout'      => '/auth/login',
    'force_reset'       => '/auth/reset-password',
    'permission_denied' => '/auth/login',
    'group_denied'      => '/auth/login',
],
```

---

## Routes

Shield registers the following routes under the prefix defined by the returned `routePrepend` value in `src/Config/Config.php` (default: `auth`).

| Method | Path | Notes |
|--------|------|-------|
| GET | `/auth/login` | Show login form |
| POST | `/auth/login` | Process login - CSRF + rate limit |
| GET | `/auth/logout` | Log out |
| GET | `/auth/register` | Show registration form |
| POST | `/auth/register` | Process registration - CSRF |
| GET | `/auth/magic-link` | Show magic link request form |
| POST | `/auth/magic-link` | Send magic link email - CSRF + rate limit |
| GET | `/auth/magic-link/verify` | Verify magic link token |
| GET | `/auth/2fa` | Show 2FA verification page (sends code) |
| POST | `/auth/2fa/verify` | Verify 2FA code - CSRF + rate limit |
| POST | `/auth/2fa/resend` | Resend 2FA code - CSRF + rate limit |
| GET | `/auth/activate` | Show activation page (sends email) |
| GET | `/auth/activate/verify` | Verify email activation token |

---

## Email Setup

Shield doesn't ship with a mailer. Provide a callback that accepts the recipient address, subject, and body:

```php
'email_sender' => function (string $to, string $subject, string $body): void {
    mail($to, $subject, $body);
},
```

The callback runs for 2FA codes, magic links, and email activation messages.

---

## Views

Shield renders its own views by default, shipping both `.php` and `.tpl` variants under `src/Views/`. To override any view, create a matching file under `app/Views/<plugin-id>/`. The plugin id is the package name, so `login.php` overrides to:

```
app/Views/enlivenapp/flight-shield/login.php
```

A theme can override it the same way. Replace `<active>` with the currently active theme's directory (for example `themes/default/Views/enlivenapp/flight-shield/login.php`).

Overrideable views:

- `login.php`
- `register.php`
- `magic_link_login.php`
- `magic_link_message.php`
- `2fa_verify.php`
- `activate.php`

---

## Security Notes

Passwords are hashed with `password_hash()` using `PASSWORD_DEFAULT` (bcrypt, cost 12). You can switch to Argon2 via `algorithm`, `memory_cost`, `time_cost`, and `threads`. Passwords rehash automatically when the cost parameters change.

Session storage is handled by `enlivenapp/flight-sessions`; see that package's README for how payloads are protected at rest.

HMAC secrets are stored encrypted with AES-256-GCM. Encryption keys live in app configuration (or better, injected from `.env`), never in the database.

All token and hash comparisons use `hash_equals()` to prevent timing attacks.

HMAC requests with a timestamp more than 300 seconds from `time()` are rejected, which blocks replay attempts.

Remember-me tokens use a split-token scheme (selector stored plain, validator stored as a SHA-256 hash). A mismatch purges all tokens for the user.

All mutating auth routes are protected by `CsrfMiddleware` from `enlivenapp/flight-csrf`.

Failed login attempts are tracked per IP across `auth_logins` and `auth_token_logins`. Excessive failures result in HTTP 429.

The session ID regenerates on login and logout, which prevents session fixation.

---

## License

MIT - see [LICENSE](LICENSE).
