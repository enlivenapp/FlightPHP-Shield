# Flight Shield

Authentication and authorization for [FlightPHP](https://flightphp.com/), ported and adapted from CodeIgniter Shield.

Requires the [flight-school](https://github.com/enlivenapp/FlightPHP-Flight-School) plugin system.

---

## Requirements

- PHP 8.1+
- `flightphp/core` ^3.0
- `enlivenapp/flight-school` ^0.2
- `enlivenapp/flight-csrf` ^0.1
- `enlivenapp/flight-settings` ^0.1
- `firebase/php-jwt` ^6.0 *(optional, required only for JWT authentication)*

---

## Installation

**1. Install via Composer**

```bash
composer require enlivenapp/flight-shield
```

**2. Enable the plugin in your flight-school config**

In `app/config/config.php`, add the plugin to your plugins array:

```php
'plugins' => [
    'enlivenapp/flight-shield' => [],
],
```

On first run, the plugin will automatically inject required `hmac` and `jwt` stub entries into your config file.

**3. Run migrations**

```bash
php runway cycle:migrate
```

---

## Features

- Session-based authentication (login/logout, remember me)
- Access token authentication (Bearer tokens)
- HMAC-SHA256 API authentication with AES-256-GCM encrypted secrets at rest
- JWT authentication (requires `firebase/php-jwt`)
- Chain authentication (try multiple authenticators in order)
- Groups and permissions (role-based access control)
- Email two-factor authentication (2FA)
- Email activation on registration
- Magic link login
- Password validators (composition, dictionary, nothing-personal, pwned)
- Rate limiting on login, 2FA, and magic link endpoints
- CSRF protection on all mutating auth routes
- Force password reset flow
- CLI commands for managing users, groups, permissions, and HMAC keys

---

## Configuration

The plugin ships with defaults. Override any value by placing the key inside your plugin's config block in `app/config/config.php`:

```php
'plugins' => [
    'enlivenapp/flight-shield' => [
        'allow_registration' => false,
        'allow_magic_link'   => true,
        'default_group'      => 'member',
        'record_login_attempt' => 'failure',

        'redirects' => [
            'after_login'    => '/dashboard',
            'after_register' => '/welcome',
            'after_logout'   => '/auth/login',
        ],

        'actions' => [
            'login'    => \Enlivenapp\FlightShield\Authentication\Actions\Email2FA::class,
            'register' => \Enlivenapp\FlightShield\Authentication\Actions\EmailActivator::class,
        ],

        'rate_limiting' => [
            'enabled'         => true,
            'max_attempts'    => 10,
            'decay_minutes'   => 30,
            'lockout_minutes' => 30,
        ],
    ],
],
```

### Key configuration options

| Key | Default | Description |
|-----|---------|-------------|
| `default_authenticator` | `session` | Which authenticator to use by default |
| `authentication_chain` | `['session', 'tokens', 'hmac']` | Order tried by `ChainAuthMiddleware` |
| `allow_registration` | `true` | Allow new user self-registration |
| `allow_magic_link` | `false` | Enable magic link login |
| `magic_link_lifetime` | `3600` | Magic link token TTL in seconds |
| `default_group` | `user` | Group assigned to newly registered users |
| `record_login_attempt` | `all` | Login attempt recording: `none`, `failure`, or `all` |
| `record_active_date` | `true` | Update `last_active` on every authenticated request |
| `unused_token_lifetime` | `7776000` | Access/HMAC token TTL in seconds (90 days) |
| `valid_login_fields` | `['email']` | Fields accepted as login identifier |
| `personal_fields` | `[]` | User fields checked by `NothingPersonalValidator` |
| `email_sender` | `null` | Callback for sending emails (see Email Setup) |
| `actions.login` | `null` | Post-login action class (e.g. Email2FA) |
| `actions.register` | `null` | Post-register action class (e.g. EmailActivator) |

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
    'algorithm'  => PASSWORD_DEFAULT,
    'cost'       => 12,
    'min_length' => 8,
    'validators' => [
        \Enlivenapp\FlightShield\Passwords\CompositionValidator::class,
        \Enlivenapp\FlightShield\Passwords\NothingPersonalValidator::class,
        \Enlivenapp\FlightShield\Passwords\DictionaryValidator::class,
    ],
],
```

### JWT settings

```php
'jwt' => [
    'header'       => 'Authorization',
    'time_to_live' => 3600,
    'default_claims' => ['iss' => 'https://example.com'],
    'keys' => [
        'default' => [
            ['kid' => '', 'alg' => 'HS256', 'secret' => 'your-256-bit-secret'],
        ],
    ],
],
```

Requires `composer require firebase/php-jwt ^6.0`. Then enable the authenticator in config:

```php
'authenticators' => [
    'jwt' => \Enlivenapp\FlightShield\Authentication\Authenticators\JWT::class,
],
```

### Redirect URLs

```php
'redirects' => [
    'login'             => '/auth/login',
    'logout'            => '/',
    'after_login'       => '/',
    'after_register'    => '/',
    'after_logout'      => '/auth/login',
    'force_reset'       => '/auth/reset-password',
    'permission_denied' => '/auth/login',
    'group_denied'      => '/auth/login',
],
```

---

## Routes

All routes are registered under the `/auth` prefix by default (controlled by `$routePrepend` in the plugin config).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/login` | Show login form |
| POST | `/auth/login` | Process login (CSRF + rate limit) |
| GET | `/auth/logout` | Log out |
| GET | `/auth/register` | Show registration form |
| POST | `/auth/register` | Process registration (CSRF) |
| GET | `/auth/magic-link` | Show magic link request form |
| POST | `/auth/magic-link` | Send magic link email (CSRF + rate limit) |
| GET | `/auth/magic-link/verify` | Verify magic link token |
| GET | `/auth/2fa` | Show 2FA verification page (sends code) |
| POST | `/auth/2fa/verify` | Verify 2FA code (CSRF + rate limit) |
| POST | `/auth/2fa/resend` | Resend 2FA code (CSRF + rate limit) |
| GET | `/auth/activate` | Show activation page (sends email) |
| GET | `/auth/activate/verify` | Verify email activation token |

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
php runway shield:user activate    -e user@example.com
php runway shield:user deactivate  -n username
php runway shield:user delete      -e user@example.com
php runway shield:user password    -n username
php runway shield:user changename  -n username --new-name newusername
php runway shield:user changeemail -n username --new-email new@example.com
php runway shield:user addgroup    -n username -g admin
php runway shield:user removegroup -n username -g admin
```

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
```

---

### `shield:permission`

Manage permissions.

```bash
php runway shield:permission list
php runway shield:permission create -a posts.create -d "Create posts"
php runway shield:permission update -a posts.create -d "Create blog posts"
php runway shield:permission delete -a posts.create
```

---

### `shield:hmac`

Manage HMAC encryption keys and token lifecycle.

```bash
# Initial setup
php runway shield:hmac init

# Key management
php runway shield:hmac listkeys
php runway shield:hmac addkey
php runway shield:hmac removekey -k k1

# Database operations
php runway shield:hmac encrypt       # encrypt any unencrypted secrets
php runway shield:hmac decrypt       # remove encryption from all secrets
php runway shield:hmac reencrypt     # migrate all secrets to the active key

# Token lifecycle
php runway shield:hmac invalidateAll # immediately expire all HMAC tokens
```

**Key rotation workflow:**

```bash
php runway shield:hmac listkeys    # confirm current state
php runway shield:hmac addkey      # generate new key, set as active
php runway shield:hmac reencrypt   # migrate all secrets to new key
php runway shield:hmac removekey -k k1  # remove old key
```

---

## Middlewares

Apply middlewares to routes or route groups using FlightPHP's `->addMiddleware()`.

### `SessionAuthMiddleware`

Requires an active session login. Redirects to the configured login URL if not authenticated.

```php
use Enlivenapp\FlightShield\Middlewares\SessionAuthMiddleware;

$router->get('/dashboard', function() { ... })
    ->addMiddleware(new SessionAuthMiddleware($app));
```

---

### `TokenAuthMiddleware`

Authenticates via a Bearer access token in the `Authorization` header. Returns 401 JSON on failure.

```php
use Enlivenapp\FlightShield\Middlewares\TokenAuthMiddleware;

$router->get('/api/data', function() { ... })
    ->addMiddleware(new TokenAuthMiddleware($app));
```

---

### `HmacAuthMiddleware`

Authenticates via HMAC-SHA256 request signing. Reads the `Authorization` header and the raw request body to verify the signature. Returns 401 JSON on failure.

```php
use Enlivenapp\FlightShield\Middlewares\HmacAuthMiddleware;

$router->post('/api/webhook', function() { ... })
    ->addMiddleware(new HmacAuthMiddleware($app));
```

---

### `JWTAuthMiddleware`

Authenticates via a JWT Bearer token. Requires `firebase/php-jwt`. Returns 401 JSON on failure.

```php
use Enlivenapp\FlightShield\Middlewares\JWTAuthMiddleware;

$router->get('/api/secure', function() { ... })
    ->addMiddleware(new JWTAuthMiddleware($app));
```

---

### `ChainAuthMiddleware`

Tries each authenticator in the `authentication_chain` config in order. The first one that succeeds grants access. Falls through to a redirect if all fail. Useful for routes that accept both session and API clients.

```php
use Enlivenapp\FlightShield\Middlewares\ChainAuthMiddleware;

$router->get('/mixed', function() { ... })
    ->addMiddleware(new ChainAuthMiddleware($app));
```

---

### `GroupMiddleware`

Requires the authenticated user to belong to one or more of the specified groups.

```php
use Enlivenapp\FlightShield\Middlewares\GroupMiddleware;

$router->group('/admin', function() { ... }, [
    new GroupMiddleware($app, 'admin', 'superadmin'),
]);
```

---

### `PermissionMiddleware`

Requires the authenticated user to hold at least one of the specified permissions.

```php
use Enlivenapp\FlightShield\Middlewares\PermissionMiddleware;

$router->get('/posts/create', function() { ... })
    ->addMiddleware(new PermissionMiddleware($app, 'posts.create'));
```

---

### `ForcePasswordResetMiddleware`

Redirects the user to the configured `force_reset` URL if their account has the force-password-reset flag set.

```php
use Enlivenapp\FlightShield\Middlewares\ForcePasswordResetMiddleware;

$router->get('/account', function() { ... })
    ->addMiddleware(new ForcePasswordResetMiddleware($app));
```

---

### `RateLimitMiddleware`

Applied automatically to login, magic link, and 2FA routes. Counts failed login attempts per IP within the `decay_minutes` window. Returns HTTP 429 JSON if `max_attempts` is reached and the most recent failure is still within the `lockout_minutes` window.

Can also be applied manually to other routes:

```php
use Enlivenapp\FlightShield\Middlewares\RateLimitMiddleware;

$router->post('/custom-auth', function() { ... })
    ->addMiddleware(new RateLimitMiddleware($app));
```

Configure in `app/config/config.php`:

```php
'rate_limiting' => [
    'enabled'         => true,
    'max_attempts'    => 10,
    'decay_minutes'   => 30,
    'lockout_minutes' => 30,
],
```

---

## Email Setup

Flight Shield does not ship with a mailer. Provide a callback that accepts the recipient address, subject, and plain-text/HTML body:

```php
'email_sender' => function(string $to, string $subject, string $body): void {
    // Use any mailer you like — PHPMailer, Symfony Mailer, sendmail, etc.
    mail($to, $subject, $body);
},
```

The callback is invoked for 2FA codes, magic links, and email activation messages.

---

## Views

Flight Shield renders its own views by default. To override any view, create a file at the matching path inside your app:

```
app/views/enlivenapp/flight-shield/<view-name>.php
```

The following views can be overridden:

- `login.php`
- `register.php`
- `magic_link_login.php`
- `magic_link_message.php`
- `2fa_verify.php`
- `activate.php`

If the file exists in your app's view directory, it will be used instead of the bundled default.

---

## Security

- **Passwords** — hashed using `password_hash()` with `PASSWORD_DEFAULT` (bcrypt, cost 12 by default). Configurable to Argon2 via `algorithm`, `memory_cost`, `time_cost`, and `threads` options.
- **HMAC secrets** — stored encrypted with AES-256-GCM. Keys are managed in `app/config/config.php` and never stored in the database.
- **Token comparison** — all token comparisons use `hash_equals()` to prevent timing attacks.
- **HMAC replay protection** — each signed request includes a timestamp; stale requests are rejected.
- **CSRF** — all mutating auth routes (login, register, magic link, 2FA) are protected by `CsrfMiddleware` from `enlivenapp/flight-csrf`.
- **Rate limiting** — failed login attempts are tracked per IP in the `logins` table. Excessive failures result in a 429 response for the duration of the lockout window.

---

## License

MIT
