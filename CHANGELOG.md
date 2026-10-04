# Changelog

This changelog follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Entries use the `type(scope): description` form.

---

## 0.6.0 - 2026-10-03

- feat(auth): add `Auth::verifyCredentials()` for plugins that need to confirm a password without logging anyone in
  - `Result` gains a `user` slot. `verifyCredentials()` reports `success`, `reason` and the user
  - One fixed reason sentence per outcome: wrong credentials, banned, not activated
  - A not-activated account gets a fresh activation email
  - Every attempt is recorded in `auth_logins`, so `RateLimitMiddleware` counts it
- feat(activate): restore the activation page at `GET /auth/activate` with an email field and a resend button
  - `POST /auth/activate/resend` is the only thing that sends mail. Loading the page never does
  - 300-second server-side cooldown per account, with the remaining time shown on the button
  - Unknown, already-active and banned addresses get the same message and no mail
- feat(login): forward a correct password on an unactivated account to the activation page instead of a dead-end error
- feat(ratelimit): throttle the activation resend endpoint by IP
  - Every submit writes an `auth_logins` row with `id_type = 'activation_resend'`, before any early return
  - `RateLimitMiddleware` takes an optional counted `id_type`. The login, 2FA and magic-link routes are unchanged
  - The counter ignores `record_login_attempt` and is excluded from the login statistics
- feat(config): add `resend_cooldown` for the activation and 2FA resend buttons
  - Default 300 seconds, the previous hardcoded value
  - `Services\ResendCooldown` holds the read-and-wait logic. The activation page and `Email2FA` both use it instead of two copies
- test(auth): cover the 2FA resend path
  - Cooldown hit sends nothing, elapsed cooldown sends a new code, and the length comes from config
- refactor(auth): move the shared credential steps into `Services\CredentialVerifier`
  - `Session` and `Auth` both use it for the password match, the attempt row and the activation mail
- fix(auth): burn a dummy password check when the login email matches no account
  - `Session::check()` now runs the same bcrypt verify as a real check, so an unknown email cannot be told apart from a wrong password by response time
  - The equaliser hash moves to `Services\CredentialVerifier`. `Auth::verifyCredentials()` uses it too
- fix(activate): drop "Please register again" from the expired-token message
- build(deps): add PHPStan, Psalm, Infection, and roave/security-advisories to require-dev, plus composer scripts for each
- test: add detail tests across authentication, authorization, middlewares, models, passwords, and services

---

## 0.5.1 - 2026-10-02

- feat(register): derive the username from the email and ignore any username sent by the caller
- fix(register): return a normal error instead of a database error when a username is taken
- fix(register): refuse a registration attempt for the email of a soft-deleted account
- fix(register): report a failed activation email and resend the link when an unactivated account registers again
- fix(users): return a normal error when a username rename, status change, or delete fails
- fix(activate): show an error page when the activation write fails
- fix(magic-link): go back to login when the activation write fails
- test: add `UserManagementTest`

---

## 0.5.0 - 2026-10-02

- feat(register): create the account and send the activation email from one call, with no session
- fix(activate): read the account from the emailed token, so the link works in any browser or device
- refactor(activate)!: take `EmailActivator` out of the action list and remove `GET /auth/activate`

  BREAKING CHANGE: `GET /auth/activate` removed. Registration sends the activation link.

- fix(magic-link): activate an inactive account when the link is clicked, then sign the user in
- refactor(middleware): log inactive users out instead of sending them to an activation action
- test: add `EmailActivatorTest` and `AuthRegistrationTest`
- docs: describe the session-free registration and activation flow

---

## 0.4.3 - 2026-09-21

- build(deps): require `enlivenapp/flight-csrf` `^1.0`

---

## 0.4.2 - 2026-09-18

- feat(db): add `updated_at` to `auth_group_permissions`

---

## 0.4.1 - 2026-09-07

- fix(session): clear the remember-me token in `logout()` even when the session user was never resolved during the logout request. Previously the remember cookie survived when `logout()` ran without a resolved user, so visiting the login page re-authenticated the user
- fix(2fa): check for `admin.access` in `verify()` and redirect admins to `after_login_admin` after a successful code check, matching the plain login flow. Before this, every user went to `after_login`

---

## 0.4.0 - 2026-09-01

### Credits

This release ports the following CodeIgniter Shield improvements. Thanks to the
upstream authors:

- **memleakd** - hierarchical permission wildcards (`PermissionMatcher`, [shield#1327](https://github.com/codeigniter4/shield/pull/1327)), conditional auth actions (`ConditionalActionInterface`, [shield#1328](https://github.com/codeigniter4/shield/pull/1328)), magic links now respect login actions ([shield#1329](https://github.com/codeigniter4/shield/pull/1329))
- **michalsn** - ignore robots on magic links ([shield#1294](https://github.com/codeigniter4/shield/pull/1294)), bot detection on the action controller ([shield#1295](https://github.com/codeigniter4/shield/pull/1295)), HIBP range endpoint fix in `PwnedValidator` ([shield#1372](https://github.com/codeigniter4/shield/pull/1372)), firebase/php-jwt v7 ([shield#1316](https://github.com/codeigniter4/shield/pull/1316))
- **warcooft** - `recordActiveDate()` only for activated, non-banned users ([shield#1184](https://github.com/codeigniter4/shield/pull/1184))
- **tomatlscomm** - remember-me cookie refresh on token restore ([shield#1306](https://github.com/codeigniter4/shield/pull/1306))
- **najdanovicivan** - empty action class disables the action ([shield#1286](https://github.com/codeigniter4/shield/pull/1286))
- **paulbalandan** - JWT header fallback removal / static analysis ([shield#1325](https://github.com/codeigniter4/shield/pull/1325))

### Changes

- feat(authz): port upstream `PermissionMatcher` to `src/Authorization/PermissionMatcher.php`. Trailing `*` grants a node and its descendants (`users.*` ⇒ `users.create`, and not `users` itself), middle `*` matches one segment (`admin.*.post`). Standalone `*` matches one segment. Grant the `superadmin` group instead (that group bypasses all checks). Old regex-based `matchesPermission()` removed
- feat(auth): add `src/Authentication/Actions/ConditionalActionInterface.php`. Actions implementing `appliesTo(User)` are only started when it returns true
- feat(support): add `src/Support/RobotDetector.php` for crawler detection (keyword list mirrors CI4's default robot list). Magic-link tokens, 2FA codes, and activation tokens now 404 for robot User-Agents
- feat(config): add `bot_detection` (`enabled`, `user_agents`). `''` (empty string) now disables an action class
- test: add tests/Unit/Authorization/PermissionMatcherTest.php, tests/Unit/Support/RobotDetectorTest.php, tests/Unit/Authentication/SessionLoginMethodTest.php, tests/Integration/Authentication/SessionRememberMeRefreshTest.php, HIBP endpoint-pinning test in PwnedValidatorTest.php
- refactor(session): `startUpAction()` / `actionApplies()` replace the direct action-class check in `attempt()`. `setPendingLoginMethod()` / `completePendingLoginMethod()` restore the `magicLogin` session marker after a pending action completes. `recordActiveDate()` only runs for activated, non-banned users
- refactor(magic-link): `verify()` starts the login action when it applies (2FA), otherwise the register action for inactive users (activation), and only then completes the passwordless login. Robot User-Agents get a 404
- refactor(register): the registration action starts only when configured and applicable. An empty action class logs the user straight in
- refactor(2fa): `show()` and `verify()` in Email2FA / EmailActivator return 404 to robot User-Agents
- refactor(middleware): SessionAuthMiddleware logs banned users out, pushes inactive users to the activation action when one applies, otherwise logs them out, and routes pending (2FA/activation) users to their action page instead of login
- refactor(auth): AccessTokens / JWT / HmacSha256 call `recordActiveDate()` only for activated, non-banned users
- refactor(jwt): the authenticator reads the configured `jwt.header` verbatim (no implicit `Authorization` fallback when unset)
- refactor(passwords): PwnedValidator builds the endpoint via `buildEndpointUrl()` (URL unchanged: `https://api.pwnedpasswords.com/range/{prefix}`)
- build(deps): composer.json (suggest) firebase/php-jwt `^7.0` (update from ^6.0). FirebaseAdapter docblock updated. Note: php-jwt v7 invalidates tokens signed with the previous short secrets. Use ≥32-byte HMAC secrets
- docs: README documents wildcard semantics, bot detection, conditional actions, and action-disable

---

## 0.3.4 - 2026-08-28

- docs: revise the README installation, configuration, and usage sections

---

## 0.3.3 - 2026-08-28

- build: change the composer.json package type from `flightphp-plugin` to `flightphp-foundation`

---

## 0.3.2 - 2026-08-28

- refactor: rename src/Commands/ to src/commands/ for PSR-4 compliance

---

## 0.3.1 - 2026-08-24

- build: declare ext-pdo and ext-openssl directly in composer.json

---

## 0.3.0 - 2026-08-24

- build(deps): add flightphp/active-record (>=0.7) and enlivenapp/flight-sessions (^0.1) to composer.json require
- feat(authz): add `src/Authorization/Permissions.php`, a Permissions service (CRUD, deletes also remove auth_group_permissions mappings and auth_permissions_users grants/denies)
- feat(users): add `src/Services/UserManagement.php`, a user administration service exposed via `auth()->users()`
- feat(cli): add the shield:user show subcommand (groups, direct permissions incl. denies, last login, status)
- feat(cli): add the shield:group syncpermissions subcommand (replaces a group's permission set, aborts if no valid aliases)
- refactor!: remove the deprecated `src/Models/Group.php` (superseded by AuthGroup in v0.1.1, no remaining references)
- refactor(session): use enlivenapp/flight-sessions for session authentication (database-backed sessions, AES-256-GCM encrypted payloads). Session authenticator, Email2FA, and EmailActivator no longer touch $_SESSION directly.
- refactor(authz): Authorizable trait methods (addGroup/removeGroup/addPermission/removePermission) no longer take an ORM handle
- feat(auth): add users()/groups()/permissions()/stats() accessors to the Auth facade
- refactor(cli): CLI mutations delegate to services so CLI and HTTP share validation. Group delete reassigns groupless users to the user group
- docs: rewrite the README for the current architecture

---

## 0.2.6 - 2026-08-22

- build(deps): remove the enlivenapp/flight-settings dependency
- refactor(models): remove the flight-settings coupling from Models\Group (optional Settings constructor parameter and permission-matrix write-back)

---

## 0.2.5 - 2026-08-22

- refactor: move Database/ from src/Database to the package root for PSR-4 compliance (migrations and seeds)

---

## 0.2.4 - 2026-08-22

- refactor: rename src/commands/ to src/Commands/ for PSR-4 compliance

---

## 0.2.3 - 2026-08-22

- build(deps): remove the enlivenapp/flight-school dependency (Plugin.php no longer hooks a flight-school lifecycle)
- docs: restructure the README for standalone use

---

## 0.2.1 - 2026-05-05

- build(deps): update composer.json dependency constraints

---

## 0.2.0 - 2026-05-03

- feat(views): add view templates (.tpl) for all auth screens: login, register, register_success, magic_link_login, magic_link_message, 2fa_verify, activate
- fix(middleware): halt after a redirect instead of continuing
- refactor(config): migrate the plugin config to return-array format

---

## 0.1.2 - 2026-04-28

- fix(stats): UserStats::totalUsers() now counts superadmin users as well (UserModel::countAll(true))

---

## v0.1.1 - 2026-04-26

- refactor!: remove src/Entities/, src/Repositories/, and src/Migrations/
- feat: add src/Models/, src/Database/Migrations/, src/Services/, src/Views/, and tests/
- refactor(auth): all authenticators (Session, AccessTokens, HmacSha256, JWT) use Models instead of Entities/Repositories
- refactor(authz): rewrite Authorization (Authorizable, Groups) for Models
- refactor(models): mark Models\Group @deprecated in favor of AuthGroup (for backward compatibility only)
- refactor(controllers): update Login, Register, and MagicLink for the new model layer
- refactor(middleware): update references
- refactor(plugin): restructure registration in Plugin.php
- refactor(cli): update Commands for Models
- feat(models): add superadmin filtering to the User model on findById, findAllPaginated, countAll
- fix(models): update the Settings import namespace in Group.php
- docs: expand README.md
- build(deps): update composer.json dependencies

---

## v0.1.0 

- Initial build and testing.