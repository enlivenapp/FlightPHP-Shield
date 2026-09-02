# Changelog

---

## 0.4.0 - 2026-09-01

### Credits

This release ports the following CodeIgniter Shield improvements. Thanks to the
upstream authors:

- **memleakd** — hierarchical permission wildcards (`PermissionMatcher`, [shield#1327](https://github.com/codeigniter4/shield/pull/1327)); conditional auth actions (`ConditionalActionInterface`, [shield#1328](https://github.com/codeigniter4/shield/pull/1328)); magic links now respect login actions ([shield#1329](https://github.com/codeigniter4/shield/pull/1329))
- **michalsn** — ignore robots on magic links ([shield#1294](https://github.com/codeigniter4/shield/pull/1294)); bot detection on the action controller ([shield#1295](https://github.com/codeigniter4/shield/pull/1295)); HIBP range endpoint fix in `PwnedValidator` ([shield#1372](https://github.com/codeigniter4/shield/pull/1372)); firebase/php-jwt v7 ([shield#1316](https://github.com/codeigniter4/shield/pull/1316))
- **warcooft** — `recordActiveDate()` only for activated, non-banned users ([shield#1184](https://github.com/codeigniter4/shield/pull/1184))
- **tomatlscomm** — remember-me cookie refresh on token restore ([shield#1306](https://github.com/codeigniter4/shield/pull/1306))
- **najdanovicivan** — empty action class disables the action ([shield#1286](https://github.com/codeigniter4/shield/pull/1286))
- **paulbalandan** — JWT header fallback removal / static analysis ([shield#1325](https://github.com/codeigniter4/shield/pull/1325))

### Changes

**Added:**
  - src/Authorization/PermissionMatcher.php : faithful port of upstream `PermissionMatcher`. Trailing `*` grants a node and all descendants (`users.*` ⇒ `users.create`, … but never `users`); middle `*` matches exactly one segment (`admin.*.post`). Standalone `*` no longer matches everything — grant the `superadmin` group instead (that group already bypasses all checks). Old regex-based `matchesPermission()` removed
  - src/Authentication/Actions/ConditionalActionInterface.php : actions implementing `appliesTo(User)` are only started when it returns true
  - src/Support/RobotDetector.php : crawler detection (keyword list mirrors CI4's default robot list); magic-link tokens, 2FA codes, and activation tokens now 404 for robot User-Agents
  - Config: `bot_detection` (`enabled`, `user_agents`); `''` (empty string) now disables an action class
  - tests/Unit/Authorization/PermissionMatcherTest.php, tests/Unit/Support/RobotDetectorTest.php, tests/Unit/Authentication/SessionLoginMethodTest.php, tests/Integration/Authentication/SessionRememberMeRefreshTest.php, HIBP endpoint-pinning test in PwnedValidatorTest.php

**Modified:**
  - Session authenticator: `startUpAction()` / `actionApplies()` replace the direct action-class check in `attempt()`; `setPendingLoginMethod()` / `completePendingLoginMethod()` restore the `magicLogin` session marker after a pending action completes; `recordActiveDate()` only runs for activated, non-banned users
  - MagicLinkController::verify() : starts the login action when it applies (2FA), otherwise the register action for inactive users (activation), and only then completes the passwordless login — robots are never served tokens
  - RegisterController : registration action starts only when configured and applicable; empty action class logs the user straight in
  - Email2FA / EmailActivator : `show()` and `verify()` return 404 to robot User-Agents
  - SessionAuthMiddleware : banned users are logged out; inactive users are pushed to the activation action when one applies, otherwise logged out; pending (2FA/activation) users are routed to their action page instead of login
  - AccessTokens / JWT / HmacSha256 : `recordActiveDate()` only for activated, non-banned users
  - JWT authenticator : reads the configured `jwt.header` verbatim (no implicit `Authorization` fallback when unset)
  - PwnedValidator : endpoint built via `buildEndpointUrl()` (URL unchanged — `https://api.pwnedpasswords.com/range/{prefix}`)
  - composer.json (suggest) : firebase/php-jwt `^7.0` (update from ^6.0); FirebaseAdapter docblock updated. Note: php-jwt v7 invalidates tokens signed with the previous short secrets — use ≥32-byte HMAC secrets
  - README : wildcard semantics, bot detection, conditional actions, and action-disable documented

---

## 0.3.1 - 2026-08-24

### Changes

**Added:**
  - composer.json : ext-pdo and ext-openssl declared directly

---

## 0.3.0 - 2026-08-24

### Changes

**Added:**
  - composer.json : flightphp/active-record (>=0.7) and enlivenapp/flight-sessions (^0.1) added to require
  - src/Authorization/Permissions.php : Permissions service (CRUD; deletes also remove auth_group_permissions mappings and auth_permissions_users grants/denies)
  - src/Services/UserManagement.php : user administration service exposed via `auth()->users()`
  - shield:user show subcommand (groups, direct permissions incl. denies, last login, status)
  - shield:group syncpermissions subcommand (replaces a group's permission set; aborts if no valid aliases)

**Deleted:**
  - src/Models/Group.php : deprecated class removed (superseded by AuthGroup in v0.1.1; no remaining references)

**Modified:**
  - Session authentication now uses enlivenapp/flight-sessions (database-backed sessions, AES-256-GCM encrypted payloads). Session authenticator, Email2FA, and EmailActivator no longer touch $_SESSION directly.
  - Authorizable trait methods (addGroup/removeGroup/addPermission/removePermission) no longer take an ORM handle
  - Auth facade gained users()/groups()/permissions()/stats() accessors
  - CLI mutations delegate to services so CLI and HTTP share validation; group delete reassigns groupless users to the user group
  - README rewritten for the current architecture

---

## 0.2.6 - 2026-08-22

### Changes

**Deleted:**
  - enlivenapp/flight-settings dependency

**Modified:**
  - Models\Group : removed its flight-settings coupling (optional Settings constructor parameter and permission-matrix write-back)

---

## 0.2.5 - 2026-08-22

### Changes

**Modified:**
  - Database/ moved from src/Database to package root for PSR-4 compliance (migrations and seeds)

---

## 0.2.4 - 2026-08-22

### Changes

**Modified:**
  - src/commands/ renamed to src/Commands/ for PSR-4 compliance

---

## 0.2.3 - 2026-08-22

### Changes

**Deleted:**
  - enlivenapp/flight-school dependency (Plugin.php no longer hooks a flight-school lifecycle)

**Modified:**
  - README restructured for standalone use

---

## 0.2.1 - 2026-05-05

### Changes

**Modified:**
  - composer.json dependency constraints updated

---

## 0.2.0 - 2026-05-03

### Changes

**Added:**
  - View templates (.tpl) for all auth screens: login, register, register_success, magic_link_login, magic_link_message, 2fa_verify, activate

**Modified:**
  - Middlewares halt correctly after redirect instead of continuing
  - Plugin config migrated to return-array format

---

## 0.1.2 - 2026-04-28

### Changes

**Modified:**
  - UserStats::totalUsers() now counts superadmin users as well (UserModel::countAll(true))

---

## v0.1.1 - 2026-04-26

### Changes

**Deleted:**                                                         
  - src/Entities/                                                                      
  - src/Repositories/ 
  - src/Migrations/                         
                                                                              
**Added:**                                                                      
  - src/Models/       
  - src/Database/Migrations/                                               
  - src/Services/                                                             
  - src/Views/               
  - tests/                                                                    
                                                                              
**Modified:**       
  - All authenticators (Session, AccessTokens, HmacSha256, JWT) uses Models instead of Entities/Repositories                                 
  - Authorization (Authorizable, Groups) : rewritten for Models
  - Models\Group : marked @deprecated in favor of AuthGroup (for backward compatibility only)
  - Controllers (Login, Register, MagicLink) : updated for new model layer    
  - Middlewares : updated references                                          
  - Plugin.php : restructured registration                                    
  - Commands : updated for Models                                             
  - User model : added superadmin filtering on findById, findAllPaginated, countAll
  - Group.php : updated Settings import namespace                             
  - README.md : expanded                                                      
  - composer.json : updated dependencies 


  #### Tests

  PHPUnit 11.5.55 by Sebastian Bergmann and contributors.

Runtime:       PHP 8.3.6
Configuration: /var/www/flight/vendor/enlivenapp/flight-shield/phpunit.xml

.....................................................SSSSSS....  63 / 374 ( 16%)
............................................................... 126 / 374 ( 33%)
............................................................... 189 / 374 ( 50%)
............................................................... 252 / 374 ( 67%)
............................................................... 315 / 374 ( 84%)
...........................................................     374 / 374 (100%)

Time: 00:02.839, Memory: 14.00 MB

OK, but some tests were skipped!
Tests: 374, Assertions: 597, Skipped: 6.

There were 6 skipped tests:

     1) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :generateTokenIncludesSubClaimFromUserId
     firebase/php-jwt not installed

     2) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :generateTokenMergesAdditionalClaims
     firebase/php-jwt not installed

     3) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :parseReturnsPayloadWithCorrectSub
     firebase/php-jwt not installed

     4) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :parseWithExpiredTokenThrows
     firebase/php-jwt not installed

     5) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :issueCreatesTokenWithoutRequiringUser
     firebase/php-jwt not installed

     6) Enlivenapp\FlightShield\Tests\Unit\Authentication\JWTManagerTest:
     :generateTokenAndParseRoundtrip
     firebase/php-jwt not installed



---

## v0.1.0 

- Initial build and testing.