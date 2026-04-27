# Changelog



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