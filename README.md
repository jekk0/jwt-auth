# Laravel JWT Authentication

![Build Status](https://github.com/jekk0/jwt-auth/actions/workflows/pipeline.yml/badge.svg?branch=main)
[![Coverage Status](https://codecov.io/gh/jekk0/jwt-auth/branch/main/graphs/badge.svg)](https://codecov.io/gh/jekk0/jwt-auth)
[![Latest Stable Version](https://poser.pugx.org/jekk0/jwt-auth/v/stable)](https://packagist.org/packages/jekk0/jwt-auth)
[![Total Downloads](https://poser.pugx.org/jekk0/jwt-auth/downloads)](https://packagist.org/packages/jekk0/jwt-auth)
[![PHP Version Require](http://poser.pugx.org/jekk0/jwt-auth/require/php)](https://packagist.org/packages/jekk0/jwt-auth)
[![License](http://poser.pugx.org/jekk0/jwt-auth/license)](https://packagist.org/packages/jekk0/jwt-auth)

## Installation

```shell
composer require jekk0/jwt-auth
```

Optionally, install the paragonie/sodium_compat package from composer
if your php env does not have libsodium installed:

```shell
composer require paragonie/sodium_compat
```
## Package configuration

### Publish package resources

```shell
php artisan vendor:publish --provider=Jekk0\JwtAuth\JwtAuthServiceProvider
```

After running this command, resources from the package, such as the configuration file and migrations, will be added to your Laravel application.
### Configure package (optional)

You should now have a `./config/jwtauth.php` file that allows you to configure the package.
### Create a new table for manage refresh tokens

Run the migrate command to create the table `jwt_refresh_tokens` needed to store JWT refresh token data

```shell
php artisan migrate
```
### Generate certificates and add configuration to your .env file

```shell
$ php artisan jwtauth:generate-certificates

Copy and paste the content below into your .env file:

JWT_AUTH_PUBLIC_KEY=zvZFv5w3DuY3rZK901cnMM8UmV...
JWT_AUTH_PRIVATE_KEY=GaD9g0Xk5QHpzIJOIuEbUEOyJXQSpN...
```
## Laravel application configuration

### Configure auth guard

Make the following changes to the file:

```diff
// file /config/auth.php

    'guards' => [
-        'web' => [
-            'driver' => 'session',
-            'provider' => 'users',
-        ],
+        'jwt-user' => [
+            'driver' => 'jwt',
+            'provider' => 'users',
+        ],
    ]
```
**A JWT user can be any model that implements the native laravel interface \Illuminate\Contracts\Auth\Authenticatable**

### Create the user auth controller

```shell
php artisan make:controller UserAuthController
```

```php
// app/Http/Controllers/UserAuthController.php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserAuthController
{
    public function login(Request $request): JsonResponse
    {
        $credentials = $request->only('email', 'password');

//        $tokens = auth('jwt-user')->attempt($credentials);
//        if (is_null($tokens)) {
//            throw new AuthenticationException();
//        }

        $tokens = auth('jwt-user')->attemptOrFail($credentials);

        return new JsonResponse($tokens->toArray());
    }

    public function refresh(Request $request): JsonResponse
    {
        $tokens = auth('jwt-user')->refreshTokens($request->get('token', ''));

        return new JsonResponse($tokens->toArray());
    }

    public function logout(): JsonResponse
    {
        auth('jwt-user')->logout();

        return new JsonResponse();
    }

    public function logoutFromAllDevices(): JsonResponse
    {
        auth('jwt-user')->logoutFromAllDevices();

        return new JsonResponse();
    }

    public function profile(Request $request): JsonResponse
    {
        return new JsonResponse(['name' => $request->user()->name, 'email' => $request->user()->email]);
    }
}

```
### Add auth routes

```php
// routes/api.php

<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserAuthController;

Route::group(['prefix' => '/auth/user'], function () {
    Route::post('/login', [UserAuthController::class, 'login']);
    Route::post('/refresh', [UserAuthController::class, 'refresh']);
    Route::post('/logout', [UserAuthController::class, 'logout'])->middleware('auth:jwt-user');
    Route::post('/logout/all', [UserAuthController::class, 'logoutFromAllDevices'])->middleware('auth:jwt-user');
    Route::get('/profile', [UserAuthController::class, 'profile'])->middleware('auth:jwt-user');
});

```
### Pruning expired JWT refresh tokens

```php
// routes/console.php

use Illuminate\Support\Facades\Schedule;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

Schedule::command('model:prune', ['--model' => [JwtRefreshToken::class]])->daily();
```

## Refresh Token Flow

The Refresh Token Flow is a mechanism that allows users to obtain a new access token without re-authenticating.
It is used to maintain sessions securely while keeping access tokens short-lived.
### User Authentication

The user logs in with their credentials (e.g., email/password)
The server verifies the credentials and issues:
- A short-lived access token (e.g., valid for 15 minutes).
- A long-lived refresh token (e.g., valid for several days or weeks).

**Authentication request:**
```shell
curl --location 'localhost:8000/api/auth/user/login' \
--header 'Accept: application/json' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "user@example.com",
    "password": "user"
}'
```

**Authentication response:**
```json
{
    "access": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
        "expiredAt": 1741606251
    },
    "refresh": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
        "expiredAt": 1744197351
    }
}
```

An **access token** is used to authenticate and authorize users, granting them access to protected resources
without needing to repeatedly log in. It contains user identity and custom claims and is typically
short-lived to enhance security.

A **refresh token** is used to obtain a new access token without requiring the user to log in again.
It is long-lived and helps maintain user sessions securely while minimizing exposure of credentials.
### Accessing Protected Resources

- The client includes the access token in the Authorization header (Bearer <access_token>) to make authenticated API requests.
- The server validates the token and grants access.

**User profile request:**
```shell
curl --location 'localhost:8000/api/auth/user/profile' \
--header 'Accept: application/json' \
--header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```
### Token Expiration & Refresh Request

- When the access token expires, the client sends a request to the token refresh endpoint.
- The request includes the refresh token.
- The server verifies the refresh token (e.g., checks its validity and ensures it is not revoked).
- If valid, the server issues a new access token and refresh token.
- The client replaces the expired access token and refresh token with new ones.

**Refresh request:**
```shell
curl --location 'localhost:8000/api/auth/user/refresh' \
--header 'Accept: application/json' \
--header 'Content-Type: application/json' \
--data '{
    "token": "YOUR_REFRESH_TOKEN"
}'
```

**Refresh response**:
```json
{
    "access": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
        "expiredAt": 1741606046
    },
    "refresh": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
        "expiredAt": 1744197146
    }
}
```
### Logout or Token Revocation

- If the user logs out, the refresh token will be revoked (removed from a database).
- If a refresh token is compromised, see [Refresh token compromised](#refresh-token-compromised)

**Logout request:**
```shell
curl --location --request POST 'localhost:8000/api/auth/user/logout' \
--header 'Accept: application/json' \
--header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

**Logout from all devices request:**
```shell
curl --location --request POST 'localhost:8000/api/auth/user/logout/all' \
--header 'Accept: application/json' \
--header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```
## Security

### Access token invalidation

Since the lifetime of an access token is relatively short (up to one hour, with a default of 15 minutes), the package does not invalidate the access token upon logout. Instead, invalidation is only performed for the refresh token to avoid additional database query overhead.

It is assumed that the frontend will simply remove the access token from storage upon logout,
allowing it to expire naturally. However, if token invalidation needs to be enforced on every request, this can be implemented using an event-based mechanism.

**Make event listener:**
```php
php artisan make:listener AccessTokenInvalidation
```

```php
<?php

namespace App\Listeners;

use Illuminate\Auth\AuthenticationException;
use Jekk0\JwtAuth\Events\JwtAccessTokenDecoded;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

class AccessTokenInvalidation
{

    public function handle(JwtAccessTokenDecoded $event): void
    {
        // Solution 1
        $accessTokenId = $event->accessToken->payload->getJwtId();
        $refreshToken = JwtRefreshToken::whereAccessTokenJti($accessTokenId)->first();

        if ($refreshToken === null) {
            throw new AuthenticationException();
        }
        
        // Solution 2
        // $refreshTokenId = $event->accessToken->payload->getReferenceTokenId();
        // $refreshToken = JwtRefreshToken::find($refreshTokenId);
        //
        // if ($refreshToken === null) {
        //     throw new AuthenticationException();
        // }

        // Solution 3
        // If you do not want to use a relational database, you can implement token invalidation using two events:
        // 1. On Logout (JwtLogout Event) – Store the access token in a blacklist for its remaining lifetime using a fast storage solution, such as Redis or MongoDB.
        // 2. On Token Decoding (JwtAccessTokenDecoded Event) – Check whether the token is in the blacklist before processing it.
    }
}
```
### Refresh token compromised

If a refresh token is reused (i.e., an old token is attempted after a new one has been issued), it is a strong indication of a token theft or replay attack. Here’s what to do:

1. Immediately Revoke All Active Tokens
    - Revoke both the newly issued and previously used refresh tokens.
    - Invalidate any active access tokens associated with the compromised refresh token.
2. Notify the User
    - If a stolen refresh token was used, inform the user about a possible security breach.
    - Recommend changing their password if suspicious activity is detected.

**Make event listener:**
```php
php artisan make:listener RefreshTokenCompromised
```

```php
<?php

namespace App\Listeners;

use Illuminate\Support\Facades\Log;
use Jekk0\JwtAuth\Events\JwtRefreshTokenCompromised;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

class RefreshTokenCompromised
{
    public function handle(JwtRefreshTokenCompromised $event): void
    {
        Log::info("Guard $event->guard: Refresh token compromised.");

        // Get all user refresh tokens
        $affectedRefreshTokens = JwtRefreshToken::where('subject', '=', (string)$event->user->id)->get();

        // If you use Access token invalidation then this step is not needed
        foreach ($affectedRefreshTokens as $refreshToken) {
            $accessTokenId = $refreshToken->access_token_jti;

            // Invalidate access tokens
            // ...
        }

        // Invalidate refresh tokens related to user
        JwtRefreshToken::whereIn('jti', $affectedRefreshTokens->pluck('jti'))->delete();

        // Send notification to user
        //...
    }
}
```
## Customization

### Customize JWT token payload

To add custom claims to a JWT token, you need to implement the interface `Jekk0\JwtAuth\Contracts\JwtCustomClaims`

```php
// file app/Models/User.php 
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Jekk0\JwtAuth\Contracts\CustomClaims;

class User extends Authenticatable implements CustomClaims
{
    // ...
    
    public function getJwtCustomClaims(): array
    {
        return [
            'role' => 'user',
            'name' => 'John'
        ];
    }
}

//...
// Get custom claims in controller 

$role = auth('jwt-user')->getAccessToken()->payload['role']
$name = auth('jwt-user')->getAccessToken()->payload['name']
```

### Customize JWT extractor

By implementing a custom extractor (default `Authorization: Bearer`), you can retrieve the JWT token from alternative locations such as request headers, query parameters or even custom request attributes.

```shell
php artisan make:provider CustomJwtTokenExtractor
```

```php
// file /app/Providers/CustomJwtTokenExtractor.php

<?php

namespace App\Providers;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Jekk0\JwtAuth\Contracts\TokenExtractor;

class CustomJwtTokenExtractor extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(TokenExtractor::class, function () {
            return new class implements TokenExtractor {
                public function __invoke(Request $request): ?string
                {
                    return $request->header('X-API-TOKEN');
                }
            };
        });
    }
    
    public function boot(): void
    {
        //
    }
}
```
### Customize JWT token issuer

By default, the JWT token issuer is taken from the request URL.
To change this behavior, override the binding for `Jekk0\JwtAuth\Contracts\TokenExtractor` as shown in the example below:

```shell
php artisan make:provider CustomJwtTokenIssuer
```

```php
// file /app/Providers/CustomJwtTokenIssuer.php

<?php

namespace App\Providers;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Jekk0\JwtAuth\Contracts\TokenIssuer;

class CustomJwtTokenIssuer extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(TokenIssuer::class, function () {
            return new class implements TokenIssuer {
                public function __invoke(Request $request): string
                {
                    return 'CustomIssuer';
                }
            };
        });
    }
    
    public function boot(): void
    {
        //
    }
}

```

### Available events:

1. Jekk0\JwtAuth\Events\JwtAccessTokenDecoded
2. Jekk0\JwtAuth\Events\JwtAttempting
3. Jekk0\JwtAuth\Events\JwtAuthenticated
4. Jekk0\JwtAuth\Events\JwtFailed
5. Jekk0\JwtAuth\Events\JwtLogin
6. Jekk0\JwtAuth\Events\JwtLogout
7. Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices
8. Jekk0\JwtAuth\Events\JwtRefreshTokenCompromised
9. Jekk0\JwtAuth\Events\JwtRefreshTokenDecoded
10. Jekk0\JwtAuth\Events\JwtTokensRefreshed
11. Jekk0\JwtAuth\Events\JwtValidated

## Functionally testing a JWT protected api

**Login with Laravel's default `actingAs` method:**

```php
public function test_authenticate_in_tests(): void
{
    $user = UserFactory::new()->create();
    $response = $this->actingAs($user, 'YOUR-GUARD-NAME')->postJson(
        '/api/profile',
        ['origin' => config('app.url')],
    );

    self::assertSame(200, $response->getStatusCode());
}
```

**Login with JWT guard:**

```php
public function test_logout(): void
{
    $user = UserFactory::new()->create();
    auth('user')->login($user);
    
    $response = $this->postJson('/api/logout', ['origin' => config('app.url')],);
    self::assertSame(200, $response->getStatusCode());
}
```

**Manually generate a JWT token for end-to-end testing:**

```php
public function test_authenticate(): void
    {
        $user = UserFactory::new()->create();
        $accessToken = $this->app->get(TokenManager::class)->makeTokenPair($user)->access;
        
        $response = $this->postJson(
            '/api/profile',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $accessToken->token]
        );

        self::assertSame(200, $response->getStatusCode());
    }
```
