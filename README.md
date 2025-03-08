# jwt-auth

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
After running this command, resources from the package, such as the configuration file and migrations,
will be added to your Laravel application.

### Configure package (optional)
You should now have a `./config/jwtauth.php` file that allows you to configure the package.

### Add new tables for manage tokens
```shell
 php artisan migrate
```

### Generate certificates for sign JWT tokens

This will add the `JWT_AUTH_PUBLIC_KEY`, `JWT_AUTH_PRIVATE_KEY` keys to your app's `.env` file.
```shell
php artisan jwtauth:generate-certificates
```

For better security, you can generate and display the key values for further addition 
to environment variables in another way.

```shell
php artisan jwtauth:generate-certificates --show
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
+            'driver' => 'jwt.token',
+            'provider' => 'users',
+        ],
    ]
```

### Create the user auth controller

```shell
php artisan make:controller UserAuthController
```
### Add auth methods

```php
// app/Http/Controllers/UserAuthController.php

class UserAuthController
{
    public function login(Request $request): JsonResponse
    {
        return new JsonResponse();
    }

    public function logout(Request $request): JsonResponse
    {
        return new JsonResponse([]);
    }
}
```
### Add auth routes
```php
// routes/api.php

<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserAuthController;

Route::group(['prefix' => '/user/auth'], function () {
    Route::post('/login', [UserAuthController::class, 'login']);
    Route::post('/logout', [UserAuthController::class, 'logout'])->middleware('auth:jwt-user');
});

```

### Pruning expired JWT refresh tokens

```php
// routes/console.php

use Illuminate\Support\Facades\Schedule;
use Jekk0\JwtAuth\Model\JwtRefreshToken

Schedule::command('model:prune', ['--model' => [JwtRefreshToken::class]])->daily();
```

## Usage examples

### Login
```shell

```

### Logout


## Customization

### Customize JWT token payload

To add custom claims to a JWT token, you need to implement the interface `Jekk0\JwtAuth\Contracts\JwtCustomClaims`

```php
// file app/Models/User.php 
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Jekk0\JwtAuth\Contracts\JwtCustomClaims;

class User extends Authenticatable implements JwtCustomClaims
{
    // ...
    
    public function getJwtCustomClaims(): array
    {
        return [
            'custom' => 'value',
            'otherCustom' => 'value'
        ];
    }
}
```

### Customize JWT extractor

By implementing a custom extractor (default `Authorization: Bearer`), you can retrieve the JWT token from alternative locations 
such as request headers, query parameters or even custom request attributes.

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
}

```

### Customize JWT token issuer

By default, the JWT token issuer is taken from the request URL.
To change this behavior, override the binding for `TokenIssuer` as shown in the example below:

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

### Customize JWT clock

If there is a need to generate JWT tokens while considering the time zone or to 
modify the time-related parameters of the token in any way, you can achieve this 
by replacing the default binding. This allows you to customize how timestamps, expiration times,
or issued-at claims (iat, exp, nbf) are handled within the token.

```shell
php artisan make:provider CustomJwtClock
```

```php
// file /app/Providers/CustomJwtTokenIssuer.php

<?php

namespace App\Providers;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Jekk0\JwtAuth\Contracts\JwtClock;

class CustomJwtTokenIssuer extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(JwtClock::class, function () {
            return new class implements JwtClock {
                public function now(): DateTimeImmutable {
                    return new \DateTimeImmutable("now", "UTC")                
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

### Available events

1. Jekk0\JwtAuth\Events\JwtAttempting
2. Jekk0\JwtAuth\Events\JwtAuthenticated
3. Jekk0\JwtAuth\Events\JwtFailed 
4. Jekk0\JwtAuth\Events\JwtLogin 
5. Jekk0\JwtAuth\Events\JwtLogout 
6. Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices 
7. Jekk0\JwtAuth\Events\JwtRefresh 
8. Jekk0\JwtAuth\Events\JwtValidated

```php

```

strict token rules for access token

# Development

Run tests
Macos
```shell
XDEBUG_MODE=coverage php vendor/bin/phpunit --coverage-html ./var/cache/coverage
```

Windows
```shell
$env:XDEBUG_MODE="coverage"
php vendor/bin/phpunit --coverage-html ./var/cache/coverage
```

run phpstan
```shell
php vendor/bin/phpstan analyse

vendor/bin/phpstan analyse --generate-baseline
```

Run psalm
```shell
php vendor/bin/psalm
```

Update baseline
```shell
# This will remove fixed issues, but will not add new issues. To add new issues, use --set-baseline=....
php vendor/bin/psalm --update-baseline

# In case you want to run psalm without the baseline, run
php vendor/bin/psalm --ignore-baseline

php vendor/bin/psalm --set-baseline=psalm-baseline.xml

```

Run cs-fixer
```shell
php vendor/bin/php-cs-fixer fix
```


php vendor/bin/infection --show-mutations
