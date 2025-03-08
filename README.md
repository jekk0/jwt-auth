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

### Add custom claims to jwt token

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

### Using custom token jwt extractor instead default (Authorization: Bearer)

```shell
php artisan make:provider CustomJwtTokenExtractor
```

```php
// file /app/Providers/CustomJwtTokenExtractor.php

use Jekk0\JwtAuth\Contracts\TokenExtractor;

class CustomJwtTokenExtractor extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->app->bind(TokenExtractor::class, static function(Request $request): ?string {
            return $request->header('X-API-TOKEN');
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        //
    }
}

```

Events
```php

```

strict token rules for access token
JwtClockContract
TokenIssuerContract
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
