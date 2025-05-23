<?php

namespace Jekk0\JwtAuth;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Jekk0\JwtAuth\Console\Commands\GenerateCertificates;
use Illuminate\Support\Facades\Auth as AuthFacade;
use Jekk0\JwtAuth\Contracts\TokenExtractor as TokenExtractorContract;
use Jekk0\JwtAuth\Contracts\TokenIssuer as TokenIssuerContract;
use Jekk0\JwtAuth\Contracts\RequestGuard as RequestGuardContract;
use Jekk0\JwtAuth\Contracts\TokenManager as TokenManagerContract;
use Jekk0\JwtAuth\Contracts\Clock as JwtClockContract;

final class JwtAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (!$this->app->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../config/jwtauth.php', 'jwtauth');
        }

        $this->app->bind(TokenExtractorContract::class, TokenExtractor::class);
        $this->app->bind(TokenIssuerContract::class, TokenIssuer::class);
        $this->app->bind(JwtClockContract::class, static function () {
            return new JwtClock(new \DateTimeZone('UTC'));
        });

        $this->app->singleton(TokenManagerContract::class, static function (Application $app) {
            /** @phpstan-ignore-next-line */
            return new TokenManager($app->get(JwtClockContract::class), $app['config']['jwtauth']);
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            /** @phpstan-ignore-next-line */
            $publishesMigrationsMethod = method_exists($this, 'publishesMigrations')
                ? 'publishesMigrations' : 'publishes';

            $this->$publishesMigrationsMethod([
                __DIR__ . '/../database/migrations' => database_path('migrations')
            ]);

            $this->publishes([__DIR__ . '/../config/jwtauth.php' => config_path('jwtauth.php')]);
            $this->commands([GenerateCertificates::class]);
        }

        $this->configureGuard();
    }

    private function configureGuard(): void
    {
        AuthFacade::resolved(function (AuthManager $auth) {
            $auth->extend('jwt', function (Application $app, string $name, array $config) use ($auth) {
                /** @var Request $request */
                $request = $app->get('request');
                $tokenManager = $app->get(TokenManagerContract::class);
                $tokenManager->setTokenIssuer(($app->get(TokenIssuerContract::class))($request));
                $guard = new RequestGuard(
                    $name,
                    new Auth(
                        $tokenManager,
                        /** @phpstan-ignore-next-line */
                        $auth->createUserProvider($config['provider']),
                        new EloquentRefreshTokenRepository()
                    ),
                    $app->get(TokenExtractorContract::class),
                    $app->get('events'),
                    $request
                );

                return tap($guard, function (RequestGuardContract $guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }
}
