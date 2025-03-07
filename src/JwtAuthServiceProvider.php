<?php

namespace Jekk0\JwtAuth;

use Carbon\FactoryImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Jekk0\JwtAuth\Console\Commands\GenerateCertificates;
use Illuminate\Support\Facades\Auth;
use Jekk0\JwtAuth\Contracts\TokenExtractor as TokenExtractorContract;
use Jekk0\JwtAuth\Contracts\TokenIssuer as TokenIssuerContract;
use Jekk0\JwtAuth\Contracts\RequestGuard as RequestGuardContract;
use Jekk0\JwtAuth\Contracts\TokenManager as TokenManagerContract;

final class JwtAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (!$this->app->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../config/jwtauth.php', 'jwtauth');
        }

        $this->app->singleton(TokenManagerContract::class, function (Application $app) {
            return new TokenManager(FactoryImmutable::getDefaultInstance(), $app['config']['jwtauth']);
        });

        $this->app->bind(TokenExtractorContract::class, TokenExtractor::class);
        $this->app->bind(TokenIssuerContract::class, TokenIssuer::class);
    }

    public function boot(): void
    {
        // todo duplicate
        $this->publishesMigrations([
            __DIR__ . '/../database/migrations' => database_path('migrations')
        ]);

        $this->publishes([
            __DIR__ . '/../config/jwtauth.php' => config_path('jwtauth.php')
        ]);

        if ($this->app->runningInConsole()) {
            $this->commands([
                GenerateCertificates::class
            ]);
        }

        $this->configureGuard();
    }

    private function configureGuard(): void
    {
        Auth::resolved(function (AuthManager $auth) {
            $auth->extend('jwt', function (Application $app, string $name, array $config) use ($auth) {
                $tokenManager = $app->get(TokenManagerContract::class);
                $tokenManager->setTokenIssuer(($app->get(TokenIssuerContract::class))($app->get('request')));
                $guard = new RequestGuard(
                    new JwtAuth(
                        $tokenManager,
                        $auth->createUserProvider($config['provider']),
                        new EloquentRefreshTokenRepository()
                    ),
                    $app->get(TokenExtractorContract::class),
                    $app->get('events'),
                    $app->get('request')
                );

                return tap($guard, function (RequestGuardContract $guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }
}
