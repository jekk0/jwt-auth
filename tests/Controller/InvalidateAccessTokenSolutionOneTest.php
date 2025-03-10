<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\Events\JwtAccessTokenDecoded;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;
use Illuminate\Support\Facades\Event;

class InvalidateAccessTokenSolutionOneTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function () {
            Event::listen(JwtAccessTokenDecoded::class, function (JwtAccessTokenDecoded $event) {
                $refreshTokenId = $event->accessToken->payload->getReferenceTokenId();
                $refreshToken = JwtRefreshToken::find($refreshTokenId);

                if ($refreshToken === null) {
                    throw new AuthenticationException();
                }
            });
        });

        parent::setUp();
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set([
            'app.key' => 'D61EMLTbWd/1wRN5LeYq5G94jBcEVF/x1xeIOgjoWNc=',
            'auth.guards.jwt-user.driver' => 'jwt',
            'auth.guards.jwt-user.provider' => 'users',
            'auth.providers.users.model' => User::class,
            'database.default' => 'testing',
            'jwtauth.public_key' => 'iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=',
            'jwtauth.private_key' => 'BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJVQrE+pkUswP8ws40q9cwDjtiTi5SrNKAcAdISIFGNA==',
        ]);
    }

    protected function defineRoutes($router)
    {
        $router->post('api/profile', function () {
            return new JsonResponse();
        })->middleware('auth:jwt-user');
    }

    public function test_authenticate(): void
    {
        $user = UserFactory::new()->create();
        $tokenPair = auth('jwt-user')->login($user);

        $response = $this->postJson(
            '/api/profile',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $tokenPair->access->token]
        );

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_authenticate_refresh_token_removed(): void
    {
        $user = UserFactory::new()->create();
        $accessToken = $this->app->get(TokenManager::class)->makeTokenPair($user)->access;
        $response = $this->postJson(
            '/api/profile',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $accessToken->token]
        );

        self::assertSame(401, $response->getStatusCode());
    }
}
