<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class AuthenticateTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    protected function defineEnvironment($app): void
    {
        $app['config']->set([
            'app.key' => 'D61EMLTbWd/1wRN5LeYq5G94jBcEVF/x1xeIOgjoWNc=',
            'auth.guards.user.driver' => 'jwt',
            'auth.guards.user.provider' => 'users',
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
        })->middleware('auth:user');
    }

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

    public function test_authenticate_in_tests(): void
    {
        $user = UserFactory::new()->create();
        $response = $this->actingAs($user, 'user')->postJson(
            '/api/profile',
            ['origin' => config('app.url')],
        );

        self::assertSame(200, $response->getStatusCode());
    }
}
