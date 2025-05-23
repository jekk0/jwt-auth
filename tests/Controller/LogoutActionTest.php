<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\RefreshTokenStatus;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class LogoutActionTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

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
        $router->post('api/logout', function () {
            auth('jwt-user')->logout();
            return new JsonResponse(['message' => 'Successfully logged out']);
        })->middleware('auth:jwt-user');

        $router->post('api/logout/all', function () {
            auth('jwt-user')->logoutFromAllDevices();
            return new JsonResponse(['message' => 'Successfully logged out from all devices']);
        })->middleware('auth:jwt-user');
    }

    public function test_logout(): void
    {
        $user = UserFactory::new()->create();

        $refreshToken = auth('jwt-user')->login($user)->refresh;

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($refreshToken->payload->getJwtId())->status);

        $response = $this->postJson('/api/logout', ['origin' => config('app.url')], );

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['message' => 'Successfully logged out'], $response->json());

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);
    }

    public function test_logout_by_without_token(): void
    {
        $response = $this->postJson(
            '/api/logout',
            ['origin' => config('app.url')],
        );

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['message' => 'Unauthenticated.'], $response->json());
    }

    public function test_logout_by_with_invalid_token(): void
    {
        $token = <<<'TOKEN'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
TOKEN;

        $response = $this->postJson(
            '/api/logout',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $token]
        );
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['message' => 'Unauthenticated.'], $response->json());
    }

    public function test_logout_with_invalid_payload_for_user(): void
    {
        UserFactory::new()->create(); // id = 1
        $differentUser = new class () extends User {
            public int $id = 1;
        };

        $token = $this->app->get(TokenManager::class)->makeTokenPair($differentUser)->access;

        $response = $this->postJson(
            '/api/logout',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $token->token]
        );

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_logout_from_all_devices(): void
    {
        $user = UserFactory::new()->create();
        // Create first session
        auth('jwt-user')->login($user);
        // Create second session
        auth('jwt-user')->login($user);
        // Create third session
        auth('jwt-user')->login($user);

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);
        $tokens = JwtRefreshToken::all();
        self::assertSame(RefreshTokenStatus::Active, $tokens->get(0)->status);
        self::assertSame(RefreshTokenStatus::Active, $tokens->get(1)->status);
        self::assertSame(RefreshTokenStatus::Active, $tokens->get(2)->status);

        $response = $this->postJson('/api/logout/all', ['origin' => config('app.url')]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['message' => 'Successfully logged out from all devices'], $response->json());

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);
    }
}
