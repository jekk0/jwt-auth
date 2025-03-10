<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class LoginActionTest extends TestCase
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
        $router->post('api/login', function (Request $request) {
            $credentials = $request->only('email', 'password');

            $tokenPair = auth('jwt-user')->attemptOrFail($credentials);

            return new JsonResponse($tokenPair->toArray());
        });
    }

    public function test_login_by_valid_credentials(): void
    {
        $password = '12345678';
        $user = UserFactory::new()->create(['password' => Hash::make($password)]);

        $response = $this->postJson(
            '/api/login',
            ['origin' => config('app.url'), 'email' => $user->email, 'password' => $password]
        );

        self::assertSame(200, $response->getStatusCode());
        $json = $response->json();

        // Access token acceptance
        $this->assertArrayHasKey('token', $json['access']);
        $this->assertArrayHasKey('expiredAt', $json['access']);

        $access = $this->app->get(TokenManager::class)->decode($json['access']['token']);
        self::assertSame($user->id, $access->payload->getSubject());
        self::assertSame('http://localhost/api/login', $access->payload->getIssuer());

        // Refresh token acceptance
        $this->assertArrayHasKey('token', $json['refresh']);
        $this->assertArrayHasKey('expiredAt', $json['refresh']);

        $refresh = $this->app->get(TokenManager::class)->decode($json['refresh']['token']);
        self::assertSame($user->id, $refresh->payload->getSubject());
        self::assertSame('http://localhost/api/login', $refresh->payload->getIssuer());

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }

    public function test_login_by_invalid_credentials(): void
    {
        $user = UserFactory::new()->create();

        $response = $this->postJson(
            '/api/login',
            ['origin' => config('app.url'), 'email' => $user->email, 'password' => 'invalid-password']
        );

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['message' => 'Unauthenticated.'], $response->json());
    }
}
