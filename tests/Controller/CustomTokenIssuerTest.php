<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Jekk0\JwtAuth\Contracts\TokenIssuer;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class CustomTokenIssuerTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function () {
            $this->app->bind(TokenIssuer::class, function () {
                return new class () implements TokenIssuer {
                    public function __invoke(Request $request): string
                    {
                        return 'JwtAuthIssuer';
                    }
                };
            });
        });

        parent::setUp();
    }

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
        $router->post('api/login', function (Request $request) {
            $credentials = $request->only('email', 'password');

            $tokenPair = auth('user')->attemptOrFail($credentials);

            return new JsonResponse($tokenPair->toArray());
        });
    }

    public function test_authenticate_with_custom_issuer(): void
    {
        $password = '12345678';
        $user = UserFactory::new()->create(['password' => Hash::make($password)]);

        $response = $this->postJson(
            '/api/login',
            ['origin' => config('app.url'), 'email' => $user->email, 'password' => $password]
        );

        self::assertSame(200, $response->getStatusCode());
        $json = $response->json();

        $access = $this->app->get(TokenManager::class)->decode($json['access']['token']);
        self::assertSame('JwtAuthIssuer', $access->payload->getIssuer());

        $refresh = $this->app->get(TokenManager::class)->decode($json['refresh']['token']);
        self::assertSame('JwtAuthIssuer', $refresh->payload->getIssuer());
    }
}
