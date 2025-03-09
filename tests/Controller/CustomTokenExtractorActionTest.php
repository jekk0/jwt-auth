<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\TokenExtractor;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class CustomTokenExtractorActionTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function () {
            $this->app->bind(TokenExtractor::class, function () {
                return new class () implements TokenExtractor {
                    public function __invoke(Request $request): ?string
                    {
                        return $request->header('X-API-TOKEN');
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
        $router->post('api/profile', function (Request $request) {
            return new JsonResponse(['email' => $request->user()->email]);
        })->middleware('auth:user');
    }

    public function test_authenticate_with_custom_token_extractor(): void
    {
        $user = UserFactory::new()->create();
        $accessToken = $this->app->get(TokenManager::class)->makeTokenPair($user)->access;
        $response = $this->postJson(
            '/api/profile',
            ['origin' => config('app.url')],
            ['X-API-TOKEN' => $accessToken->token]
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['email' => $user->email], $response->json());
    }
}
