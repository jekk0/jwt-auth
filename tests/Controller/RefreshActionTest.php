<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\Database\Factories\JwtRefreshTokenFactory;
use Jekk0\JwtAuth\Token;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class RefreshActionTest extends TestCase
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
        $router->post('api/refresh', function (Request $request) {
            $tokenPair = auth('jwt-user')->refreshTokens($request->bearerToken());

            return new JsonResponse($tokenPair->toArray());
        });
    }

    public function test_refresh(): void
    {
        $user = UserFactory::new()->create();
        $tokenPair = auth('jwt-user')->login($user);

        $response = $this->postJson(
            '/api/refresh',
            ['origin' => config('app.url')],
            ['Authorization' => 'Bearer ' . $tokenPair->refresh->token]
        );

        self::assertSame(200, $response->getStatusCode());
        $json = $response->json();

        $this->assertArrayHasKey('token', $json['access']);
        $this->assertArrayHasKey('expiredAt', $json['access']);

        /** @var Token $newAccessToken */
        $newAccessToken = $this->app->get(TokenManager::class)->decode($json['access']['token']);

        /** @var Token $newRefreshToken */
        $newRefreshToken = $this->app->get(TokenManager::class)->decode($json['refresh']['token']);

        // Access token
        self::assertNotEquals($tokenPair->access->token, $newAccessToken->token);
        self::assertNotEquals($tokenPair->access->payload->getJwtId(), $newAccessToken->payload->getJwtId());
        self::assertNotEquals($tokenPair->access->payload->getJwtId(), $newAccessToken->payload->getReferenceTokenId());
        self::assertGreaterThan($tokenPair->access->payload->getJwtId(), $newAccessToken->payload->getNotBefore());
        self::assertGreaterThan($tokenPair->access->payload->getJwtId(), $newAccessToken->payload->getIssuedAt());
        self::assertGreaterThan($tokenPair->access->payload->getJwtId(), $newAccessToken->payload->getExpiriedAt());

        self::assertSame($tokenPair->access->payload->getIssuer(), $newAccessToken->payload->getIssuer());
        self::assertSame($tokenPair->access->payload->getSubject(), $newAccessToken->payload->getSubject());
        self::assertSame($tokenPair->access->payload->getAudience(), $newAccessToken->payload->getAudience());
        self::assertSame($tokenPair->access->payload->getTokenType(), $newAccessToken->payload->getTokenType());

        // Refresh token
        self::assertNotEquals($tokenPair->refresh->token, $newRefreshToken->token);
        self::assertNotEquals($tokenPair->refresh->payload->getJwtId(), $newRefreshToken->payload->getJwtId());
        self::assertNotEquals(
            $tokenPair->refresh->payload->getJwtId(),
            $newRefreshToken->payload->getReferenceTokenId()
        );
        self::assertGreaterThan($tokenPair->refresh->payload->getJwtId(), $newRefreshToken->payload->getNotBefore());
        self::assertGreaterThan($tokenPair->refresh->payload->getJwtId(), $newRefreshToken->payload->getIssuedAt());
        self::assertGreaterThan($tokenPair->refresh->payload->getJwtId(), $newRefreshToken->payload->getExpiriedAt());

        self::assertSame($tokenPair->refresh->payload->getIssuer(), $newRefreshToken->payload->getIssuer());
        self::assertSame($tokenPair->refresh->payload->getSubject(), $newRefreshToken->payload->getSubject());
        self::assertSame($tokenPair->refresh->payload->getAudience(), $newRefreshToken->payload->getAudience());
        self::assertSame($tokenPair->refresh->payload->getTokenType(), $newRefreshToken->payload->getTokenType());
    }

    public function test_refresh_with_access_token(): void
    {
        $user = UserFactory::new()->create();
        $tokenPair = auth('jwt-user')->login($user);

        $response = $this->postJson(
            '/api/refresh', ['origin' => config('app.url')], ['Authorization' => 'Bearer ' . $tokenPair->access->token]
        );

        self::assertSame(401, $response->getStatusCode());
    }

    //todo
    public function test_refresh_token_compromised(): void
    {
        $user = UserFactory::new()->create();
        $refreshToken = $this->app->get(TokenManager::class)->makeTokenPair($user)->refresh;

        $response = $this->postJson(
            '/api/refresh', ['origin' => config('app.url')], ['Authorization' => 'Bearer ' . $refreshToken->token]
        );

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_refresh_with_empty_token(): void
    {
        $response = $this->postJson(
            '/api/refresh', ['origin' => config('app.url')], ['Authorization' => 'Bearer ']
        );

        self::assertSame(401, $response->getStatusCode());
    }
}
