<?php

namespace Jekk0\JwtAuth\Tests\Controller;

use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Jekk0\JwtAuth\Contracts\Clock;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class CustomClockTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    private int $timestamp = 1700000000;
    private int $ttlAccess = 100;
    private int $ttlRefresh = 1000;

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function () {
            $this->app->bind(Clock::class, function () {
                $clock = new class () implements Clock {
                    public static int $timestamp;
                    public function now(): \DateTimeImmutable
                    {
                        return new \DateTimeImmutable('@' . self::$timestamp);
                    }
                };

                $clock::$timestamp = $this->timestamp;
                return $clock;
            });
        });

        parent::setUp();

        JWT::$timestamp = $this->timestamp;
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        JWT::$timestamp = null;
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
            'jwtauth.ttl.access' => $this->ttlAccess,
            'jwtauth.ttl.refresh' => $this->ttlRefresh,
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

    public function test_authenticate_with_custom_clock(): void
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
        self::assertSame($this->timestamp, $access->payload->getIssuedAt());
        self::assertSame($this->timestamp, $access->payload->getNotBefore());
        self::assertSame($this->timestamp + $this->ttlAccess, $access->payload->getExpiriedAt());

        $refresh = $this->app->get(TokenManager::class)->decode($json['refresh']['token']);
        self::assertSame($this->timestamp, $refresh->payload->getIssuedAt());
        self::assertSame($this->timestamp, $refresh->payload->getNotBefore());
        self::assertSame($this->timestamp + $this->ttlRefresh, $refresh->payload->getExpiriedAt());
    }
}
