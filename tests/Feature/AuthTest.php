<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\EloquentRefreshTokenRepository;
use Jekk0\JwtAuth\Auth;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\Payload;
use Orchestra\Testbench\TestCase;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class AuthTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    private \Jekk0\JwtAuth\Contracts\Auth $auth;

    protected function setUp(): void
    {
        parent::setUp();

        $this->auth = new Auth(
            $this->app->get(TokenManager::class),
            $this->app->get('auth')->createUserProvider('users'),
            new EloquentRefreshTokenRepository()
        );
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

    public function test_create_token_pair(): void
    {
        $user = UserFactory::new()->create();

        $result = $this->auth->createTokenPair($user);

        self::assertSame($user->id, $result->access->payload->getSubject());
        self::assertSame(hash('xxh3', $user::class), $result->access->payload->getAudience());

        self::assertSame($user->id, $result->refresh->payload->getSubject());
        self::assertSame(hash('xxh3', $user::class), $result->refresh->payload->getAudience());

        self::assertSame($result->access->payload->getReferenceTokenId(), $result->refresh->payload->getJwtId());
        self::assertSame($result->refresh->payload->getReferenceTokenId(), $result->access->payload->getJwtId());

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }

    public function test_retrieve_by_credentials_user_exists(): void
    {
        $password = '12345678';
        $user = UserFactory::new()->create(['password' => Hash::make($password)]);

        $result = $this->auth->retrieveByCredentials(['email' => $user->email, 'password' => $password]);

        self::assertTrue($user->is($result));
    }

    public function test_retrieve_by_credentials_user_not_exists(): void
    {
        $credentials = ['email' => 'example.com', 'password' => ''];

        $result = $this->auth->retrieveByCredentials($credentials);

        $this->assertNull($result);
    }

    public function test_has_valid_credentials(): void
    {
        $password = '12345678';
        $user = UserFactory::new()->create(['password' => Hash::make($password)]);
        $credentials = ['email' => $user->email, 'password' => $password];

        $result = $this->auth->hasValidCredentials($user, $credentials);

        self::assertTrue($result);
    }

    public function test_has_invalid_credentials(): void
    {
        $password = '12345678';
        $user = UserFactory::new()->create(['password' => Hash::make($password)]);
        $credentials = ['email' => $user->email, 'password' => 'invalid'];

        $result = $this->auth->hasValidCredentials($user, $credentials);

        self::assertFalse($result);
    }

    public function test_retrieve_by_payload(): void
    {
        $user = UserFactory::new()->create();

        $result = $this->auth->retrieveByPayload(new Payload(['sub' => $user->id, 'aud' => \hash('xxh3', $user::class)]));

        self::assertTrue($user->is($result));
    }

    public function test_retrieve_by_payload_user_not_found(): void
    {
        $result = $this->auth->retrieveByPayload(new Payload(['sub' => 'id', 'aud' => 'asd']));

        self::assertNull($result);
    }

    public function test_revoke_refresh_token(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create($jti, $accessTokenJti, $subject, $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);

        $this->auth->revokeRefreshToken($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);
    }

    public function test_revoke_all_refresh_tokens(): void
    {
        $user = UserFactory::new()->create();
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create('1', '4', $user->id, $expiredAt);
        (new EloquentRefreshTokenRepository())->create('2', '5', $user->id, $expiredAt);
        (new EloquentRefreshTokenRepository())->create('3', '6', 'other-subject', $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);

        $this->auth->revokeAllRefreshTokens($user);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }
}
