<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Illuminate\Auth\EloquentUserProvider;
use Jekk0\JwtAuth\Contracts\RefreshTokenRepository;
use Jekk0\JwtAuth\Contracts\TokenManager as TokenManagerContract;
use Jekk0\JwtAuth\Auth;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenManager;
use Jekk0\JwtAuth\TokenPair;
use Lcobucci\Clock\SystemClock;
use PHPUnit\Framework\TestCase;
use Workbench\App\Models\User;

class AuthTest extends TestCase
{
    public function test_create_token_pair(): void
    {
        $user = $this->createMock(User::class);
        $tokenPair = new TokenPair(
            new Token('jwt', new Payload(['jti' => '1', 'sub' => 1, 'exp' => time()])),
            new Token('jwt', new Payload(['jti' => '2', 'sub' => 1, 'exp' => time()])),
        );

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $tokenManager = $this->createMock(TokenManagerContract::class);
        $tokenManager->expects($this->once())->method('makeTokenPair')->with($user)->willReturn($tokenPair);

        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);
        $refreshTokenRepository->expects($this->once())->method('create');

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->createTokenPair($user);

        self::assertSame($tokenPair, $result);
    }

    public function test_retrieve_by_credentials_user_exists(): void
    {
        $credentials = ['email' => 'example.com', 'password' => ''];
        $userProvider = $this->createMock(EloquentUserProvider::class);
        $userProvider->expects($this->once())
            ->method('retrieveByCredentials')
            ->with($credentials)
            ->willReturn($expected = $this->createMock(User::class));

        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->retrieveByCredentials($credentials);

        self::assertSame($expected, $result);
    }

    public function test_retrieve_by_credentials_user_not_exists(): void
    {
        $credentials = ['email' => 'example.com', 'password' => ''];

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $userProvider->expects($this->once())
            ->method('retrieveByCredentials')
            ->with($credentials)
            ->willReturn(null);

        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->retrieveByCredentials($credentials);

        $this->assertNull($result);
    }

    public function test_has_valid_credentials(): void
    {
        $userProvider = $this->createMock(EloquentUserProvider::class);
        $user = $this->createMock(User::class);
        $credentials = ['email' => 'example.com', 'password' => 'password'];
        $userProvider->expects($this->once())
            ->method('validateCredentials')
            ->with($user, $credentials)
            ->willReturn(true);

        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->hasValidCredentials($user, $credentials);

        self::assertTrue($result);
    }

    public function test_has_invalid_credentials(): void
    {
        $userProvider = $this->createMock(EloquentUserProvider::class);
        $user = $this->createMock(User::class);
        $credentials = ['email' => 'example.com', 'password' => 'password'];
        $userProvider->expects($this->once())
            ->method('validateCredentials')
            ->with($user, $credentials)
            ->willReturn(false);

        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->hasValidCredentials($user, $credentials);

        self::assertFalse($result);
    }

    public function test_retrieve_by_payload(): void
    {
        $userId = 25;
        $user = new User();
        $user->id = $userId;
        $payload = new Payload([
            'iss' => '',
            'sub' => $userId,
            'exp' => time(),
            'nbf' => time(),
            'iat' => time(),
            'jti' => '',
            'mhs' => hash('xxh3', $user::class),
        ]);

        $tokenManager = new TokenManager(
            SystemClock::fromUTC(),
            [
                'public_key' => 'iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=',
                'private_key' => 'BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJVQrE+pkUswP8ws40q9cwDjtiTi5SrNKAcAdISIFGNA==',
                'alg' => 'EdDSA',
                'leeway' => 0,
                'ttl' => 2592000,
                'claims' => [
                    'iss' => 'jwt'
                ],
            ]
        );
        $userProvider = $this->createMock(EloquentUserProvider::class);
        $userProvider->method('getModel')->willReturn($user::class);
        $userProvider->method('retrieveById')->with($userId)->willReturn($user);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);

        self::assertSame($user, $auth->retrieveByPayload($payload));
    }

    public function test_retrieve_by_payload_user_not_found(): void
    {
        $userId = 1;
        $user = new User();
        $user->id = $userId;
        $payload = new Payload([
            'iss' => '',
            'sub' => $userId,
            'exp' => time(),
            'nbf' => time(),
            'iat' => time(),
            'jti' => '',
            'mhs' => '',
        ]);
        $tokenManager = new TokenManager(
            SystemClock::fromUTC(),
            [
                'public_key' => 'iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=',
                'private_key' => 'BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJVQrE+pkUswP8ws40q9cwDjtiTi5SrNKAcAdISIFGNA==',
                'alg' => 'EdDSA',
                'leeway' => 0,
                'ttl' => 2592000, // in seconds (30 days)
                'claims' => [
                    'iss' => 'jwt'
                ],
            ]
        );

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $userProvider->method('retrieveById')
            ->with($userId)
            ->willReturn(null);

        $user = $auth->retrieveByPayload($payload);

        self::assertNull($user);
    }

    public function test_decode_token(): void
    {
        $token = '1234-4567';
        $accessToken = new Token('access', new Payload([]));

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $tokenManager = $this->createMock(TokenManagerContract::class);
        $tokenManager->expects($this->once())
            ->method('decode')
            ->with($token)->willReturn($accessToken);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->decodeToken($token);

        self::assertSame($accessToken, $result);
    }

    public function test_get_refresh_token(): void
    {
        $token = '1234-4567';

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);
        $refreshTokenRepository->expects($this->once())->method('get')->with($token)
            ->willReturn($expected = new JwtRefreshToken());

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);
        $result = $auth->getRefreshToken($token);

        self::assertSame($expected, $result);
    }

    public function test_revoke_refresh_token(): void
    {
        $jti = 'ABCD-EFGH-IJKL';
        $userProvider = $this->createMock(EloquentUserProvider::class);
        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);
        $refreshTokenRepository->expects($this->once())->method('delete')->with($jti);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);

        $auth->revokeRefreshToken($jti);
    }

    public function test_revoke_all_refresh_tokens(): void
    {
        $subject = 'user-subject';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('getAuthIdentifier')->willReturn($subject);

        $userProvider = $this->createMock(EloquentUserProvider::class);
        $tokenManager = $this->createMock(TokenManagerContract::class);
        $refreshTokenRepository = $this->createMock(RefreshTokenRepository::class);
        $refreshTokenRepository->expects($this->once())->method('deleteAllBySubject')->with($subject);

        $auth = new Auth($tokenManager, $userProvider, $refreshTokenRepository);

        $auth->revokeAllRefreshTokens($user);
    }
}
