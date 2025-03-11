<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\Auth;
use Jekk0\JwtAuth\Contracts\TokenExtractor;
use Jekk0\JwtAuth\Events\JwtAccessTokenDecoded;
use Jekk0\JwtAuth\Events\JwtAttempting;
use Jekk0\JwtAuth\Events\JwtAuthenticated;
use Jekk0\JwtAuth\Events\JwtFailed;
use Jekk0\JwtAuth\Events\JwtLogin;
use Jekk0\JwtAuth\Events\JwtLogout;
use Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices;
use Jekk0\JwtAuth\Events\JwtRefreshTokenCompromised;
use Jekk0\JwtAuth\Events\JwtRefreshTokenDecoded;
use Jekk0\JwtAuth\Events\JwtTokensRefreshed;
use Jekk0\JwtAuth\Events\JwtValidated;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\RefreshTokenStatus;
use Jekk0\JwtAuth\RequestGuard;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;
use Jekk0\JwtAuth\TokenType;
use PHPUnit\Framework\TestCase;
use Workbench\App\Models\User;
use PHPUnit\Framework\Attributes\DataProvider;

class RequestGuardTest extends TestCase
{
    public function test_attempt(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 29]);
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(true);
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => '1', 'sub' => 1, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => '2', 'sub' => 1, 'exp' => time()])),
            )
        );

        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($guardName, $credentials);
        $expectedEvent2 = new JwtValidated($guardName, $user);
        $expectedEvent3 = new JwtLogin($guardName, $user);
        $expectedEvent4 = new JwtAuthenticated($guardName, $user, $tokenPair->access);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(4))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2, $expectedEvent3, $expectedEvent4) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                    3 => $this->assertEquals($expectedEvent3, $event),
                    4 => $this->assertEquals($expectedEvent4, $event)
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->attempt($credentials);

        self::assertSame($tokenPair, $result);
        self::assertSame($user, $guard->user());
        self::assertSame($user->id, $guard->id());
        self::assertSame($tokenPair->access, $guard->getAccessToken());
        self::assertTrue($guard->check());
        self::assertFalse($guard->guest());
    }

    public function test_attempt_user_not_found(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn(null);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($guardName, $credentials);
        $expectedEvent2 = new JwtFailed($guardName, null, $credentials);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->attempt($credentials);

        self::assertNull($result);
        self::assertNull($guard->user());
        self::assertNull($guard->id());
        self::assertNull($guard->getAccessToken());
        self::assertFalse($guard->check());
        self::assertTrue($guard->guest());
    }

    public function test_attempt_user_with_wrong_password(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 29]);
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(false);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($guardName, $credentials);
        $expectedEvent2 = new JwtFailed($guardName, $user, $credentials);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->attempt($credentials);

        self::assertNull($result);
        self::assertNull($guard->user());
        self::assertNull($guard->id());
        self::assertNull($guard->getAccessToken());
        self::assertFalse($guard->check());
        self::assertTrue($guard->guest());
    }

    public function test_attempt_or_fail_wrong_password(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 29]);
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(false);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($guardName, $credentials);
        $expectedEvent2 = new JwtFailed($guardName, $user, $credentials);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);

        $guard->attemptOrFail($credentials);
    }

    public function test_login(): void
    {
        $user = new User(['id' => 71]);
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => '1', 'sub' => 1, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => '2', 'sub' => 1, 'exp' => time()])),
            )
        );

        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtLogin($guardName, $user);
        $expectedEvent2 = new JwtAuthenticated($guardName, $user, $tokenPair->access);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->login($user);

        self::assertSame($tokenPair, $result);
        self::assertSame($user, $guard->user());
        self::assertSame($user->id, $guard->id());
        self::assertSame($tokenPair->access, $guard->getAccessToken());
        self::assertTrue($guard->check());
        self::assertFalse($guard->guest());
    }

    public function test_logout(): void
    {
        $user = new User(['id' => 71]);
        $accessToken = new Token(
            'jwt',
            new Payload(
                ['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('revokeRefreshToken')->with($accessToken->payload->getReferenceTokenId());
        $auth->expects($this->never())->method('decodeToken');
        $expectedEvent1 = new JwtAuthenticated($guardName, $user, $accessToken);
        $expectedEvent2 = new JwtLogout($guardName, $user);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$accessToken->token}");

        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setToken($accessToken);
        $guard->setUser($user);

        $guard->logout();

        self::assertNull($guard->user());
        self::assertNull($guard->id());
        self::assertNull($guard->getAccessToken());
        self::assertFalse($guard->check());
        self::assertTrue($guard->guest());
    }

    public function test_logout_from_all_devices(): void
    {
        $user = new User(['id' => 71]);
        $accessToken = new Token(
            'jwt',
            new Payload(
                ['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('revokeAllRefreshTokens')->with($user);
        $auth->expects($this->never())->method('decodeToken');

        $expectedEvent1 = new JwtAuthenticated($guardName, $user, $accessToken);
        $expectedEvent2 = new JwtLogoutFromAllDevices($guardName, $user);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$accessToken->token}");
        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setToken($accessToken);
        $guard->setUser($user);

        $guard->logoutFromAllDevices();

        self::assertNull($guard->user());
        self::assertNull($guard->id());
        self::assertNull($guard->getAccessToken());
        self::assertFalse($guard->check());
        self::assertTrue($guard->guest());
    }

    public function test_refresh_tokens(): void
    {
        $user = new User(['id' => '33']);
        $refreshToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => 'AAAA',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'NNN',
                    'ttp' => TokenType::Refresh->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn($user);
        $auth->expects($this->once())->method('getRefreshToken')->with($refreshToken->payload->getJwtId())->willReturn(
            new JwtRefreshToken()
        );
        $auth->expects($this->once())->method('markAsUsed')->with($refreshToken->payload->getJwtId());
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => 'new_1', 'sub' => $user->id, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => 'new_2', 'sub' => $user->id, 'exp' => time()])),
            )
        );
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefreshTokenDecoded($guardName, $refreshToken);
        $expectedEvent2 = new JwtLogin($guardName, $user);
        $expectedEvent3 = new JwtAuthenticated($guardName, $user, $tokenPair->access);
        $expectedEvent4 = new JwtTokensRefreshed($guardName, $user, $tokenPair);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(4))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2, $expectedEvent3, $expectedEvent4) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                    3 => $this->assertEquals($expectedEvent3, $event),
                    4 => $this->assertEquals($expectedEvent4, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->refreshTokens($refreshToken->token);

        self::assertSame($tokenPair, $result);
    }

    public function test_refresh_invalid_token_type(): void
    {
        $refreshToken = new Token(
            'jwt',
            new Payload(
                ['jti' => 'AAAA', 'sub' => '1234', 'exp' => time(), 'rfi' => 'NNN', 'ttp' => TokenType::Access->value]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->never())->method('retrieveByPayload');
        $auth->expects($this->never())->method('getRefreshToken');
        $auth->expects($this->never())->method('revokeRefreshToken');
        $auth->expects($this->never())->method('createTokenPair');
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);
        $guard->refreshTokens($refreshToken->token);
    }

    public function test_refresh_tokens_user_not_found(): void
    {
        $refreshToken = new Token(
            'jwt',
            new Payload(
                ['jti' => 'AAAA', 'sub' => '1234', 'exp' => time(), 'rfi' => 'NNN', 'ttp' => TokenType::Refresh->value]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn(null);
        $auth->expects($this->never())->method('getRefreshToken');
        $auth->expects($this->never())->method('revokeRefreshToken');
        $auth->expects($this->never())->method('createTokenPair');
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefreshTokenDecoded($guardName, $refreshToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(1))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);
        $guard->refreshTokens($refreshToken->token);
    }

    public function test_refresh_tokens_token_not_found(): void
    {
        $user = new User(['id' => 89]);
        $refreshToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => '1234-abcd',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'NNN',
                    'ttp' => TokenType::Refresh->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn($user);
        $auth->expects($this->once())->method('getRefreshToken')->willReturn(null);
        $auth->expects($this->never())->method('revokeRefreshToken');
        $auth->expects($this->never())->method('createTokenPair');
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefreshTokenDecoded($guardName, $refreshToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(1))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);
        $guard->refreshTokens($refreshToken->token);
    }

    #[DataProvider('data_for_refresh_tokens_token_invalid_status')]
    public function test_refresh_tokens_token_invalid_status(JwtRefreshToken $model): void
    {
        $user = new User(['id' => 89]);
        $refreshToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => '1234-abcd',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'NNN',
                    'ttp' => TokenType::Refresh->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn($user);
        $auth->expects($this->once())->method('getRefreshToken')->willReturn($model);
        $auth->expects($this->never())->method('revokeRefreshToken');
        $auth->expects($this->never())->method('createTokenPair');
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefreshTokenDecoded($guardName, $refreshToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(1))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);
        $guard->refreshTokens($refreshToken->token);
    }

    public static function data_for_refresh_tokens_token_invalid_status(): \Generator
    {
        yield from [
            'Compromised Token' => [new JwtRefreshToken(['status' => RefreshTokenStatus::Compromised])]
        ];
    }

    public function test_refresh_tokens_compromised(): void
    {
        $user = new User(['id' => '33']);
        $refreshToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => 'AAAA',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'NNN',
                    'ttp' => TokenType::Refresh->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn($user);
        $auth->expects($this->once())->method('getRefreshToken')->with($refreshToken->payload->getJwtId())->willReturn(
            new JwtRefreshToken(['status' => RefreshTokenStatus::Used])
        );
        $auth->expects($this->once())->method('markAsCompromised')->with($refreshToken->payload->getJwtId());
        $auth->expects($this->never())->method('markAsUsed');
        $auth->expects($this->never())->method('createTokenPair');

        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefreshTokenDecoded($guardName, $refreshToken);
        $expectedEvent2 = new JwtRefreshTokenCompromised($guardName, $user, $refreshToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event)
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);
        $guard->refreshTokens($refreshToken->token);
    }

    public function test_user_with_access_token(): void
    {
        $user = new User(['id' => '71']);
        $accessToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => 'QWERT',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'UUAI',
                    'ttp' => TokenType::Access->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('decodeToken')->with($accessToken->token)->willReturn($accessToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($accessToken->payload)->willReturn($user);

        $expectedEvent1 = new JwtAccessTokenDecoded($guardName, $accessToken);
        $expectedEvent2 = new JwtAuthenticated($guardName, $user, $accessToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(2))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                };
            }
        );

        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$accessToken->token}");
        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

        $result = $guard->user();

        self::assertSame($user, $result);
        self::assertSame($user->id, $guard->id());
        self::assertSame($accessToken, $guard->getAccessToken());
        self::assertTrue($guard->check());
        self::assertTrue($guard->hasUser());
        self::assertFalse($guard->guest());
    }

    public function test_user_with_refresh_token(): void
    {
        $user = new User(['id' => '71']);
        $refreshToken = new Token(
            'jwt',
            new Payload(
                [
                    'jti' => 'QWERT',
                    'sub' => $user->id,
                    'exp' => time(),
                    'rfi' => 'UUAI',
                    'ttp' => TokenType::Refresh->value
                ]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        //        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->any())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->never())->method('retrieveByPayload');

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($this->exactly(0))->method('dispatch');
        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$refreshToken->token}");
        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

        $result = $guard->user();

        self::assertNull($result);
        self::assertNull($guard->id());
        self::assertNull($guard->getAccessToken());
        self::assertFalse($guard->check());
        self::assertFalse($guard->hasUser());
        self::assertTrue($guard->guest());
    }

    public function test_get_access_token_authenticated(): void
    {
        $user = new User(['id' => 71]);
        $accessToken = new Token(
            'jwt',
            new Payload(
                ['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value]
            )
        );
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('https://example.com/');
        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setToken($accessToken);
        $guard->setUser($user);

        $result = $guard->getAccessToken();

        self::assertSame($accessToken, $result);
    }

    public function test_get_access_token_unauthenticated(): void
    {
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('https://example.com/');
        $guard = new RequestGuard($guardName, $auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

        $result = $guard->getAccessToken();

        self::assertNull($result);
    }

    public function test_validate(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 59]);
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(true);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->validate($credentials);

        self::assertTrue($result);
    }

    public function test_has_user_null(): void
    {
        $guardName = 'jwt-user';
        $auth = $this->createMock(Auth::class);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('');
        $guard = new RequestGuard($guardName, $auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->hasUser();

        self::assertFalse($result);
    }
}
