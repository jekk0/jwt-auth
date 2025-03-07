<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\JwtAuth;
use Jekk0\JwtAuth\Contracts\TokenExtractor;
use Jekk0\JwtAuth\Events\JwtAttempting;
use Jekk0\JwtAuth\Events\JwtAuthenticated;
use Jekk0\JwtAuth\Events\JwtFailed;
use Jekk0\JwtAuth\Events\JwtLogin;
use Jekk0\JwtAuth\Events\JwtLogout;
use Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices;
use Jekk0\JwtAuth\Events\JwtRefresh;
use Jekk0\JwtAuth\Events\JwtValidated;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\RequestGuard;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;
use Jekk0\JwtAuth\TokenType;
use PHPUnit\Framework\TestCase;
use Workbench\App\Models\User;

class RequestGuardTest extends TestCase
{

    public function test_attempt(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 29]);

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(true);
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => '1', 'sub' => 1, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => '2', 'sub' => 1, 'exp' => time()])),
            )
        );

        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($credentials);
        $expectedEvent2 = new JwtValidated($user);
        $expectedEvent3 = new JwtLogin($user);
        $expectedEvent4 = new JwtAuthenticated($user, $tokenPair->access);

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
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

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

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn(null);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($credentials);
        $expectedEvent2 = new JwtFailed(null, $credentials);

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
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

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

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(false);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($credentials);
        $expectedEvent2 = new JwtFailed($user, $credentials);

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
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

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

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(false);
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtAttempting($credentials);
        $expectedEvent2 = new JwtFailed($user, $credentials);

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
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

        $this->expectException(AuthenticationException::class);

        $guard->attemptOrFail($credentials);
    }

    public function test_login(): void
    {
        $user = new User(['id' => 71]);

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => '1', 'sub' => 1, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => '2', 'sub' => 1, 'exp' => time()])),
            )
        );

        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtLogin($user);
        $expectedEvent2 = new JwtAuthenticated($user, $tokenPair->access);

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
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

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
            new Payload(['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value])
        );
        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('revokeRefreshToken')->with($accessToken->payload->getReferenceTokenId());
        $auth->expects($this->never())->method('decodeToken');
        $expectedEvent1 = new JwtAuthenticated($user, $accessToken);
        $expectedEvent2 = new JwtLogout($user);

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

        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setUser($user, $accessToken);

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
            new Payload(['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value])
        );
        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('revokeAllRefreshTokens')->with($user);
        $auth->expects($this->never())->method('decodeToken');

        $expectedEvent1 = new JwtAuthenticated($user, $accessToken);
        $expectedEvent2 = new JwtLogoutFromAllDevices($user);

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
        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setUser($user, $accessToken);

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
            new Payload(['jti' => 'AAAA', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'NNN', 'ttp' => TokenType::Refresh->value])
        );

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($refreshToken->payload)->willReturn($user);
        $auth->expects($this->once())->method('revokeRefreshToken')->with($refreshToken->payload->getJwtId());
        $auth->expects($this->once())->method('createTokenPair')->with($user)->willReturn(
            $tokenPair = new TokenPair(
                new Token('jwt', new Payload(['jti' => 'new_1', 'sub' => $user->id, 'exp' => time()])),
                new Token('jwt', new Payload(['jti' => 'new_2', 'sub' => $user->id, 'exp' => time()])),
            )
        );
        $tokenExtractor = $this->createMock(TokenExtractor::class);

        $expectedEvent1 = new JwtRefresh($user, $refreshToken);
        $expectedEvent2 = new JwtLogin($user);
        $expectedEvent3 = new JwtAuthenticated($user, $tokenPair->access);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(3))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1, $expectedEvent2, $expectedEvent3) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                    2 => $this->assertEquals($expectedEvent2, $event),
                    3 => $this->assertEquals($expectedEvent3, $event),
                };
            }
        );

        $request = Request::create('');
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->refreshTokens($tokenPair->refresh->token);

        self::assertSame($tokenPair, $result);
    }

    public function test_user_with_access_token(): void
    {
        $user = new User(['id' => '71']);
        $accessToken = new Token(
            'jwt',
            new Payload(['jti' => 'QWERT', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value])
        );
        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('decodeToken')->with($accessToken->token)->willReturn($accessToken);
        $auth->expects($this->once())->method('retrieveByPayload')->with($accessToken->payload)->willReturn($user);

        $expectedEvent1 = new JwtAuthenticated($user, $accessToken);

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($matcher = $this->exactly(1))->method('dispatch')->willReturnCallback(
            function ($event) use ($matcher, $expectedEvent1) {
                match ($matcher->numberOfInvocations()) {
                    1 => $this->assertEquals($expectedEvent1, $event),
                };
            }
        );

        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$accessToken->token}");
        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

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
            new Payload(['jti' => 'QWERT', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Refresh->value])
        );
        $auth = $this->createMock(JwtAuth::class);
//        $auth->expects($this->once())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->any())->method('decodeToken')->with($refreshToken->token)->willReturn($refreshToken);
        $auth->expects($this->never())->method('retrieveByPayload');

        $dispatcher = $this->createMock(Dispatcher::class);
        $dispatcher->expects($this->exactly(0))->method('dispatch');
        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer {$refreshToken->token}");
        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

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
            new Payload(['jti' => '1', 'sub' => $user->id, 'exp' => time(), 'rfi' => 'UUAI', 'ttp' => TokenType::Access->value])
        );
        $auth = $this->createMock(JwtAuth::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('https://example.com/');
        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);
        $guard->setUser($user, $accessToken);

        $result = $guard->getAccessToken();

        self::assertSame($accessToken, $result);
    }

    public function test_get_access_token_unauthenticated(): void
    {
        $auth = $this->createMock(JwtAuth::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('https://example.com/');
        $guard = new RequestGuard($auth, new \Jekk0\JwtAuth\TokenExtractor(), $dispatcher, $request);

        $result = $guard->getAccessToken();

        self::assertNull($result);
    }

    public function test_validate(): void
    {
        $credentials = ['email' => 'example.com', 'password' => '123456'];
        $user = new User(['id' => 59]);

        $auth = $this->createMock(JwtAuth::class);
        $auth->expects($this->once())->method('retrieveByCredentials')->with($credentials)->willReturn($user);
        $auth->expects($this->once())->method('hasValidCredentials')->with($user, $credentials)->willReturn(true);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('');
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->validate($credentials);

        self::assertTrue($result);
    }

    public function test_has_user_null(): void
    {
        $auth = $this->createMock(JwtAuth::class);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $dispatcher = $this->createMock(Dispatcher::class);

        $request = Request::create('');
        $guard = new RequestGuard($auth, $tokenExtractor, $dispatcher, $request);

        $result = $guard->hasUser();

        self::assertFalse($result);
    }
//
//    public function test_check(): void
//    {
//    }
//
//    public function test_guest(): void
//    {
//    }
//
//    public function test_id(): void
//    {
//    }
//
//    public function test_set_user(): void
//    {
//    }
//
//    public function test_set_request(): void
//    {
//    }
}
