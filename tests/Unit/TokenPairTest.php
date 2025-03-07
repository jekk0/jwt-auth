<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;
use PHPUnit\Framework\TestCase;

class TokenPairTest extends TestCase
{
    public function test_getters(): void
    {
        $accessToken = new Token('access-token', new Payload(['exp' => 12345]));
        $refreshToken = new Token('refresh-token', new Payload(['exp' => 56789]));

        $tokenPair = new TokenPair($accessToken, $refreshToken);

        self::assertNotSame($accessToken, $refreshToken);
        self::assertSame($accessToken, $tokenPair->access);
        self::assertSame($refreshToken, $tokenPair->refresh);

        self::assertSame(
            [
                'access' => [
                    'token' => 'access-token',
                    'expiredAt' => 12345
                ],
                'refresh' => [
                    'token' => 'refresh-token',
                    'expiredAt' => 56789
                ]
            ],
            $tokenPair->toArray()
        );
    }
}
