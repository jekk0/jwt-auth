<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\Token;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function test_getters(): void
    {
        $token = new Token($tokenValue = 'access-token', $payload = new Payload(['exp' => 12345]));

        self::assertSame($tokenValue, $token->token);
        self::assertSame($payload, $token->payload);
    }
}
