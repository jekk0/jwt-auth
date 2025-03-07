<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Illuminate\Http\Request;
use Jekk0\JwtAuth\TokenIssuer;
use PHPUnit\Framework\TestCase;

class TokenIssuerTest extends TestCase
{
    public function test_getters(): void
    {
        $request = Request::create($expected = 'https://example.com/api/auth/login');

        $result = (new TokenIssuer())($request);

        self::assertSame($expected, $result);
    }
}
