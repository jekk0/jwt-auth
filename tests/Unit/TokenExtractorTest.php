<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Illuminate\Http\Request;
use Jekk0\JwtAuth\TokenExtractor;
use PHPUnit\Framework\TestCase;

class TokenExtractorTest extends TestCase
{
    public function test_getters(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

        $request = Request::create('https://example.com/');
        $request->headers->set('Authorization', "Bearer $token");

        $result = (new TokenExtractor())($request);

        self::assertSame($token, $result);
    }
}
