<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Orchestra\Testbench\TestCase;
use Orchestra\Testbench\Concerns\WithWorkbench;

class JwtRefreshTokenTest extends TestCase
{
    use RefreshDatabase;
    use WithWorkbench;

    protected function defineEnvironment($app): void
    {
        $app['config']->set([
            'app.key' => 'D61EMLTbWd/1wRN5LeYq5G94jBcEVF/x1xeIOgjoWNc=',
            'database.default' => 'testing',
        ]);
    }

    public function test_prunable_action(): void
    {
        JwtRefreshToken::create(
            [
                'jti' => '01JNV3PEN545PQPN6FQC8F6C39',
                'access_token_jti' => '01JNV3Q6DEF81VT704ZEX2ADXX',
                'sub' => 'a',
                'expired_at' => now()->subDay()
            ]
        );
        JwtRefreshToken::create(
            [
                'jti' => '01JNV3PEN5V6HWPJJ65MHG9KGQ',
                'access_token_jti' => '01JNV3Q6DEJCKYX6C0B2838KNQ',
                'sub' => 'b',
                'expired_at' => now()->subWeek()
            ]
        );
        JwtRefreshToken::create(
            [
                'jti' => '01JNV3PEN5193ED0H2HWHVMY7J',
                'access_token_jti' => '01JNV3Q6DE1T6SAW6ERFAFQ59B',
                'sub' => 'c',
                'expired_at' => now()->addDay()
            ]
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);

        $count = (new JwtRefreshToken())->pruneAll();

        self::assertSame(2, $count);
        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        $token = JwtRefreshToken::find('01JNV3PEN5193ED0H2HWHVMY7J');
        self::assertSame('01JNV3PEN5193ED0H2HWHVMY7J', $token->jti);
        self::assertSame('01JNV3Q6DE1T6SAW6ERFAFQ59B', $token->access_token_jti);
        self::assertSame('c', $token->sub);
    }

    public function test_prunable_builder(): void
    {
        $result = (new JwtRefreshToken())->prunable();

        self::assertInstanceOf(Builder::class, $result);
    }
}
