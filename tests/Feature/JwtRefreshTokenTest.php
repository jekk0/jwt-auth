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
        JwtRefreshToken::create(['jti' => '1', 'sub' => 'a', 'expired_at' => now()->subDay()]);
        JwtRefreshToken::create(['jti' => '2', 'sub' => 'b', 'expired_at' => now()->subWeek()]);
        JwtRefreshToken::create(['jti' => '3', 'sub' => 'c', 'expired_at' => now()->addDay()]);

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);

        $count = (new JwtRefreshToken())->pruneAll();

        self::assertSame(2, $count);
        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame('3', JwtRefreshToken::find(3)->jti);
        self::assertSame('c', JwtRefreshToken::find(3)->sub);
    }

    public function test_prunable_builder(): void
    {
        $result = (new JwtRefreshToken())->prunable();

        self::assertInstanceOf(Builder::class, $result);
    }
}
