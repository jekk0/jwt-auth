<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Jekk0\JwtAuth\EloquentRefreshTokenRepository;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Orchestra\Testbench\TestCase;
use Orchestra\Testbench\Concerns\WithWorkbench;

class EloquentRefreshTokenRepositoryTest extends TestCase
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

    public function test_create(): void
    {
        $jti = 'zxcvbn';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);

        (new EloquentRefreshTokenRepository())->create($jti, $subject, $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }

    public function test_delete(): void
    {
        $jti = 'zxcvbn';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create($jti, $subject, $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);

        (new EloquentRefreshTokenRepository())->delete($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);
    }

    public function test_delete_all_by_subject(): void
    {
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create('1', $subject, $expiredAt);
        (new EloquentRefreshTokenRepository())->create('2', $subject, $expiredAt);
        (new EloquentRefreshTokenRepository())->create('3', 'other-subject', $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);

        (new EloquentRefreshTokenRepository())->deleteAllBySubject($subject);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }
}
