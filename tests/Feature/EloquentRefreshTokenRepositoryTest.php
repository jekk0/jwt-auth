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
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);

        (new EloquentRefreshTokenRepository())->create($jti, $accessTokenJti, $subject, $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }

    public function test_delete(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create($jti, $accessTokenJti, $subject, $expiredAt);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);

        (new EloquentRefreshTokenRepository())->delete($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 0);
    }

    public function test_delete_all_by_subject(): void
    {
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        (new EloquentRefreshTokenRepository())->create(
            '01JNV3HSGKE0ZJ44GBB299WD6S',
            '01JNV3HSGMD3MZRSDY3WJV2DD2',
            $subject,
            $expiredAt
        );
        (new EloquentRefreshTokenRepository())->create(
            '01JNV3HSGK48FMGCHNW2BSWSY3',
            '01JNV3HSGMWBQWZNQW93RJ12Y9',
            $subject,
            $expiredAt
        );
        (new EloquentRefreshTokenRepository())->create(
            '01JNV3HSGK1MZ7EYTQ7N8Q9V0M',
            '01JNV3HSGMZ26F430Y6VA1FECP',
            'other-subject',
            $expiredAt
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);

        (new EloquentRefreshTokenRepository())->deleteAllBySubject($subject);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
    }
}
