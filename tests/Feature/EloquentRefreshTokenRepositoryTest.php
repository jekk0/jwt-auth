<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Jekk0\JwtAuth\Database\Factories\JwtRefreshTokenFactory;
use Jekk0\JwtAuth\EloquentRefreshTokenRepository;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\RefreshTokenStatus;
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

    public function test_get(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        JwtRefreshTokenFactory::new()->create(
            ['jti' => $jti, 'access_token_jti' => $accessTokenJti, 'sub' => $subject, 'expired_at' => $expiredAt]
        );

        $refreshToken = (new EloquentRefreshTokenRepository())->get($jti);

        self::assertSame($jti, $refreshToken->jti);
        self::assertSame($accessTokenJti, $refreshToken->access_token_jti);
        self::assertSame($subject, $refreshToken->sub);
    }

    public function test_get_not_found(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';

        $refreshToken = (new EloquentRefreshTokenRepository())->get($jti);

        self::assertNull($refreshToken);
    }

    public function test_mark_as_revoked(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        JwtRefreshTokenFactory::new()->create(
            ['jti' => $jti, 'access_token_jti' => $accessTokenJti, 'sub' => $subject, 'expired_at' => $expiredAt]
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti)->status);

        (new EloquentRefreshTokenRepository())->markAsRevoked($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Revoked, JwtRefreshToken::find($jti)->status);
    }

    public function test_mark_as_revoked_all_by_subject(): void
    {
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        JwtRefreshTokenFactory::new()->create(
            [
                'jti' => $jti1 = '01JNV3HSGKE0ZJ44GBB299WD6S',
                'access_token_jti' => '01JNV3HSGMD3MZRSDY3WJV2DD2',
                'sub' => $subject,
                'expired_at' => $expiredAt
            ]
        );
        JwtRefreshTokenFactory::new()->create(
            [
                'jti' => $jti2 = '01JNV3HSGK48FMGCHNW2BSWSY3',
                'access_token_jti' => '01JNV3HSGMWBQWZNQW93RJ12Y9',
                'sub' => $subject,
                'expired_at' => $expiredAt
            ]
        );
        JwtRefreshTokenFactory::new()->create(
            [
                'jti' => $jti3 = '01JNV3HSGK1MZ7EYTQ7N8Q9V0M',
                'access_token_jti' => '01JNV3HSGMZ26F430Y6VA1FECP',
                'sub' => 'other-subject',
                'expired_at' => $expiredAt
            ]
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti1)->status);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti2)->status);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti3)->status);

        (new EloquentRefreshTokenRepository())->markAsRevokedAllBySubject($subject);

        $this->assertDatabaseCount(JwtRefreshToken::class, 3);
        self::assertSame(RefreshTokenStatus::Revoked, JwtRefreshToken::find($jti1)->status);
        self::assertSame(RefreshTokenStatus::Revoked, JwtRefreshToken::find($jti2)->status);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti3)->status);
    }

    public function test_mark_as_used(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        JwtRefreshTokenFactory::new()->create(
            ['jti' => $jti, 'access_token_jti' => $accessTokenJti, 'sub' => $subject, 'expired_at' => $expiredAt]
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti)->status);

        (new EloquentRefreshTokenRepository())->markAsUsed($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Used, JwtRefreshToken::find($jti)->status);
    }

    public function test_mark_as_compromised(): void
    {
        $jti = '01JNV3HSGK8TSR3TFAYN2VBQ6F';
        $accessTokenJti = '01JNV3HSGKSWAQFYVN56G84AC3';
        $subject = 'subject';
        $expiredAt = new \DateTimeImmutable();
        JwtRefreshTokenFactory::new()->create(
            ['jti' => $jti, 'access_token_jti' => $accessTokenJti, 'sub' => $subject, 'expired_at' => $expiredAt]
        );

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Active, JwtRefreshToken::find($jti)->status);

        (new EloquentRefreshTokenRepository())->markAsCompromised($jti);

        $this->assertDatabaseCount(JwtRefreshToken::class, 1);
        self::assertSame(RefreshTokenStatus::Compromised, JwtRefreshToken::find($jti)->status);
    }
}
