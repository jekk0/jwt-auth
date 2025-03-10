<?php

namespace Jekk0\JwtAuth;

use Jekk0\JwtAuth\Contracts\RefreshTokenRepository as RefreshTokenRepositoryContract;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

final class EloquentRefreshTokenRepository implements RefreshTokenRepositoryContract
{
    public function create(
        string $jti,
        string $accessTokenJti,
        int|string $subject,
        \DateTimeImmutable $expired_at
    ): void {
        JwtRefreshToken::create(
            ['jti' => $jti, 'access_token_jti' => $accessTokenJti, 'sub' => $subject, 'expired_at' => $expired_at]
        );
    }

    public function get(string $jti): ?JwtRefreshToken
    {
        return JwtRefreshToken::find($jti);
    }

    public function delete(string $jti): void
    {
        JwtRefreshToken::destroy($jti);
    }

    public function deleteAllBySubject(string $subject): void
    {
        JwtRefreshToken::where('sub', $subject)->delete();
    }
}
