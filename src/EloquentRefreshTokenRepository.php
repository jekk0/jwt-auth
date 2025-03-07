<?php

namespace Jekk0\JwtAuth;

use Jekk0\JwtAuth\Contracts\RefreshTokenRepository as RefreshTokenRepositoryContract;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

final class EloquentRefreshTokenRepository implements RefreshTokenRepositoryContract
{
    public function create(string $jti, int|string $subject, \DateTimeImmutable $expired_at): void
    {
        JwtRefreshToken::create(['jti' => $jti, 'sub' => $subject, 'expired_at' => $expired_at]);
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
