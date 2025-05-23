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
            [
                'jti' => $jti,
                'access_token_jti' => $accessTokenJti,
                'subject' => $subject,
                'expired_at' => $expired_at,
                'status' => RefreshTokenStatus::Active
            ]
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
        JwtRefreshToken::where('subject', $subject)->delete();
    }

    public function markAsUsed(JwtRefreshToken $refreshToken): void
    {
        $refreshToken->status = RefreshTokenStatus::Used;
        $refreshToken->save();
    }

    public function markAsCompromised(JwtRefreshToken $refreshToken): void
    {
        $refreshToken->status = RefreshTokenStatus::Compromised;
        $refreshToken->save();
    }
}
