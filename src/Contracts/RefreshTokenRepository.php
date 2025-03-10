<?php

namespace Jekk0\JwtAuth\Contracts;

use Jekk0\JwtAuth\Model\JwtRefreshToken;

interface RefreshTokenRepository
{
    public function create(
        string $jti,
        string $accessTokenJti,
        int|string $subject,
        \DateTimeImmutable $expired_at
    ): void;

    public function get(string $jti): ?JwtRefreshToken;

    public function markAsRevoked(string $jti): void;

    public function markAsRevokedAllBySubject(string $subject): void;

    public function markAsUsed(string $jti): void;

    public function markAsCompromised(string $jti): void;
}
