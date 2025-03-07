<?php

namespace Jekk0\JwtAuth\Contracts;

interface RefreshTokenRepository
{
    public function create(string $jti, int|string $subject, \DateTimeImmutable $expired_at): void;

    public function delete(string $jti): void;

    public function deleteAllBySubject(string $subject): void;
}
