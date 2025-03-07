<?php

namespace Jekk0\JwtAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;

interface JwtAuth
{
    public function createTokenPair(Authenticatable $user): TokenPair;

    /**
     * @param array<non-empty-string, string> $credentials
     */
    public function retrieveByCredentials(array $credentials): ?Authenticatable;

    /**
     * @param Authenticatable|null $user
     * @param array<non-empty-string, string> $credentials
     */
    public function hasValidCredentials(?Authenticatable $user, array $credentials): bool;

    public function retrieveByPayload(Payload $payload): ?Authenticatable;

    public function decodeToken(string $token): Token;

    public function revokeRefreshToken(string $jti): void;

    public function revokeAllRefreshTokens(Authenticatable $user): void;
}
