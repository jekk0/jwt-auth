<?php

namespace Jekk0\JwtAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;

interface TokenManager
{
    public function makeTokenPair(Authenticatable $user): TokenPair;

    public function decode(string $token): Token;

    public function isPayloadFor(Payload $payload, string $userClass): bool;

    public function setTokenIssuer(string $issuer): void;
}
