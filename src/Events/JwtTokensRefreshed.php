<?php

namespace Jekk0\JwtAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;
use Jekk0\JwtAuth\TokenPair;

class JwtTokensRefreshed
{
    use SerializesModels;

    public function __construct(
        public readonly string $guard,
        public readonly Authenticatable $user,
        public readonly TokenPair $refreshToken
    ) {
    }
}
