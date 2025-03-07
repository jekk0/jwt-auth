<?php

namespace Jekk0\JwtAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;
use Jekk0\JwtAuth\Token;

class JwtRefresh
{
    use SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Token $refreshToken
    ) {
    }
}
