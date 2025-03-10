<?php

namespace Jekk0\JwtAuth\Events;

use Illuminate\Queue\SerializesModels;
use Jekk0\JwtAuth\Token;

class JwtAccessTokenDecoded
{
    use SerializesModels;

    public function __construct(
        public readonly string $guard,
        public readonly Token $accessToken
    ) {
    }
}
