<?php

namespace Jekk0\JwtAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class JwtLogoutFromAllDevices
{
    use SerializesModels;

    public function __construct(
        public readonly string $guard,
        public readonly Authenticatable $user
    ) {
    }
}
