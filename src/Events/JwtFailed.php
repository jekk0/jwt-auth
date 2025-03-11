<?php

namespace Jekk0\JwtAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;

class JwtFailed
{
    /**
     * @param Authenticatable|null $user
     * @param array<non-empty-string, string> $credentials
     */
    public function __construct(
        public readonly string $guard,
        public readonly ?Authenticatable $user,
        #[\SensitiveParameter]
        public readonly array $credentials
    ) {
    }
}
