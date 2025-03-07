<?php

namespace Jekk0\JwtAuth;

final class Token
{
    public function __construct(
        public readonly string $token,
        public readonly Payload $payload
    ) {
    }
}
