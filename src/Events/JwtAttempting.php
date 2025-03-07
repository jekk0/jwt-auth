<?php

namespace Jekk0\JwtAuth\Events;

final class JwtAttempting
{
    /**
     * @param array<non-empty-string, string> $credentials
     */
    public function __construct(
        #[\SensitiveParameter]
        public readonly array $credentials
    ) {
    }
}
