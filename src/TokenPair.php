<?php

namespace Jekk0\JwtAuth;

final class TokenPair
{
    public function __construct(
        public readonly Token $access,
        public readonly Token $refresh
    ) {
    }

    /**
     * @return array<non-empty-string, mixed>
     */
    public function toArray(): array
    {
        return [
            'access' => [
                'token' => $this->access->token,
                'expiredAt' => $this->access->payload->getExpiriedAt()
            ],
            'refresh' => [
                'token' => $this->refresh->token,
                'expiredAt' => $this->refresh->payload->getExpiriedAt()
            ]
        ];
    }
}
