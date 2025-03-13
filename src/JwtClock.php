<?php

namespace Jekk0\JwtAuth;

use Jekk0\JwtAuth\Contracts\Clock;

final class JwtClock implements Clock
{
    public function __construct(
        private readonly \DateTimeZone $timezone
    ) {
    }

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now', $this->timezone);
    }
}
