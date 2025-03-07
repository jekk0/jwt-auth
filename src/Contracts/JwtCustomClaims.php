<?php

namespace Jekk0\JwtAuth\Contracts;

interface JwtCustomClaims
{
    /**
     * @return array<non-empty-string, mixed>
     */
    public function getJwtCustomClaims(): array;
}
