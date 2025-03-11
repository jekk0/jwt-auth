<?php

namespace Jekk0\JwtAuth\Contracts;

interface CustomClaims
{
    /**
     * @return array<non-empty-string, mixed>
     */
    public function getJwtCustomClaims(): array;
}
