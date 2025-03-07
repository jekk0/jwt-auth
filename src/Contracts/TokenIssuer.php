<?php

namespace Jekk0\JwtAuth\Contracts;

use Illuminate\Http\Request;

interface TokenIssuer
{
    public function __invoke(Request $request): string;
}
