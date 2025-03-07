<?php

namespace Jekk0\JwtAuth;

use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\TokenIssuer as TokenIssuerContract;

final class TokenIssuer implements TokenIssuerContract
{
    public function __invoke(Request $request): string
    {
        return $request->url();
    }
}
