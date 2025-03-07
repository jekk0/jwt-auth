<?php

namespace Jekk0\JwtAuth;

use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\TokenExtractor as TokenExtractorContract;

final class TokenExtractor implements TokenExtractorContract
{
    public function __invoke(Request $request): ?string
    {
        return $request->bearerToken();
    }
}
