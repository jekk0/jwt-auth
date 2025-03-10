<?php

namespace Jekk0\JwtAuth\Exceptions;

use RuntimeException;

final class RefreshTokenCompromised extends RuntimeException
{
    protected $message = 'JWT refresh token compromised.';
}
