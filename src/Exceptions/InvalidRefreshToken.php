<?php

namespace Jekk0\JwtAuth\Exceptions;

use RuntimeException;

final class InvalidRefreshToken extends RuntimeException
{
    protected $message = 'Invalid refresh token.';
}
