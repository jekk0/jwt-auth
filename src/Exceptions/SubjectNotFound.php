<?php

namespace Jekk0\JwtAuth\Exceptions;

use RuntimeException;

final class SubjectNotFound extends RuntimeException
{
    protected $message = 'JWT subject not found.';
}
