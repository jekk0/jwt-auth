<?php

namespace Jekk0\JwtAuth;

enum TokenType: string
{
    case Access = 'access';
    case Refresh = 'refresh';
}
