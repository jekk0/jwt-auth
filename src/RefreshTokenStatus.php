<?php

namespace Jekk0\JwtAuth;

enum RefreshTokenStatus: int
{
    case Active = 0;
    case Used = 1;
    case Compromised = 2;
}
