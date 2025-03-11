<?php

namespace Jekk0\JwtAuth;

enum RefreshTokenStatus: string
{
    case Active = 'ACTIVE';
    case Used = 'USED';
    case Compromised = 'COMPROMISED';
}
