<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Public Key
    |--------------------------------------------------------------------------
    |
    | Used for verifying token signatures. Can be shared with services that need to validate tokens.
    |
    */
    'public_key' => env('JWT_AUTH_PUBLIC_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Private Key
    |--------------------------------------------------------------------------
    |
    | Used for signing tokens. Must be kept secure.
    |
    */
    'private_key' => env('JWT_AUTH_PRIVATE_KEY'),

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    |
    | The signing algorithm defines how tokens are encrypted and verified.
    |
    | EdDSA Hardcoded.
    | ECDSA excels in performance, offering faster key generation and signature creation and verification.
    | Its efficiency makes it ideal for devices with limited processing power.
    | RSA tends to be slower, especially during key generation and signature creation.
    |
    */
    'alg' => 'EdDSA',

    /*
    |--------------------------------------------------------------------------
    | Tokens time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time in seconds that the token will be valid for.
    |
    */
    'ttl' => [
        /*
        |--------------------------------------------------------------------------
        | Access Token Lifetime
        |--------------------------------------------------------------------------
        |
        | Specify the length of time in seconds that the token will be valid for.
        |
        | This defines how long an access token remains valid before expiration.
        | Typically, access tokens have a short lifespan (e.g., 15 minutes to 1 hour) to enhance security.
        | Default: one hour
        |
        */
        'access' => env('JWT_AUTH_ACCESS_TOKEN_TTL', 3600),

        /*
        |--------------------------------------------------------------------------
        | Refresh Token Lifetime
        |--------------------------------------------------------------------------
        |
        | Specify the length of time in seconds that the token will be valid for.
        |
        | A refresh token is used to obtain a new access token without requiring the user to reauthenticate.
        | Refresh tokens generally have a longer lifespan (e.g., days or weeks).
        | Default: seven days
        |
        */
        'refresh' => env('JWT_AUTH_REFRESH_TOKEN_TTL', 604800),
    ],
];
