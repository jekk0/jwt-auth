<?php

namespace Jekk0\JwtAuth\Contracts;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Token;
use Jekk0\JwtAuth\TokenPair;

interface RequestGuard extends Guard
{
    /**
     * @param array<non-empty-string, string> $credentials
     * @return ?TokenPair
     */
    public function attempt(array $credentials): ?TokenPair;

    /**
     * @param array<non-empty-string, string> $credentials
     * @return TokenPair
     *
     * @throws AuthenticationException
     */
    public function attemptOrFail(array $credentials): TokenPair;

    public function login(Authenticatable $user): TokenPair;

    public function logout(): void;

    public function logoutFromAllDevices(): void;

    public function refreshTokens(string $refreshToken): TokenPair;

    public function getAccessToken(): ?Token;

    public function setRequest(Request $request): void;
}
