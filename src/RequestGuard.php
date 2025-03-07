<?php

namespace Jekk0\JwtAuth;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\RequestGuard as JwtGuardContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Jekk0\JwtAuth\Contracts\JwtAuth;
use Jekk0\JwtAuth\Contracts\TokenExtractor as TokenExtractorContract;
use Jekk0\JwtAuth\Events\JwtAttempting;
use Jekk0\JwtAuth\Events\JwtAuthenticated;
use Jekk0\JwtAuth\Events\JwtFailed;
use Jekk0\JwtAuth\Events\JwtLogin;
use Jekk0\JwtAuth\Events\JwtLogout;
use Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices;
use Jekk0\JwtAuth\Events\JwtRefresh;
use Jekk0\JwtAuth\Events\JwtValidated;
use Jekk0\JwtAuth\Exceptions\JwtTokenDecodeException;
use Jekk0\JwtAuth\Exceptions\JwtTokenInvalidType;
use Illuminate\Contracts\Events\Dispatcher;

final class RequestGuard implements JwtGuardContract
{
    private ?Authenticatable $user = null;
    private ?Token $accessToken = null;
    private bool $loggedOut = false;

    public function __construct(
        private readonly JwtAuth $jwtAuth,
        private readonly TokenExtractorContract $tokenExtractor,
        private readonly Dispatcher $dispatcher,
        private Request $request
    ) {
    }

    public function attempt(array $credentials): ?TokenPair
    {
        $this->dispatcher->dispatch(new JwtAttempting($credentials));

        $user = $this->jwtAuth->retrieveByCredentials($credentials);

        if ($user === null || $this->jwtAuth->hasValidCredentials($user, $credentials) === false) {
            $this->dispatcher->dispatch(new JwtFailed($user, $credentials));

            return null;
        }

        $this->dispatcher->dispatch(new JwtValidated($user));


        return $this->login($user);
    }

    public function attemptOrFail(array $credentials): TokenPair
    {
        $tokenPair = $this->attempt($credentials);

        if ($tokenPair === null) {
            throw new AuthenticationException();
        }

        return $tokenPair;
    }

    public function login(Authenticatable $user): TokenPair
    {
        $tokenPair = $this->jwtAuth->createTokenPair($user);

        $this->dispatcher->dispatch(new JwtLogin($user));

        $this->setUser($user, $tokenPair->access);

        return $tokenPair;
    }

    public function logout(): void
    {
        if ($this->user()) {
            $this->jwtAuth->revokeRefreshToken($this->accessToken->payload->getReferenceTokenId());

            $this->dispatcher->dispatch(new JwtLogout($this->user()));
        }

        $this->forgetUser();
    }

    public function logoutFromAllDevices(): void
    {
        if ($this->user()) {
            $this->jwtAuth->revokeAllRefreshTokens($this->user());

            $this->dispatcher->dispatch(new JwtLogoutFromAllDevices($this->user()));
        }

        $this->forgetUser();
    }

    public function refreshTokens(string $refreshToken): TokenPair
    {
        try {
            $token = $this->jwtAuth->decodeToken($refreshToken);
            if ($token->payload->getTokenType() !== TokenType::Refresh) {
                throw new JwtTokenInvalidType('Invalid JWT token type. Expected refresh token.');
            }

            $user = $this->jwtAuth->retrieveByPayload($token->payload);

            $this->dispatcher->dispatch(new JwtRefresh($user, $token));
            $this->jwtAuth->revokeRefreshToken($token->payload->getJwtId());
            $tokenPair = $this->login($user);

            return $tokenPair;
        } catch (JwtTokenDecodeException|JwtTokenInvalidType) {
            throw new AuthenticationException();
        }
    }

    public function user(): ?Authenticatable
    {
        if ($this->loggedOut === true) {
            return null;
        }

        if ($this->user instanceof Authenticatable) {
            return $this->user;
        }

        $accessToken = ($this->tokenExtractor)($this->request);

        if ($accessToken === null) {
            return null;
        }

        try {
            $accessToken = $this->jwtAuth->decodeToken($accessToken);
            // Reject if used refresh token instead access token
            if ($accessToken->payload->getTokenType() !== TokenType::Access) {
                throw new JwtTokenInvalidType('Invalid JWT token type. Expected access token.');
            }

            $user = $this->jwtAuth->retrieveByPayload($accessToken->payload);

            if ($user instanceof Authenticatable) {
                $this->setUser($user, $accessToken);
            }

            return $this->user;
        } catch (JwtTokenDecodeException|JwtTokenInvalidType) {
            return null;
        }
    }

    public function getAccessToken(): ?Token
    {
        return $this->accessToken;
    }

    /**
     * @param array<non-empty-string, string> $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return $this->jwtAuth->hasValidCredentials($this->jwtAuth->retrieveByCredentials($credentials), $credentials);
    }

    public function hasUser(): bool
    {
        return $this->user() instanceof Authenticatable;
    }

    public function check(): bool
    {
        return $this->user() instanceof Authenticatable;
    }

    public function guest(): bool
    {
        return $this->check() === false;
    }

    public function id(): int|string|null
    {

        if ($this->check()) {
            return $this->user()->getAuthIdentifier();
        }

        return null;
    }

    public function setUser(Authenticatable $user, ?Token $accessToken = null): self
    {
        $this->user = $user;
        $this->accessToken = $accessToken;
        $this->loggedOut = false;

        $this->dispatcher->dispatch(new JwtAuthenticated($user, $accessToken));

        return $this;
    }

    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    private function forgetUser(): void
    {
        $this->user = null;
        $this->accessToken = null;
        $this->loggedOut = true;
    }
}
