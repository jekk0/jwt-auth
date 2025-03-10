<?php

namespace Jekk0\JwtAuth;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Jekk0\JwtAuth\Contracts\RequestGuard as JwtGuardContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Jekk0\JwtAuth\Contracts\Auth;
use Jekk0\JwtAuth\Contracts\TokenExtractor as TokenExtractorContract;
use Jekk0\JwtAuth\Events\JwtAccessTokenDecoded;
use Jekk0\JwtAuth\Events\JwtAttempting;
use Jekk0\JwtAuth\Events\JwtAuthenticated;
use Jekk0\JwtAuth\Events\JwtFailed;
use Jekk0\JwtAuth\Events\JwtLogin;
use Jekk0\JwtAuth\Events\JwtLogout;
use Jekk0\JwtAuth\Events\JwtLogoutFromAllDevices;
use Jekk0\JwtAuth\Events\JwtRefreshTokenCompromised;
use Jekk0\JwtAuth\Events\JwtRefreshTokenDecoded;
use Jekk0\JwtAuth\Events\JwtTokensRefreshed;
use Jekk0\JwtAuth\Events\JwtValidated;
use Jekk0\JwtAuth\Exceptions\RefreshTokenCompromised;
use Jekk0\JwtAuth\Exceptions\SubjectNotFound;
use Jekk0\JwtAuth\Exceptions\TokenDecodeException;
use Jekk0\JwtAuth\Exceptions\TokenInvalidType;
use Illuminate\Contracts\Events\Dispatcher;

final class RequestGuard implements JwtGuardContract
{
    private ?Authenticatable $user = null;
    private ?Token $accessToken = null;
    private bool $loggedOut = false;

    public function __construct(
        private readonly string $guard,
        private readonly Auth $jwtAuth,
        private readonly TokenExtractorContract $tokenExtractor,
        private readonly Dispatcher $dispatcher,
        private Request $request
    ) {
    }

    public function attempt(array $credentials): ?TokenPair
    {
        $this->dispatcher->dispatch(new JwtAttempting($this->guard, $credentials));

        $user = $this->jwtAuth->retrieveByCredentials($credentials);

        if ($user === null || $this->jwtAuth->hasValidCredentials($user, $credentials) === false) {
            $this->dispatcher->dispatch(new JwtFailed($this->guard, $user, $credentials));

            return null;
        }

        $this->dispatcher->dispatch(new JwtValidated($this->guard, $user));


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

        $this->dispatcher->dispatch(new JwtLogin($this->guard, $user));

        $this->setToken( $tokenPair->access);
        $this->setUser($user);

        return $tokenPair;
    }

    public function logout(): void
    {
        if ($this->user()) {
            $this->jwtAuth->revokeRefreshToken($this->accessToken->payload->getReferenceTokenId());

            $this->dispatcher->dispatch(new JwtLogout($this->guard, $this->user()));
        }

        $this->forgetUser();
    }

    public function logoutFromAllDevices(): void
    {
        if ($this->user()) {
            $this->jwtAuth->revokeAllRefreshTokens($this->user());

            $this->dispatcher->dispatch(new JwtLogoutFromAllDevices($this->guard, $this->user()));
        }

        $this->forgetUser();
    }

    public function refreshTokens(string $refreshToken): TokenPair
    {
        try {
            $token = $this->jwtAuth->decodeToken($refreshToken);
            if ($token->payload->getTokenType() !== TokenType::Refresh) {
                throw new TokenInvalidType('Invalid JWT token type. Expected refresh token.');
            }

            $this->dispatcher->dispatch(new JwtRefreshTokenDecoded($this->guard, $token));

            $user = $this->jwtAuth->retrieveByPayload($token->payload);

            if ($user === null) {
                throw new SubjectNotFound();
            }

            if ($this->jwtAuth->getRefreshToken($token->payload->getJwtId()) === null) {
                $this->dispatcher->dispatch(new JwtRefreshTokenCompromised($this->guard, $user, $token));

                throw new RefreshTokenCompromised();
            }

            $tokenPair = $this->login($user);
            $this->dispatcher->dispatch(new JwtTokensRefreshed($this->guard, $user, $tokenPair));
            $this->jwtAuth->revokeRefreshToken($token->payload->getJwtId());

            return $tokenPair;
        } catch (TokenDecodeException|TokenInvalidType|RefreshTokenCompromised|SubjectNotFound) {
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
                throw new TokenInvalidType('Invalid JWT token type. Expected access token.');
            }

            $this->dispatcher->dispatch(new JwtAccessTokenDecoded($this->guard, $accessToken));

            $user = $this->jwtAuth->retrieveByPayload($accessToken->payload);

            if ($user instanceof Authenticatable) {
                $this->setToken($accessToken);
                $this->setUser($user);
            }

            return $this->user;
        } catch (TokenDecodeException|TokenInvalidType) {
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

    public function setUser(Authenticatable $user): self
    {
        $this->user = $user;
        $this->loggedOut = false;

        $this->dispatcher->dispatch(new JwtAuthenticated($this->guard, $user, $this->accessToken));

        return $this;
    }

    public function setToken(Token $accessToken): void
    {
        $this->accessToken = $accessToken;
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
