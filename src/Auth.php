<?php

namespace Jekk0\JwtAuth;

use Illuminate\Contracts\Auth\UserProvider;
use Jekk0\JwtAuth\Contracts\Auth as JwtAuthContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Jekk0\JwtAuth\Contracts\RefreshTokenRepository;
use Jekk0\JwtAuth\Contracts\TokenManager;
use Jekk0\JwtAuth\Model\JwtRefreshToken;

final class Auth implements JwtAuthContract
{
    public function __construct(
        private readonly TokenManager $tokenManager,
        private readonly UserProvider $userProvider,
        private readonly RefreshTokenRepository $refreshTokenRepository
    ) {
    }

    public function createTokenPair(Authenticatable $user): TokenPair
    {
        $tokenPair = $this->tokenManager->makeTokenPair($user);

        $this->refreshTokenRepository->create(
            jti: $tokenPair->refresh->payload->getJwtId(),
            accessTokenJti: $tokenPair->access->payload->getJwtId(),
            subject: $tokenPair->refresh->payload->getSubject(),
            expired_at: new \DateTimeImmutable("@{$tokenPair->refresh->payload->getExpiriedAt()}"),
        );

        return $tokenPair;
    }

    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        return $this->userProvider->retrieveByCredentials($credentials);
    }

    public function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        return $this->userProvider->validateCredentials($user, $credentials) === true;
    }

    public function retrieveByPayload(Payload $payload): ?Authenticatable
    {
        $model = method_exists($this->userProvider, 'getModel') ? $this->userProvider->getModel() : null;

        if ($model && $this->tokenManager->isPayloadFor($payload, $model)) {
            return $this->userProvider->retrieveById($payload->getSubject());
        }

        return null;
    }

    // todo chenge arg
    public function getRefreshToken(string $jti): ?JwtRefreshToken
    {
        return $this->refreshTokenRepository->get($jti);
    }

    public function decodeToken(string $token): Token
    {
        return $this->tokenManager->decode($token);
    }

    // todo chenge arg
    public function revokeRefreshToken(string $jti): void
    {
        $this->refreshTokenRepository->delete($jti);
    }

    public function revokeAllRefreshTokens(Authenticatable $user): void
    {
        $this->refreshTokenRepository->deleteAllBySubject($user->getAuthIdentifier());
    }

    // todo test
    // todo chenge arg
    public function markAsUsed(string $jti): void
    {
        $this->refreshTokenRepository->markAsUsed($jti);
    }

    // todo chenge arg
    // todo test
    public function markAsCompromised(string $jti): void
    {
        $this->refreshTokenRepository->markAsCompromised($jti);
    }
}
