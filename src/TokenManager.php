<?php

namespace Jekk0\JwtAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Jekk0\JwtAuth\Contracts\CustomClaims;
use Jekk0\JwtAuth\Exceptions\TokenDecodeException;
use Psr\Clock\ClockInterface;
use Jekk0\JwtAuth\Contracts\TokenManager as TokenManagerContract;

final class TokenManager implements TokenManagerContract
{
    private const MODEL_HASH_ALGO = 'xxh3';

    private string $tokenIssuer = 'JWTAuth';

    /**
     * @param ClockInterface $clock
     * @param array{'public_key': string, 'private_key': string, 'alg': string, 'leeway': int, 'ttl': array{'access': int, 'refresh': int}} $config
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly array $config
    ) {
        JWT::$leeway = $this->config['leeway'];
    }

    public function makeTokenPair(Authenticatable $user): TokenPair
    {
        $now = $this->clock->now();
        $accessTokenExpiredAt = $this->getExpirationTime($now, TokenType::Access);
        $refreshTokenExpiredAt = $this->getExpirationTime($now, TokenType::Refresh);
        $accessTokenId = (string)Str::ulid();
        $refreshTokenId = (string)Str::ulid();

        $payload = [
            'iss' => $this->tokenIssuer,
            'sub' => $user->getAuthIdentifier(),
            'nbf' => $now->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'mhs' => $this->hashUserModel($user::class),
        ];

        // TODO
        $accessTokenPayload = array_merge(
            $payload,
            [
                'exp' => $accessTokenExpiredAt,
                'ttp' => TokenType::Access->value,
                'jti' => $accessTokenId,
                'rfi' => $refreshTokenId
            ]
        );

        $accessTokenPayload += $user instanceof CustomClaims
            ? $user->getJwtCustomClaims() : [];

        $refreshTokenPayload = array_merge(
            $payload,
            [
                'exp' => $refreshTokenExpiredAt,
                'ttp' => TokenType::Refresh->value,
                'jti' => $refreshTokenId,
                'rfi' => $accessTokenId
            ]
        );

        return new TokenPair(
            access: new Token(
                token: $this->encodePayload($accessTokenPayload),
                payload: new Payload($accessTokenPayload)
            ),
            refresh: new Token(
                token: $this->encodePayload($refreshTokenPayload),
                payload: new Payload($refreshTokenPayload)
            )
        );
    }

    public function decode(string $token): Token
    {
        try {
            $decoded = $this->decodePayload($token);
        } catch (\Exception $exception) {
            throw new TokenDecodeException($exception->getMessage(), previous: $exception);
        }

        return new Token($token, new Payload(get_object_vars($decoded)));
    }

    public function isPayloadFor(Payload $payload, string $userClass): bool
    {
        return $this->hashUserModel($userClass) === $payload->getModelHash();
    }

    public function setTokenIssuer(string $issuer): void
    {
        $this->tokenIssuer = $issuer;
    }

    private function getExpirationTime(\DateTimeImmutable $now, TokenType $tokenType): int
    {
        $ttl = match ($tokenType) {
            TokenType::Access => $this->config['ttl']['access'],
            TokenType::Refresh => $this->config['ttl']['refresh']
        };

        $ttlInterval = new \DateInterval("PT{$ttl}S");

        return $now->add($ttlInterval)->getTimestamp();
    }

    private function hashUserModel(string $model): string
    {
        return hash(self::MODEL_HASH_ALGO, $model);
    }

    /**
     * @param array<non-empty-string, mixed> $payload
     *
     * @return string
     */
    private function encodePayload(array $payload): string
    {
        return JWT::encode($payload, $this->config['private_key'], $this->config['alg']);
    }

    private function decodePayload(string $token): \stdClass
    {
        return JWT::decode($token, new Key($this->config['public_key'], $this->config['alg']));
    }
}
