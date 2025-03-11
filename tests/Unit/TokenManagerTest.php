<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Firebase\JWT\JWT;
use Jekk0\JwtAuth\Contracts\CustomClaims;
use Jekk0\JwtAuth\Exceptions\TokenDecodeException;
use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\TokenManager;
use Jekk0\JwtAuth\TokenPair;
use Jekk0\JwtAuth\TokenType;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Workbench\App\Models\User;

class TokenManagerTest extends TestCase
{
    public function test_make_token_pair(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        $timestamp = 1700000000;
        $clock->expects($this->once())->method('now')->willReturn(new \DateTimeImmutable("@$timestamp"));
        JWT::$timestamp = $timestamp;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('getAuthIdentifier')->willReturn($id = 1);

        $result = $tokenManager->makeTokenPair($user);

        self::assertInstanceOf(TokenPair::class, $result);
        self::assertNotSame(
            $result->access->payload->getReferenceTokenId(),
            $result->refresh->payload->getReferenceTokenId()
        );

        // Access token
        self::assertTrue(is_string($result->access->token));
        self::assertSame('JWTAuth', $result->access->payload->getIssuer());
        self::assertSame($id, $result->access->payload->getSubject());
        self::assertSame(hash('xxh3', $user::class), $result->access->payload->getAudience());
        self::assertSame($timestamp, $result->access->payload->getNotBefore());
        self::assertSame($timestamp, $result->access->payload->getIssuedAt());
        self::assertSame($timestamp + 3600, $result->access->payload->getExpiriedAt());
        self::assertSame(TokenType::Access, $result->access->payload->getTokenType());
        self::assertTrue(is_string($result->access->payload->getJwtId()));
        self::assertTrue(is_string($result->access->payload->getReferenceTokenId()));

        // Refresh token
        self::assertTrue(is_string($result->refresh->token));
        self::assertSame('JWTAuth', $result->refresh->payload->getIssuer());
        self::assertSame($id, $result->refresh->payload->getSubject());
        self::assertSame(hash('xxh3', $user::class), $result->refresh->payload->getAudience());
        self::assertSame($timestamp, $result->refresh->payload->getNotBefore());
        self::assertSame($timestamp, $result->refresh->payload->getIssuedAt());
        self::assertSame($timestamp + 2592000, $result->refresh->payload->getExpiriedAt());
        self::assertSame(TokenType::Refresh, $result->refresh->payload->getTokenType());
        self::assertTrue(is_string($result->refresh->payload->getJwtId()));
        self::assertTrue(is_string($result->refresh->payload->getReferenceTokenId()));
    }

    public function test_make_token_pair_with_custom_claims(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        $timestamp = 1700000000;
        $clock->expects($this->once())->method('now')->willReturn(new \DateTimeImmutable("@$timestamp"));
        JWT::$timestamp = $timestamp;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $user = new class () extends User implements CustomClaims {
            public int $id = 122;

            public function getJwtCustomClaims(): array
            {
                return [
                    'role' => 'user',
                    'value' => 139,
                    'otherCustom' => 'value'
                ];
            }
        };

        $result = $tokenManager->makeTokenPair($user);

        // Access token
        self::assertArrayHasKey('role', $result->access->payload);
        self::assertArrayHasKey('value', $result->access->payload);
        self::assertArrayHasKey('otherCustom', $result->access->payload);
        self::assertSame('user', $result->access->payload['role']);
        self::assertSame(139, $result->access->payload['value']);
        self::assertSame('value', $result->access->payload['otherCustom']);

        // Refresh token
        self::assertArrayNotHasKey('user', $result->refresh->payload);
        self::assertArrayNotHasKey('value', $result->refresh->payload);
        self::assertArrayNotHasKey('otherCustom', $result->refresh->payload);
    }

    public function test_decode(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        $timestamp = 1700000000;
        $clock->expects($this->once())->method('now')->willReturn(new \DateTimeImmutable("@$timestamp"));
        JWT::$timestamp = $timestamp;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('getAuthIdentifier')->willReturn($id = 1);

        $tokenPair = $tokenManager->makeTokenPair($user);

        self::assertEquals($tokenPair->access->payload, $tokenManager->decode($tokenPair->access->token)->payload);
        self::assertEquals($tokenPair->refresh->payload, $tokenManager->decode($tokenPair->refresh->token)->payload);
    }

    public function test_decode_broken_configuration(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        $tokenManager = new TokenManager($clock, ['public_key' => '', 'private_key' => '', 'alg' => '']);

        $this->expectException(TokenDecodeException::class);

        $tokenManager->decode('');
    }

    public function test_decode_expired_token(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        JWT::$timestamp = null;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $token =
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJKV1RBdXRoIiwic3ViIjoxLCJhdWQiOiI3OTZkYzExZTllODYwNmQwIiwibmJmIjoxNzAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMjU5MjAwMCwidHRwIjoicmVmcmVzaCIsImp0aSI6IjAxSk5QRjRGTVlZS1paQlFDRTVQWlZRUDFaIiwicmZpIjoiMDFKTlBGNEZNWVlLWlpCUUNFNVBaVlFQMVkifQ.tdGuVGuDox-S9gtFQ_erEGQ6AdRfPEmF8s0WWFaLhked31-elH6hXvOCyAoXyAIZ6j6LUJuosSTVc5ktdn8xBQ';

        $this->expectException(TokenDecodeException::class);
        $this->expectExceptionMessage('Expired token');

        $tokenManager->decode($token);
    }

    public function test_is_payload_for_valid_user(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        JWT::$timestamp = null;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $payload = new Payload(['aud' => hash('xxh3', User::class)]);

        $result = $tokenManager->isPayloadFor($payload, User::class);

        self::assertTrue($result);
    }

    public function test_is_payload_for_invalid_user(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        JWT::$timestamp = null;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $payload = new Payload(['aud' => 'invalid']);

        $result = $tokenManager->isPayloadFor($payload, User::class);

        self::assertFalse($result);
    }

    public function test_set_token_issuer(): void
    {
        $clock = $this->createMock(ClockInterface::class);
        $timestamp = 1700000000;
        $clock->expects($this->once())->method('now')->willReturn(new \DateTimeImmutable("@$timestamp"));
        JWT::$timestamp = $timestamp;
        $tokenManager = new TokenManager($clock, $this->getConfig());
        $tokenManager->setTokenIssuer('X-TOKEN-ISSUER-EXAMPLE');
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('getAuthIdentifier')->willReturn(1);

        $result = $tokenManager->makeTokenPair($user);

        self::assertSame('X-TOKEN-ISSUER-EXAMPLE', $result->access->payload->getIssuer());
    }

    private function getConfig(): array
    {
        return [
            'public_key' => 'iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=',
            'private_key' => 'BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJVQrE+pkUswP8ws40q9cwDjtiTi5SrNKAcAdISIFGNA==',
            'alg' => 'EdDSA',
            'ttl' => [
                'access' => 3600,
                'refresh' => 2592000,
            ],
        ];
    }
}
