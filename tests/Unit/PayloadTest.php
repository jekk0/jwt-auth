<?php

namespace Jekk0\JwtAuth\Tests\Unit;

use Jekk0\JwtAuth\Payload;
use Jekk0\JwtAuth\TokenType;
use PHPUnit\Framework\TestCase;
use Workbench\App\Models\User;

class PayloadTest extends TestCase
{
    public function test_jwt_getters(): void
    {
        $issuer = 'issuer';
        $subject = 'subject';
        $modelHash = User::class;
        $expirationTime = time() + 1000;
        $notBefore = $issuedAt = time();
        $jwtId = '1234-5678-9101';
        $rfi = 'abcd=efgh-ijkl';
        $payload = new Payload([
            'iss' => $issuer,
            'sub' => $subject,
            'exp' => $expirationTime,
            'nbf' => $notBefore,
            'iat' => $issuedAt,
            'jti' => $jwtId,
            'ttp' => TokenType::Access->value,
            'rfi' => $rfi,
            'mhs' => $modelHash,
        ]);

        self::assertSame($issuer, $payload->getIssuer());
        self::assertSame($subject, $payload->getSubject());
        self::assertSame($expirationTime, $payload->getExpiriedAt());
        self::assertSame($notBefore, $payload->getNotBefore());
        self::assertSame($issuedAt, $payload->getIssuedAt());
        self::assertSame($jwtId, $payload->getJwtId());
        self::assertSame(TokenType::Access, $payload->getTokenType());
        self::assertSame($rfi, $payload->getReferenceTokenId());
        self::assertSame($modelHash, $payload->getModelHash());
    }

    public function test_array_offset_exists(): void
    {
        $payload = new Payload(['custom' => 1]);

        $result = $payload->offsetExists('custom');

        self::assertTrue($result);
    }

    public function test_array_offset_not_exists(): void
    {
        $payload = new Payload([]);

        $result = $payload->offsetExists('custom');

        self::assertFalse($result);
    }

    public function test_array_offset_get(): void
    {
        $payload = new Payload(['value' => 'str']);

        $result = $payload->offsetGet('value');

        self::assertSame('str', $result);
    }

    public function test_array_offset_get_thrown_exception(): void
    {
        $payload = new Payload([]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Array key 'unavailable' not exists");

        $payload->offsetGet('unavailable');
    }

    public function test_array_offset_set(): void
    {
        $payload = new Payload([]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Cann't modify readonly payload");

        $payload->offsetSet('key', 'value');
    }

    public function test_array_offset_unset(): void
    {
        $payload = new Payload([]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Cann't modify readonly payload");

        $payload->offsetUnset('key');
    }
}
