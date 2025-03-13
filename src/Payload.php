<?php

namespace Jekk0\JwtAuth;

/**
 * @implements \ArrayAccess<non-empty-string, mixed>
 */
final class Payload implements \ArrayAccess
{
    /**
     * @param array<string, mixed> $container
     */
    public function __construct(
        private readonly array $container
    ) {
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->container[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return  $this->container[$offset] ?? throw new \RuntimeException("Array key '$offset' not exists");
    }

    public function offsetSet(mixed $offset, mixed $value): never
    {
        throw new \RuntimeException("Cann't modify readonly payload");
    }

    public function offsetUnset(mixed $offset): never
    {
        throw new \RuntimeException("Cann't modify readonly payload");
    }

    public function getIssuer(): string
    {
        return $this->container['iss'];
    }

    public function getSubject(): int|string
    {
        return $this->container['sub'];
    }

    public function getExpiriedAt(): int
    {
        return $this->container['exp'];
    }

    public function getNotBefore(): int
    {
        return $this->container['nbf'];
    }

    public function getIssuedAt(): int
    {
        return $this->container['iat'];
    }

    public function getJwtId(): string
    {
        return $this->container['jti'];
    }

    public function getTokenType(): TokenType
    {
        return TokenType::from($this->container['ttp']);
    }

    public function getReferenceTokenId(): string
    {
        return $this->container['rfi'];
    }

    public function getModelHash(): string
    {
        return $this->container['mhs'];
    }
}
