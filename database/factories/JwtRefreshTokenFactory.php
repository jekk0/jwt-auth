<?php

namespace Jekk0\JwtAuth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Jekk0\JwtAuth\Model\JwtRefreshToken;
use Jekk0\JwtAuth\RefreshTokenStatus;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\Jekk0\JwtAuth\Model\JwtRefreshToken>
 */
class JwtRefreshTokenFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var class-string<\Illuminate\Database\Eloquent\Model>
     */
    protected $model = JwtRefreshToken::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'jti' => (string)Str::ulid(),
            'access_token_jti' => (string)Str::ulid(),
            'sub' => fake()->uuid(),
            'expired_at' => now()->addDay(),
            'status' => RefreshTokenStatus::Active,
        ];
    }

    public function used(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => RefreshTokenStatus::Used,
        ]);
    }
}
