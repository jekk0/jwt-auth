<?php

namespace Jekk0\JwtAuth\Model;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\MassPrunable;
use Jekk0\JwtAuth\RefreshTokenStatus;

final class JwtRefreshToken extends Model
{
    use HasUlids;
    use MassPrunable;

    protected $primaryKey = 'jti';
    protected $keyType = 'string';

    protected $casts = [
        'expired_at' => 'datetime',
        'status' => RefreshTokenStatus::class
    ];

    protected $fillable = [
        'jti',
        'access_token_jti',
        'sub',
        'expired_at',
        'status'
    ];

    protected $hidden = [

    ];

    /**
     * Get the prunable model query.
     *
     * @return \Illuminate\Database\Eloquent\Builder<static>
     */
    public function prunable()
    {
        return static::where('expired_at', '<=', now());
    }
}
