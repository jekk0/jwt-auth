<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('jwt_refresh_tokens', function (Blueprint $table) {
            $table->char('jti', 26)->primary(false);
            $table->char('access_token_jti', 26)->index();
            $table->string('sub', 36);
            $table->timestamp('expired_at');
            $table->string('status', 36);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('jwt_auth_tokens');
    }
};
