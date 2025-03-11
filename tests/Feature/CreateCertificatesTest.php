<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Orchestra\Testbench\Concerns\WithWorkbench;

class CreateCertificatesTest extends TestCase
{
    use WithWorkbench;

    private const VARIABLE_REGEX_TEMPLATE = '/^%s=(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})\r?\n?/m';

    public function test_execute_command_with_show_option(): void
    {
        $code = $this->withoutMockingConsoleOutput()->artisan('jwtauth:generate-certificates');

        $output = Artisan::output();

        $this->assertStringContainsString('Copy and paste the content below into your .env file:', $output);
        $this->assertMatchesRegularExpression(sprintf(self::VARIABLE_REGEX_TEMPLATE, 'JWT_AUTH_PUBLIC_KEY'), $output);
        $this->assertMatchesRegularExpression(sprintf(self::VARIABLE_REGEX_TEMPLATE, 'JWT_AUTH_PRIVATE_KEY'), $output);

        self::assertSame(0, $code);
    }
}
