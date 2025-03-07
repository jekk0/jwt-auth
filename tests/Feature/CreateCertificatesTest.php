<?php

namespace Jekk0\JwtAuth\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Orchestra\Testbench\Concerns\WithWorkbench;

class CreateCertificatesTest extends TestCase
{
    use WithWorkbench;

    private const PUBLIC_KEY_REGEX = '/^JWT_AUTH_PUBLIC_KEY=(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})\r?\n?/m';
    private const PRIVATE_KEY_REGEX = '/^JWT_AUTH_PRIVATE_KEY=(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})\r?\n?/m';

    public function test_execute_command_with_show_option(): void
    {
        $code = $this->withoutMockingConsoleOutput()
            ->artisan('jwtauth:generate-certificates', ['--show' => 1]);

        $output = Artisan::output();

        self::assertSame(0, $code);
        $this->assertStringContainsString('Public Key: ', $output);
        $this->assertStringContainsString('Private Key: ', $output);
    }

    public function test_execute_command_add_auth_env_variables(): void
    {
        $envfile = tempnam(sys_get_temp_dir(), '_env');
        $data = <<<'ENV'
            APP_URL=http://localhost.com
            ENV;

        file_put_contents($envfile, $data);

        $this->artisan('jwtauth:generate-certificates', ['env' => $envfile])
            ->expectsOutputToContain('JWT Auth keys successfully updated.')
            ->assertExitCode(0);

        $content = file($envfile);
        $this->assertMatchesRegularExpression(self::PUBLIC_KEY_REGEX, $content[1]);
        $this->assertMatchesRegularExpression(self::PRIVATE_KEY_REGEX, $content[2]);

        unset($envfile);
    }

    public function test_execute_command_update_auth_env_variables(): void
    {
        $envfile = tempnam(sys_get_temp_dir(), '_env');
        $data = <<<'ENV'
            APP_NAME=Laravel
            APP_ENV=local
            APP_URL=http://localhost.com
            JWT_AUTH_PUBLIC_KEY=iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=
            JWT_AUTH_PRIVATE_KEY=BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJVQrE+pkUswP8ws40q9cwDjtiTi5SrNKAcAdISIFGNA==
            ENV;

        file_put_contents($envfile, $data);

        $this->artisan('jwtauth:generate-certificates', ['env' => $envfile])
            ->expectsOutputToContain('JWT Auth keys successfully updated.')
            ->assertExitCode(0);

        $content = file($envfile);

        $this->assertMatchesRegularExpression('/^APP_NAME=Laravel\r?\n?/m', $content[0]);
        $this->assertMatchesRegularExpression('/^APP_ENV=local\r?\n?/m', $content[1]);
        $this->assertMatchesRegularExpression('/^APP_URL=http:\/\/localhost\.com\r?\n?/m', $content[2]);

        $this->assertMatchesRegularExpression(self::PUBLIC_KEY_REGEX, $content[3]);
        $this->assertStringNotContainsString('iVUKxPqZFLMD/MLONKvXMA47Yk4uUqzSgHAHSEiBRjQ=', $content[3]);
        $this->assertMatchesRegularExpression(self::PRIVATE_KEY_REGEX, $content[4]);
        $this->assertStringNotContainsString('BO2A8TxpH/g3TJqL2udi4lkDumzI6kXoz2o/NC2dRaOJV', $content[4]);

        unset($envfile);
    }
}
