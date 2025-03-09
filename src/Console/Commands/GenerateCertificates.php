<?php

namespace Jekk0\JwtAuth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'jwtauth:generate-certificates')]
final class GenerateCertificates extends Command
{
    use ConfirmableTrait;

    private const BASE64_REGEX = '/^%s(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})\r?\n?/m';

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwtauth:generate-certificates
        {env? : Path to .env file for insert new configuration values}
        {--show : Display the key instead of modifying files}
        {--force : Force the operation to run when in production}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate and setup a new JWT tokens';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $newPublicKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $newPrivateKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        if ((bool)$this->option('show') === true) {
            $this->line("<comment>Public Key: $newPublicKey</comment>");
            $this->line("<comment>Private Key: $newPrivateKey</comment>");

            return 0;
        }

        if ($this->confirmToProceed() === false) {
            return 0;
        }

        $envFilePatch = $this->argument('env') ?: $this->laravel->environmentFilePath();

        $envPublicKeyRegex = sprintf(self::BASE64_REGEX, 'JWT_AUTH_PUBLIC_KEY=');
        $envPrivateKeyRegex = sprintf(self::BASE64_REGEX, 'JWT_AUTH_PRIVATE_KEY=');

        $envFileContent = file_get_contents($envFilePatch);

        $envPublicKeyExists = preg_match($envPublicKeyRegex, $envFileContent) === 1;
        $envPrivateKeyExists = preg_match($envPrivateKeyRegex, $envFileContent) === 1;

        /** @phpstan-ignore match.unhandled */
        $newEnvFileContent = match (true) {
            $envPublicKeyExists === true && $envPrivateKeyExists === true => preg_replace(
                [$envPublicKeyRegex, $envPrivateKeyRegex],
                ["JWT_AUTH_PUBLIC_KEY=$newPublicKey" . PHP_EOL, "JWT_AUTH_PRIVATE_KEY=$newPrivateKey" . PHP_EOL],
                $envFileContent
            ),

            $envPublicKeyExists === false && $envPrivateKeyExists === false => $envFileContent . PHP_EOL
                . "JWT_AUTH_PUBLIC_KEY=$newPublicKey" . PHP_EOL . "JWT_AUTH_PRIVATE_KEY=$newPrivateKey" . PHP_EOL,
            //todo add other steps ....
        };

        //todo backup on exception?

        file_put_contents($envFilePatch, $newEnvFileContent);

        $this->components->info('JWT Auth keys successfully updated.');

        return 0;
    }
}
