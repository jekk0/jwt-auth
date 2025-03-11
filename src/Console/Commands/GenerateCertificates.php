<?php

namespace Jekk0\JwtAuth\Console\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'jwtauth:generate-certificates')]
final class GenerateCertificates extends Command
{
    protected $signature = 'jwtauth:generate-certificates';

    protected $description = 'Generate JWT auth certificates';

    public function handle(): int
    {
        $keyPair = sodium_crypto_sign_keypair();
        $publicKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $privateKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $this->line("<info>Copy and paste the content below into your .env file:</info>");
        $this->line("");
        $this->line("<info>JWT_AUTH_PUBLIC_KEY=$publicKey</info>");
        $this->line("<info>JWT_AUTH_PRIVATE_KEY=$privateKey</info>");

        return 0;
    }
}
