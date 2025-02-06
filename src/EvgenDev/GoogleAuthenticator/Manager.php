<?php

namespace EvgenDev\GoogleAuthenticator;

class Manager
{
    protected GoogleAuthenticator $googleAuthenticator;

    public function __construct(Request $request)
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function getCode(string $secret, ?int $time = null): string
    {
        return $this->googleAuthenticator->getCode($secret, $time);
    }

    public function checkCode(string $secret, string $code): bool
    {
        return $this->googleAuthenticator->checkCode($secret, $code);
    }

    public function getQRCodeUrl(string $user, string $hostname, string $secret): string
    {
        return $this->googleAuthenticator->getQRCodeUrl($user, $hostname, $secret);
    }

    public function generateSecret(): string
    {
        return $this->googleAuthenticator->generateSecret();
    }
}