<?php

namespace EvgenDev\GoogleAuthenticator;

class GoogleAuthenticator
{
    const SECRET_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    const PASS_CODE_LENGTH = 6;
    const SECRET_LENGTH = 10;

    protected float|int|object $pinModulo;


    public function __construct()
    {
        $this->pinModulo = pow(10, static::PASS_CODE_LENGTH);
    }

    /**
     * @param string $secret
     * @param string $code
     * @return bool
     */
    public function checkCode(string $secret, string $code): bool
    {
        $time = floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            if (hash_equals($this->getCode($secret, $time + $i), $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $secret
     * @param int|null $time
     * @return string
     */
    public function getCode(string $secret, ?int $time = null): string
    {
        if (is_null($time)) {
            $time = floor(time() / 30);
        }

        $base32 = new FixedBitNotation(5, static::SECRET_CHARS, true, true);
        $secret = $base32->decode($secret);

        $time = pack("N", $time);
        $time = str_pad($time, 8, chr(0), STR_PAD_LEFT);

        $hash = hash_hmac('sha1', $time, $secret, true);
        $offset = ord(substr($hash, -1));
        $offset = $offset & 0xF;

        $truncatedHash = self::hashToInt($hash, $offset) & 0x7FFFFFFF;
        $pinValue = str_pad($truncatedHash % $this->pinModulo, 6, "0", STR_PAD_LEFT);;

        return $pinValue;
    }

    protected function hashToInt($bytes, $start)
    {
        $input = substr($bytes, $start, strlen($bytes) - $start);
        $val2 = unpack("N", substr($input, 0, 4));
        return $val2[1];
    }

    /**
     * @param string $user
     * @param string $hostname
     * @param string $secret
     * @return string
     */
    public function getQRCodeUrl(string $user, string $hostname, string $secret): string
    {
        $encoder = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=";
        return sprintf("%sotpauth://totp/%s@%s&secret=%s", $encoder, $user, $hostname, $secret);
    }

    public function generateSecret(): string
    {
        $secret = "";
        for ($i = 1; $i <= static::SECRET_LENGTH; $i++) {
            $c = rand(0, 255);
            $secret .= pack("c", $c);
        }
        $base32 = new FixedBitNotation(5, static::SECRET_CHARS, true, true);
        return $base32->encode($secret);
    }
}

