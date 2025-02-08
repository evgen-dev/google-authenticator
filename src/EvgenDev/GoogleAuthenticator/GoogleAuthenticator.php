<?php

namespace EvgenDev\GoogleAuthenticator;

class GoogleAuthenticator
{
    const SECRET_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    const PASS_CODE_LENGTH = 6;
    const SECRET_LENGTH = 10;

    const NTP_SERVER_HOST = 'time.google.com';
    const NTP_SERVER_PORT = '123';

    const NTP_TIME = 'ntptime';
    const LOCAL_TIME = 'localtime';

    protected float|int|object $pinModulo;
    protected string $timeType = '';


    public function __construct(string $type = self::LOCAL_TIME)
    {
        $this->pinModulo = pow(10, static::PASS_CODE_LENGTH);
        $this->setTimeType($type);
    }

    /**
     * @param string $type
     * @return $this
     */
    public function setTimeType(string $type){
        if(!in_array($type, [self::LOCAL_TIME, self::NTP_TIME])){
            throw new \InvalidArgumentException('Unsupported time type provided');
        }

        $this->timeType = $type;
        return  $this;
    }

    /**
     * @param string $secret
     * @param string $code
     * @return bool
     */
    public function checkCode(string $secret, string $code): bool
    {
        $time = floor($this->time() / 30);
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
            $time = floor($this->time() / 30);
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

    protected function googleNTPTime()
    {
        $socket = @fsockopen(
            "udp://".static::NTP_SERVER_HOST,
            static::NTP_SERVER_PORT,
            $err_no,
            $err_str,
            1
        );

        if(!$socket) {
            throw new \RuntimeException('Could not connect to NTP server');
        }

        fwrite($socket,chr(0x1b).str_repeat("\0",47));
        $packetReceived=fread($socket,48);

        return unpack('N',$packetReceived,40)[1]-2208988800;
    }

    protected function time(): int{
        if($this->timeType == self::LOCAL_TIME){
            return time();
        }
        return $this->googleNTPTime();
    }
}

