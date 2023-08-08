<?php

namespace App;

class AESHelper
{
    public function __construct(
        protected $key,
        protected $iv,
        protected $method = "aes-256-ctr",
    )
    {
    }

    public function encrypt(string $message): bool|string
    {
        // todo maybe bin2hex
        return openssl_encrypt($message, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }

    public function decrypt(string $message): bool|string
    {
        return openssl_decrypt($message, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }
}