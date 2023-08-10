<?php

namespace App;

class AESHelper
{
    protected $blockBuffer = '';
    protected $printOFFSET = 0;

    public function __construct(
        protected $key,
        protected $iv,
        protected $method = "aes-256-ctr",
    )
    {
    }

    public function update($data)
    {
        $output = '';

        $this->blockBuffer .= $data;
        $output .= openssl_encrypt($this->blockBuffer, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);

        $out = substr($output, $this->printOFFSET);
        $this->printOFFSET = strlen($output);

        return $out;
    }
}