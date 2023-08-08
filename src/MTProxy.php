<?php

namespace App;

use Clue\React\Socks\Client;
use React;
use React\Socket\TcpConnector;
use React\Socket\TcpServer;

class MTProxy
{
    protected ?TcpServer $clientSocket = null;

    protected array $telegramServerURLs = [
        0 => "149.154.175.50:443",
        1 => "149.154.167.51:443",
        2 => "149.154.175.100:443",
        3 => "149.154.167.91:443",
        4 => "149.154.171.5:443"
    ];

    protected array $idleConnections = [
        0 => [],
        1 => [],
        2 => [],
        3 => [],
        4 => [],
    ];

    public function __construct(
        protected int     $proxyPort,
        protected string  $proxySecret,
        protected ?string $socksProxy = null,
        protected int     $serverCount = 10
    )
    {
        for ($i = 0; $i < $serverCount; $i++) {
            $this->createNewServer(0);
            $this->createNewServer(1);
            $this->createNewServer(2);
            $this->createNewServer(3);
            $this->createNewServer(4);
        }

        $this->createProxyListener();
    }

    public function createProxyListener(): array
    {
        if ($this->clientSocket != null)
            return [
                'result' => false,
                'error' => 'Already initialized'
            ];

        $this->clientSocket = new React\Socket\TcpServer('0.0.0.0:' . $this->proxyPort);

        $this->clientSocket->on("connection", [$this, "onClientNewConnection"]);
        $this->clientSocket->on("error", function () {
            $this->clientSocket = null;
            $this->createProxyListener();
        });

        echo "Proxy initialize on https://t.me/proxy?server=192.168.3.13&port=" . $this->proxyPort . "&secret=" . $this->proxySecret . PHP_EOL;

        return ['result' => true];
    }

    public function onClientNewConnection(React\Socket\ConnectionInterface $clientConnection)
    {
        echo "New Income Connection" . PHP_EOL;
        $isInit = false;
        $serverConnection = null;
        $clientDecrypter = null;
        $clientEncrypter = null;
        $DCId = null;

        $clientConnection->on('data', function ($data) use (&$clientConnection, &$isInit, &$serverConnection, &$clientDecrypter, &$clientEncrypter, &$DCId) {
            echo sprintf("New Data Received With %s Len Data and %s init status\n", strlen($data), intval($isInit));
            if (!$isInit) {
                if (strlen($data) == 41 || strlen($data) == 56) {
                    $clientConnection->close();
                    return;
                }

                if (strlen($data) < 64) {
                    $clientConnection->close();
                    return;
                }

                $binariesSecret = hex2bin($this->proxySecret);
                $generateClientKeys = $this->generateKeyIVPair($data, $binariesSecret);

                $clientDecrypter = new AESHelper(
                    $generateClientKeys['decrypt']['key'],
                    $generateClientKeys['decrypt']['iv'],
                );

                $clientEncrypter = new AESHelper(
                    $generateClientKeys['encrypt']['key'],
                    $generateClientKeys['encrypt']['iv'],
                );

                $decryptedAuthPacket = $clientDecrypter->decrypt($data);
                $DCId = abs(unpack('s', substr($decryptedAuthPacket, 60, 2))[1]) - 1;

                for ($i = 0; $i < 4; $i++) {
                    if (ord($decryptedAuthPacket[56 + $i]) !== 0xef) {
                        $clientConnection->close();
                        return;
                    }
                }

                if ($DCId > 4 || $DCId < 0) {
                    $clientConnection->end();
                    return;
                }

                echo "Waanaa Connect on DataCenter $DCId " . PHP_EOL;

                $data = substr($data, 64);
                $isInit = true;
            }

            $payload = $clientDecrypter->decrypt($data);

            if ($serverConnection == null) {
                while (true) {
                    $serverConnection = $this->getIdleTelegramSocket($DCId);
                    if ($serverConnection == null)
                        break;

                    if (!$serverConnection['serverSocket']->isWritable()) {
                        echo "Server is not writeable" . PHP_EOL;
                        $serverConnection = null;
                    } else {
                        $serverConnection['serverSocket']->on('data', function ($data) use (&$clientConnection, &$serverConnection, &$clientEncrypter) {
                            echo "new Data from server" . PHP_EOL;
                            if ($clientConnection->isWritable()) {
                                $decryptedPacket = $serverConnection['serverDecrypter']->decrypt($data);
                                $encryptedPacket = $clientEncrypter->encrypt($decryptedPacket);

                                $isOk = $clientConnection->write($encryptedPacket);
                                echo "Write on Client is " . intval($isOk) . PHP_EOL;
                            } else {
                                echo "Client Not Writable" . PHP_EOL;
                                $clientConnection->close();
                                $serverConnection['serverSocket']->close();
                            }
                        });

                        $serverConnection['serverSocket']->on('error', function () use (&$clientConnection, &$serverConnection) {
                            $clientConnection->close();
                            $serverConnection['serverSocket']->close();
                        });

                        $serverConnection['serverSocket']->on('end', function () use (&$clientConnection, &$serverConnection) {
                            if ($clientConnection != null) {
                                $clientConnection->close();
                            }

                            $serverConnection['serverSocket']->close();
                        });
                        break;
                    }
                }

                if ($serverConnection == null) {
                    echo "No Active Server To Connect Client" . PHP_EOL;
                    $clientConnection->close();
                    return;
                }
            }

            $encryptedPayload = $serverConnection['serverEncrypter']->encrypt($payload);
            if ($serverConnection['serverSocket']->isWritable()) {
                $isOk = $serverConnection['serverSocket']->write($encryptedPayload);
                echo "Write on server is " . intval($isOk) . PHP_EOL;
            } else {
                $clientConnection->close();
                $serverConnection['serverSocket']->close();
            }
        });
    }

    protected function createNewServer(int $dc)
    {
        $client = new TcpConnector();
        if ($this->socksProxy == null)
            $connector = $client;
        else
            $connector = new Client($this->socksProxy, $client);

        $connector->connect($this->telegramServerURLs[$dc])
            ->then(function (React\Socket\ConnectionInterface $connection) use ($dc) {
                $generatedKeyPair = $this->generateKeyIVPair();

                $serverDecrypter = new AESHelper(
                    $generatedKeyPair['decrypt']['key'],
                    $generatedKeyPair['decrypt']['iv'],
                );

                $serverEncrypter = new AESHelper(
                    $generatedKeyPair['encrypt']['key'],
                    $generatedKeyPair['encrypt']['iv'],
                );

                $encryptedPacket = $serverEncrypter->encrypt($generatedKeyPair['buffer']);

                $encryptedPacket = substr_replace($encryptedPacket, $generatedKeyPair['buffer'], 0, 56);

                if (!$connection->write($encryptedPacket)) {
                    $connection->close();
                    return;
                }

                $this->idleConnections[$dc][] = [
                    'serverSocket' => $connection,

                    'serverDecrypter' => $serverDecrypter,
                    'serverEncrypter' => $serverEncrypter,
                ];
                echo "New Server On DC.$dc" . PHP_EOL;
            }, function () {
                echo "Failed" . PHP_EOL;
            })->catch(function () {
                echo "catch" . PHP_EOL;
            });
    }

    protected function getIdleTelegramSocket(int $dc)
    {
        if (count($this->idleConnections[$dc]) == 0)
            return null;

        $idleConnection = $this->idleConnections[$dc][0];
        array_shift($this->idleConnections[$dc]);
        $this->createNewServer($dc);
        return $idleConnection;
    }

    protected function generateKeyIVPair($buffer = null, $secret = null): array
    {
        if ($secret == null)
            $secret = '';

        try {
            if ($buffer == null)
                $buffer = random_bytes(64);

            /*
             * Temperary Disable That
                while (true) {
                    $val = (ord($buf64[3]) << 24) | (ord($buf64[2]) << 16) | (ord($buf64[1]) << 8) | ord($buf64[0]);
                    $val2 = (ord($buf64[7]) << 24) | (ord($buf64[6]) << 16) | (ord($buf64[5]) << 8) | ord($buf64[4]);

                    if ($buf64[0] != 0xef &&
                        $val != 0x44414548 &&
                        $val != 0x54534f50 &&
                        $val != 0x20544547 &&
                        $val != 0x4954504f &&
                        $val != 0xeeeeeeee &&
                        $val2 != 0x00000000) {
                        $buf64[56] = $buf64[57] = $buf64[58] = $buf64[59] = 0xef;
                        break;
                    }
                }
            */

            $keyIV = substr($buffer, 8, 48);

            return [
                'result' => true,
                'buffer' => $buffer,
                'decrypt' => [
                    'key' => hash("sha256", substr($keyIV, 0, 32) . $secret, true),
                    'iv' => substr($keyIV, 32, 16),
                ],
                'encrypt' => [
                    'key' => hash("sha256", substr($this->reverseKey($keyIV), 0, 32) . $secret, true),
                    'iv' => substr($this->reverseKey($keyIV), 32, 16),
                ]
            ];
        } catch (\Exception $e) {
            return [
                'result' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    protected function reverseKey($binaryString)
    {
        $length = strlen($binaryString);
        for ($i = 0, $j = $length - 1; $i < $j; ++$i, --$j) {
            $t = $binaryString[$j];
            $binaryString[$j] = $binaryString[$i];
            $binaryString[$i] = $t;
        }
        return $binaryString;
    }

}