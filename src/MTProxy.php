<?php

namespace App;

use Clue\React\Socks\Client;
use React;
use React\Socket\TcpConnector;
use React\Socket\TcpServer;

class MTProxy
{
    protected int $counter = 0;
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
        protected int     $serverCount = 5
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

        $this->clientSocket = new TcpServer(
            '0.0.0.0:' . $this->proxyPort,
            context: [
                'so_reuseport' => true,
            ]
        );

        $this->clientSocket->on("connection", [$this, "onClientNewConnection"]);
        $this->clientSocket->on("error", function () {
            $this->clientSocket = null;
            $this->createProxyListener();
        });

        echo "Starting Service.." . PHP_EOL;

        return ['result' => true];
    }

    public function onClientNewConnection(React\Socket\ConnectionInterface $clientConnection)
    {
//        echo "New Income Connection" . PHP_EOL;
        $isInit = false;
        $connId = null;
        $serverConnection = null;
        $clientDecrypter = null;
        $clientEncrypter = null;
        $DCId = null;

        $clientConnection->on('data', function ($data) use (&$clientConnection, &$isInit, &$serverConnection, &$clientDecrypter, &$clientEncrypter, &$DCId, &$connId) {
            if ($connId == null)
                $connId = $this->getUniqueID();

            echo "Client #$connId Sent Data With " . strlen($data) . " Size" . PHP_EOL;
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
                $generateClientKeys = $this->generateKeyIVPairClient($data, $binariesSecret);

                $clientDecrypter = new AESHelper(
                    $generateClientKeys['decrypt']['key'],
                    $generateClientKeys['decrypt']['iv'],
                );

                $clientEncrypter = new AESHelper(
                    $generateClientKeys['encrypt']['key'],
                    $generateClientKeys['encrypt']['iv'],
                );

                $decryptedAuthPacket = $clientDecrypter->update($generateClientKeys['buffer']);
                $DCId = abs(unpack('s', substr($decryptedAuthPacket, 60, 2))[1]) - 1;

                for ($i = 0; $i < 4; $i++) {
                    if (bin2hex($decryptedAuthPacket[56 + $i]) != "ef") {
                        echo "******** Client Destroyed Line 110";
                        $clientConnection->close();
                        return;
                    }
                }

                if ($DCId > 4 || $DCId < 0) {
                    echo "********  Client Destroyed Cause DataCenterID not in range" . PHP_EOL;
                    $clientConnection->end();
                    return;
                }

                echo "Connect on DataCenter $DCId " . PHP_EOL;

                $data = substr($data, 64);
//                $this->hexView("Data       ", $data);
                $isInit = true;
            }

            // TODO Why 105 Size Packets FROM Payload In JS Starts with a0 00 00 But in php no! maybe something wrong in substr o sth else. check thats
            $payload = $clientDecrypter->update($data);
//            $this->hexView("Payload:   ", $payload);

            if ($serverConnection == null) {
                while (true) {
                    $serverConnection = $this->getIdleTelegramSocket($DCId);
                    if ($serverConnection == null) {
                        break;
                    }

                    if (!$serverConnection['serverSocket']->isWritable()) {
                        echo "********  Server is not writeable" . PHP_EOL;
                        $serverConnection = null;
                    } else {
//                        $serverConnection['serverSocket']->write(bin2hex("ef"));
                        $serverConnection['serverSocket']->on('data', function ($data) use (&$clientConnection, &$serverConnection, &$clientEncrypter, &$connId) {
                            echo "Client #$connId Receive message from server with " . strlen($data) . " size" . PHP_EOL;
                            if ($clientConnection->isWritable()) {
                                $decryptedPacket = $serverConnection['serverDecrypter']->update($data);
                                $encryptedPacket = $clientEncrypter->update($decryptedPacket);

                                $isOk = $clientConnection->write($encryptedPacket);
                                echo "Client #$connId Responed To Device with " . intval($isOk) . " status" . PHP_EOL;
                            } else {
                                echo "******** Client Not Writable" . PHP_EOL;
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
                    echo "********  No Active Server To Connect Client" . PHP_EOL;
                    $clientConnection->close();
                    return;
                }
            }

            $encryptedPayload = $serverConnection['serverEncrypter']->update($payload);
            if ($serverConnection['serverSocket']->isWritable()) {
                $isOk = $serverConnection['serverSocket']->write($encryptedPayload);
                echo "Client #$connId Write on server With " . intval($isOk) . " Status" . PHP_EOL;
            } else {
                $clientConnection->close();
                $serverConnection['serverSocket']->close();
            }
        });

        $clientConnection->on("end", function () use (&$clientConnection, &$serverConnection, &$connId) {
            echo "******** Client #$connId Closed Cause END" . PHP_EOL;
            $clientConnection->close();
            if ($serverConnection != null) $serverConnection['serverSocket']->close();
        });
        $clientConnection->on("timeout", function () use (&$clientConnection, &$serverConnection, &$connId) {
            echo "******** Client #$connId Closed Cause TIMEOUT" . PHP_EOL;
            $clientConnection->close();
            if ($serverConnection != null) $serverConnection['serverSocket']->close();
        });
        $clientConnection->on("error", function () use (&$clientConnection, &$serverConnection, &$connId) {
            echo "******** Client #$connId Closed Cause ERROR" . PHP_EOL;
            $clientConnection->close();
            if ($serverConnection != null) $serverConnection['serverSocket']->close();
        });
    }

    protected function createNewServer(int $dc)
    {
        $client = new React\Socket\TcpConnector();

        if ($this->socksProxy == null)
            $connector = $client;
        else
            $connector = new Client($this->socksProxy, $client);

        $connector->connect($this->telegramServerURLs[$dc])
            ->then(function (React\Socket\ConnectionInterface $connection) use ($dc) {
                $generatedKeyPair = $this->generateKeyIVPairServer();

                $serverDecrypter = new AESHelper(
                    $generatedKeyPair['decrypt']['key'],
                    $generatedKeyPair['decrypt']['iv'],
                );

                $serverEncrypter = new AESHelper(
                    $generatedKeyPair['encrypt']['key'],
                    $generatedKeyPair['encrypt']['iv'],
                );

                $encryptedPacket = $serverEncrypter->update($generatedKeyPair['buffer']);
                $editedEncryptedPacket = substr($generatedKeyPair['buffer'], 0, 56) . substr($encryptedPacket, 56);

                if (!$connection->write($editedEncryptedPacket)) {
                    $connection->close();
                    return;
                }

                $this->idleConnections[$dc][] = [
                    'serverSocket' => $connection,

                    'serverDecrypter' => $serverDecrypter,
                    'serverEncrypter' => $serverEncrypter,
                ];
//                echo "New Server On DC.$dc" . PHP_EOL;
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

        $this->createNewServer($dc);
        return array_shift($this->idleConnections[$dc]);
    }

    protected function generateKeyIVPairServer(): array
    {
        try {
            $buffer = $this->generateRandomBuffer();
            while (!$this->checkBuffer($buffer)) {
                $buffer = $this->generateRandomBuffer();
            }

            $buffer[56] = $buffer[57] = $buffer[58] = $buffer[59] = hex2bin('EF');

            $keyIV = substr($buffer, 8, 48);

            return [
                'result' => true,
                'buffer' => $buffer,
                'encrypt' => [
                    'key' => substr($keyIV, 0, 32),
                    'iv' => substr($keyIV, 32, 16),
                ],
                'decrypt' => [
                    'key' => substr(strrev($keyIV), 0, 32),
                    'iv' => substr(strrev($keyIV), 32, 16),
                ]
            ];
        } catch (\Exception $e) {
            return [
                'result' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    protected function generateKeyIVPairClient($buffer, $secret): array
    {
        try {
            $buffer = substr($buffer, 0, 64);
            $keyIV = substr($buffer, 8, 48);

            return [
                'result' => true,
                'buffer' => $buffer,
                'decrypt' => [
                    'key' => hash("sha256", substr($keyIV, 0, 32) . $secret, true),
                    'iv' => substr($keyIV, 32, 16),
                ],
                'encrypt' => [
                    'key' => hash("sha256", substr(strrev($keyIV), 0, 32) . $secret, true),
                    'iv' => substr(strrev($keyIV), 32, 16),
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

    protected function generateRandomBuffer(): string
    {
        $randomBytes = random_bytes(64);
        return $randomBytes;
    }

    protected function checkBuffer($randomBytes): bool
    {
        $firstByte = $randomBytes[0];
        $val = (ord($randomBytes[3]) << 24) | (ord($randomBytes[2]) << 16) | (ord($randomBytes[1]) << 8) | ord($randomBytes[0]);
        $val2 = (ord($randomBytes[7]) << 24) | (ord($randomBytes[6]) << 16) | (ord($randomBytes[5]) << 8) | ord($randomBytes[4]);

        return ($firstByte != 0xef) && ($val != 0x44414548) && ($val != 0x54534f50) && ($val != 0x20544547) && ($val != 0x4954504f) && ($val != 0xeeeeeeee) && ($val2 != 0x00000000);
    }

    protected function getUniqueID(): int
    {
        return ++$this->counter;
    }

    protected function hexView($ctx, $bin, $unlimit = false)
    {
        $x = str_split(bin2hex($bin), 2);
        if ($unlimit)
            echo "$ctx: " . implode(" ", $x) . " - Count: " . count($x) . PHP_EOL;
        else
            echo "$ctx: " . implode(" ", array_slice($x, 0, 41)) . " - Count: " . count($x) . PHP_EOL;
    }

}