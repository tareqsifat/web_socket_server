<?php
// ws_server.php
// Run: php ws_server.php
set_time_limit(0);
error_reporting(E_ALL);

$wsHost = '0.0.0.0';
$wsPort = 8080;

$adminHost = '127.0.0.1';
$adminPort = 9000;

$null = NULL;

// Create listening sockets
$wsSocket = stream_socket_server("tcp://{$wsHost}:{$wsPort}", $errno, $errstr);
if (!$wsSocket) {
    echo "Failed to create websocket socket: $errstr ($errno)\n";
    exit(1);
}
stream_set_blocking($wsSocket, false);
echo "WebSocket server listening on ws://{$wsHost}:{$wsPort}\n";

$adminSocket = stream_socket_server("tcp://{$adminHost}:{$adminPort}", $errno, $errstr);
if (!$adminSocket) {
    echo "Failed to create admin socket: $errstr ($errno)\n";
    exit(1);
}
stream_set_blocking($adminSocket, false);
echo "Admin notifier listening on {$adminHost}:{$adminPort}\n";

$clients = [];       // array of client streams => ['resource' => stream, 'handshake' => bool, 'buffer' => '']
$adminConnections = []; // we will accept admin connections transiently

while (true) {
    $read = [$wsSocket, $adminSocket];
    foreach ($clients as $c) { $read[] = $c['resource']; }
    foreach ($adminConnections as $c) { $read[] = $c; }

    $write = NULL;
    $except = NULL;
    $ready = @stream_select($read, $write, $except, 0, 200000); // 200ms

    if ($ready === false) { usleep(100000); continue; }
    if ($ready > 0) {
        // New WS client
        if (in_array($wsSocket, $read, true)) {
            $newsock = @stream_socket_accept($wsSocket, 0);
            if ($newsock) {
                stream_set_blocking($newsock, false);
                $key = (int)$newsock;
                $clients[$key] = ['resource' => $newsock, 'handshake' => false, 'buffer' => ''];
                echo "New WS client: $key\n";
            }
            $idx = array_search($wsSocket, $read, true);
            if ($idx !== false) unset($read[$idx]);
        }

        // New admin connection
        if (in_array($adminSocket, $read, true)) {
            $adminConn = @stream_socket_accept($adminSocket, 0);
            if ($adminConn) {
                stream_set_blocking($adminConn, false);
                $adminConnections[] = $adminConn;
                echo "New admin connection\n";
            }
            $idx = array_search($adminSocket, $read, true);
            if ($idx !== false) unset($read[$idx]);
        }

        // Read from clients
        foreach ($clients as $key => &$c) {
            $res = $c['resource'];
            if (in_array($res, $read, true)) {
                $data = @fread($res, 2048);
                if ($data === false || $data === '') {
                    // client disconnected
                    fclose($res);
                    unset($clients[$key]);
                    echo "Client $key disconnected\n";
                    continue;
                }
                if (!$c['handshake']) {
                    // perform WebSocket handshake
                    $c['buffer'] .= $data;
                    if (strpos($c['buffer'], "\r\n\r\n") !== false) {
                        $hdrs = $c['buffer'];
                        if (preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $hdrs, $matches)) {
                            $key64 = trim($matches[1]);
                            $accept = base64_encode(sha1($key64 . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
                            $upgrade  = "HTTP/1.1 101 Switching Protocols\r\n"
                                      . "Upgrade: websocket\r\n"
                                      . "Connection: Upgrade\r\n"
                                      . "Sec-WebSocket-Accept: $accept\r\n\r\n";
                            fwrite($res, $upgrade);
                            $c['handshake'] = true;
                            $c['buffer'] = '';
                            echo "Handshake done for client $key\n";
                        } else {
                            // invalid handshake, close
                            fclose($res);
                            unset($clients[$key]);
                            echo "Handshake failed (no key) for client $key\n";
                        }
                    }
                } else {
                    // websocket frame received (not used for chat from browser in this server)
                    // We won't expect messages from clients (we broadcast from admin). Still, we need to read & ignore.
                    $frame = $data;
                    // decode minimal one-frame text
                    $decoded = '';
                    $len = ord($frame[1]) & 127;
                    $masks = '';
                    $dataStart = 2;
                    if ($len === 126) {
                        $masks = substr($frame, 4, 4);
                        $dataStart = 8;
                    } elseif ($len === 127) {
                        $masks = substr($frame, 10, 4);
                        $dataStart = 14;
                    } else {
                        $masks = substr($frame, 2, 4);
                        $dataStart = 6;
                    }
                    $payload = substr($frame, $dataStart);
                    $out = '';
                    for ($i = 0; $i < strlen($payload); ++$i) {
                        $out .= $payload[$i] ^ $masks[$i % 4];
                    }
                    // optional: log incoming client message
                    // echo "Client message: $out\n";
                }
            }
        }
        unset($c);

        // Read from admin connections (transient)
        foreach ($adminConnections as $idx => $acon) {
            if (in_array($acon, $read, true)) {
                $payload = '';
                while (!feof($acon)) {
                    $buf = @fread($acon, 4096);
                    if ($buf === '' || $buf === false) break;
                    $payload .= $buf;
                }
                $payload = trim($payload);
                // admin connection finished or closed
                fclose($acon);
                unset($adminConnections[$idx]);
                if ($payload !== '') {
                    // broadcast payload to all WS clients
                    echo "Admin payload received: " . substr($payload,0,200) . "\n";
                    foreach ($clients as $k => $c2) {
                        if ($c2['handshake']) {
                            $msg = $payload;
                            // encode as ws frame
                            $b1 = chr(0x81); // final, text
                            $len = strlen($msg);
                            if ($len <= 125) {
                                $header = $b1 . chr($len);
                            } elseif ($len <= 65535) {
                                $header = $b1 . chr(126) . pack('n', $len);
                            } else {
                                $header = $b1 . chr(127) . pack('J', $len);
                            }
                            @fwrite($c2['resource'], $header . $msg);
                        }
                    }
                }
            }
        }
    }

    // small sleep to reduce CPU
    usleep(20000);
}
