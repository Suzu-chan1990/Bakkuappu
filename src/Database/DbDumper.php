<?php
declare(strict_types=1);

namespace Bakkuappu\Database;

use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Support\Process;
use RuntimeException;

/**
 * Native MariaDB / MySQL dumper. The dump is streamed straight into the encryption,
 * no unencrypted SQL file is written.
 */
readonly class DbDumper
{
    /**
     * Dumps the WordPress database encrypted into $destPath and returns the stream key
     * (for the verification right after the backup).
     * $tmpDir holds the short-lived credentials file (0600) and the stderr log.
     */
    public function dumpEncrypted(string $destPath, BackupCrypto $crypto, string $tmpDir): string
    {
        if (!defined('DB_USER') || !defined('DB_PASSWORD') || !defined('DB_NAME') || !defined('DB_HOST')) {
            throw new RuntimeException('WordPress database constants are not defined.');
        }

        $binary = $this->findBinary();
        $credentials = self::writeCredentialsFile($tmpDir);

        try {
            // --defaults-extra-file must be the first option. The password is read from that
            // file, so it never appears in the process list (ps).
            $command = [
                $binary,
                '--defaults-extra-file=' . $credentials,
                '--single-transaction',
                '--routines',
                '--triggers',
                '--default-character-set=' . (defined('DB_CHARSET') && DB_CHARSET !== '' ? DB_CHARSET : 'utf8mb4'),
            ];
            // mysqldump from MySQL 8+ queries COLUMN_STATISTICS by default, which MariaDB servers
            // do not have ("Unknown table 'COLUMN_STATISTICS'"). mariadb-dump does not know the option.
            if (self::supportsOption($binary, '--column-statistics')) {
                $command[] = '--column-statistics=0';
            }
            $command[] = DB_NAME;

            $process = new Process($command, $tmpDir);
            try {
                $streamKey = $crypto->encryptToPath($process->stream, $destPath, ['kind' => 'db']);
            } catch (\Throwable $e) {
                $process->finish();
                throw $e;
            }
            [$code, $stderr] = $process->finish();
        } finally {
            @unlink($credentials);
        }

        if ($code !== 0) {
            if (file_exists($destPath)) unlink($destPath);
            throw new RuntimeException('Database dump failed (code ' . $code . ')' . ($stderr !== '' ? ': ' . $stderr : '.'));
        }
        return $streamKey;
    }

    /**
     * Writes a client option file readable only by the PHP user (also used for the import).
     */
    public static function writeCredentialsFile(string $tmpDir): string
    {
        $file = tempnam($tmpDir, 'bkp-my-');
        if ($file === false) {
            throw new RuntimeException('Temporary credentials file could not be created.');
        }
        chmod($file, 0600);

        $conn = self::parseHost((string) DB_HOST);
        $lines = ['[client]', 'user=' . self::quote((string) DB_USER), 'password=' . self::quote((string) DB_PASSWORD)];
        if ($conn['socket'] !== null) {
            $lines[] = 'socket=' . self::quote($conn['socket']);
        } else {
            $lines[] = 'host=' . self::quote($conn['host']);
            if ($conn['port'] !== null) $lines[] = 'port=' . $conn['port'];
        }

        if (file_put_contents($file, implode("\n", $lines) . "\n") === false) {
            @unlink($file);
            throw new RuntimeException('Temporary credentials file could not be written.');
        }
        return $file;
    }

    /**
     * Option file values are double-quoted; backslash and quote are escaped.
     */
    private static function quote(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    /**
     * Splits DB_HOST like WordPress does: "host", "host:3307", "host:/path/to.sock",
     * ":/path/to.sock", "[::1]:3307".
     *
     * @return array{host:string,port:?int,socket:?string}
     */
    public static function parseHost(string $dbHost): array
    {
        $host = $dbHost;
        $port = null;
        $socket = null;

        if (preg_match('/^\[([^\]]+)\](?::(\d+))?$/', $dbHost, $m)) {
            $host = $m[1];
            $port = isset($m[2]) && $m[2] !== '' ? (int) $m[2] : null;
        } elseif (substr_count($dbHost, ':') === 1) {
            [$host, $rest] = explode(':', $dbHost, 2);
            if ($rest !== '' && ctype_digit($rest)) {
                $port = (int) $rest;
            } elseif ($rest !== '') {
                $socket = $rest;
            }
        } elseif (str_contains($dbHost, ':') && str_contains($dbHost, '/')) {
            // "host:/path/with:colon.sock"
            $pos = strpos($dbHost, ':');
            $host = substr($dbHost, 0, $pos);
            $socket = substr($dbHost, $pos + 1);
        }

        if ($host === '') $host = 'localhost';
        return ['host' => $host, 'port' => $port, 'socket' => $socket];
    }

    /**
     * True when the dump binary lists $option in its --help output.
     */
    private static function supportsOption(string $binary, string $option): bool
    {
        if (!function_exists('exec')) return false;
        $out = [];
        $code = 1;
        @exec(escapeshellarg($binary) . ' --help 2>/dev/null', $out, $code);
        return $code === 0 && str_contains(implode("\n", $out), $option);
    }

    /**
     * Finds the dump binary. mariadb-dump comes first: newer MariaDB versions no longer ship
     * the "mysqldump" name (or only as a deprecated alias); mysqldump is the fallback for MySQL.
     */
    private function findBinary(): string
    {
        foreach (['mariadb-dump', 'mysqldump'] as $bin) {
            $path = Process::which($bin);
            if ($path !== null) return $path;
        }
        throw new RuntimeException('Critical error: neither mariadb-dump nor mysqldump was found on the system.');
    }
}
