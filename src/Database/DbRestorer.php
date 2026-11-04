<?php
declare(strict_types=1);

namespace Bakkuappu\Database;

use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Support\Process;
use RuntimeException;

/**
 * Imports an encrypted database dump. The dump is decrypted straight into the MariaDB /
 * MySQL client, no unencrypted SQL file is written. Credentials come from wp-config.php.
 */
readonly class DbRestorer
{
    public function restore(string $encPath, BackupCrypto $crypto, string $tmpDir): void
    {
        $binary = $this->findClient();
        $credentials = DbDumper::writeCredentialsFile($tmpDir);
        try {
            $command = [
                $binary,
                '--defaults-extra-file=' . $credentials,
                '--default-character-set=' . (defined('DB_CHARSET') && DB_CHARSET !== '' ? DB_CHARSET : 'utf8mb4'),
                DB_NAME,
            ];
            $process = new Process($command, $tmpDir, 'write');
            $error = null;
            try {
                $crypto->decryptToStream($encPath, $process->stream);
            } catch (\Throwable $e) {
                // A write error usually means the client stopped; its message is more useful
                $error = $e;
            }
            [$code, $output] = $process->finish();
        } finally {
            @unlink($credentials);
        }

        if ($code !== 0) {
            throw new RuntimeException('Database import failed (code ' . $code . ')' . ($output !== '' ? ': ' . $output : '.'));
        }
        if ($error) {
            throw new RuntimeException('Database import aborted: ' . $error->getMessage());
        }
    }

    /**
     * MariaDB client first: newer MariaDB versions no longer ship the "mysql" name
     * (or only as a deprecated alias); mysql is the fallback for MySQL servers.
     */
    private function findClient(): string
    {
        foreach (['mariadb', 'mysql'] as $bin) {
            $path = Process::which($bin);
            if ($path !== null) return $path;
        }
        throw new RuntimeException('Neither the mariadb nor the mysql client was found on the system.');
    }
}
