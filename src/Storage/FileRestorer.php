<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Support\Process;
use RuntimeException;

/**
 * Extracts an encrypted wp-content archive. The archive is decrypted straight into tar,
 * no unencrypted archive is written. Existing files are overwritten; files that are not in
 * the backup are left alone.
 */
readonly class FileRestorer
{
    public function restore(string $encPath, string $targetDir, BackupCrypto $crypto, string $tmpDir): void
    {
        $tar = Process::which('tar');
        if ($tar === null) {
            throw new RuntimeException('tar was not found on the system.');
        }
        if (!is_dir($targetDir) || !is_writable($targetDir)) {
            throw new RuntimeException('Target folder is not writable: ' . $targetDir);
        }

        // --no-same-owner: files belong to the PHP user; GNU tar refuses ".." and absolute
        // member names by default, so nothing is written outside $targetDir.
        $process = new Process([$tar, '-x', '--no-same-owner', '-C', $targetDir], $tmpDir, 'write');
        $error = null;
        try {
            $crypto->decryptToStream($encPath, $process->stream);
        } catch (\Throwable $e) {
            $error = $e;
        }
        [$code, $output] = $process->finish();

        if ($code !== 0) {
            throw new RuntimeException('Extracting failed (code ' . $code . ')' . ($output !== '' ? ': ' . $output : '.'));
        }
        if ($error) {
            throw new RuntimeException('Extracting aborted: ' . $error->getMessage());
        }
    }
}
