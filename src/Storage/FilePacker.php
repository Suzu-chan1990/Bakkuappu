<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Support\Process;
use RuntimeException;

readonly class FilePacker
{
    /**
     * Creates a native tar stream and pipes it through the encryption in real time.
     * No unencrypted archive is written.
     *
     * Returns the stream key (for the verification right after the backup).
     *
     * @param list<string> $excludes tar --exclude patterns
     */
    public function packAndEncrypt(string $sourceDir, string $destEncFile, BackupCrypto $crypto, array $excludes = [], ?string $tmpDir = null): string
    {
        $tar = Process::which('tar');
        if ($tar === null) {
            throw new RuntimeException('tar was not found on the system.');
        }

        $command = [$tar, '-c', '-C', $sourceDir];
        foreach ($excludes as $ex) {
            $command[] = '--exclude=' . $ex;
        }
        $command[] = '.';

        $process = new Process($command, $tmpDir ?? dirname($destEncFile));
        try {
            $streamKey = $crypto->encryptToPath($process->stream, $destEncFile, ['kind' => 'files']);
        } catch (\Throwable $e) {
            $process->finish();
            throw $e;
        }
        [$exitCode, $stderr] = $process->finish();

        // Exit code 1 = "some files changed while being read" (GNU tar); the archive is still usable
        if ($exitCode !== 0 && $exitCode !== 1) {
            if (file_exists($destEncFile)) unlink($destEncFile);
            throw new RuntimeException('System tar error (code ' . $exitCode . '): ' . $stderr);
        }
        return $streamKey;
    }
}
