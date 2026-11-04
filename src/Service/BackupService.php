<?php
declare(strict_types=1);

namespace Bakkuappu\Service;

use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Database\DbDumper;
use Bakkuappu\Database\DbRestorer;
use Bakkuappu\Storage\BackupFile;
use Bakkuappu\Storage\DiskSpace;
use Bakkuappu\Storage\Retention;
use Bakkuappu\Storage\FilePacker;
use Bakkuappu\Storage\FileRestorer;
use Bakkuappu\Support\JobLog;
use Bakkuappu\Support\Settings;
use RuntimeException;

/**
 * Backup, verify and restore steps. Used by the WP-CLI commands (also when started from the
 * admin or the schedule, which run WP-CLI in the background).
 */
final class BackupService
{
    public function __construct(
        private readonly string $vaultPath,
        private readonly BackupCrypto $crypto,
        private readonly JobLog $job
    ) {
    }

    /**
     * @return list<string> created file names
     */
    public function backup(string $type, string $label = ''): array
    {
        $created = [];
        $kinds = $type === 'full' ? ['db', 'files'] : [$type];
        $this->checkSpace($kinds);

        if ($type === 'db' || $type === 'full') {
            $this->job->log('Creating the database dump and encrypting it directly ...');
            $name = BackupFile::name('db', $label);
            $start = microtime(true);
            $streamKey = (new DbDumper())->dumpEncrypted($this->vaultPath . DIRECTORY_SEPARATOR . $name, $this->crypto, $this->vaultPath);
            $this->job->addFile($name);
            $created[] = $name;
            $this->job->log(sprintf('Database backed up: %s (%s, %.1f s)', $name, size_format((int) filesize($this->vaultPath . DIRECTORY_SEPARATOR . $name)), microtime(true) - $start));
            $this->verifyCreated($name, $streamKey);
        }
        if ($type === 'files' || $type === 'full') {
            $this->job->log('Packing wp-content and encrypting it directly ...');
            $name = BackupFile::name('files', $label);
            $start = microtime(true);
            $streamKey = (new FilePacker())->packAndEncrypt(WP_CONTENT_DIR, $this->vaultPath . DIRECTORY_SEPARATOR . $name, $this->crypto, Settings::get()['excludes'], $this->vaultPath);
            $this->job->addFile($name);
            $created[] = $name;
            $this->job->log(sprintf('Files backed up: %s (%s, %.1f s)', $name, size_format((int) filesize($this->vaultPath . DIRECTORY_SEPARATOR . $name)), microtime(true) - $start));
            $this->verifyCreated($name, $streamKey);
        }

        // Only after everything succeeded: old backups are never deleted for a failed one
        foreach (Retention::apply($this->vaultPath, $created) as $old) {
            $this->job->log('Retention: old backup deleted: ' . $old);
        }
        return $created;
    }

    /**
     * Stops before the backup when the free space in the vault is clearly too small.
     *
     * @param list<string> $kinds
     */
    private function checkSpace(array $kinds): void
    {
        $needed = 0;
        $free = null;
        foreach ($kinds as $kind) {
            $c = DiskSpace::check($this->vaultPath, $kind);
            $free = $c['free'];
            if ($c['needed'] === null) {
                $this->job->log('Disk space: size of the ' . ($kind === 'db' ? 'database' : 'files') . ' backup could not be estimated, check skipped.');
                continue;
            }
            $needed += $c['needed'];
        }
        if ($free === null) {
            $this->job->log('Disk space: free space in the vault could not be determined, check skipped.');
            return;
        }
        if ($needed > 0 && $free < $needed) {
            throw new RuntimeException(sprintf(
                'Not enough disk space in the vault: %s free, about %s needed. Delete old backups or set up retention.',
                size_format($free),
                size_format($needed)
            ));
        }
        $this->job->log(sprintf('Disk space: %s free%s.', size_format($free), $needed > 0 ? ', about ' . size_format($needed) . ' needed' : ''));
    }

    /**
     * Decrypts a new backup completely once. A file that fails is deleted, so no broken
     * backup is left that looks fine.
     */
    private function verifyCreated(string $name, string $streamKey): void
    {
        $path = $this->vaultPath . DIRECTORY_SEPARATOR . $name;
        $start = microtime(true);
        try {
            // With the stream key of this run: works also with a public key, where the
            // server itself can no longer decrypt the backup later
            $this->crypto->verify($path, $streamKey);
        } catch (\Throwable $e) {
            @unlink($path);
            throw new RuntimeException('Verification of the new backup failed, the file was deleted: ' . $e->getMessage());
        }
        $this->job->log(sprintf('Verified: %s decrypts completely (%.1f s).', $name, microtime(true) - $start));
    }

    public function verify(string $path): void
    {
        $this->job->log('Verifying ' . basename($path) . ' (full decryption) ...');
        $start = microtime(true);
        $this->crypto->verify($path);
        $this->job->log(sprintf('Verification passed: key fits, file is complete and undamaged (%.1f s).', microtime(true) - $start));
    }

    /**
     * Restores a backup file. The file is verified completely first, so a damaged or
     * truncated backup is never half imported.
     */
    public function restore(string $path, bool $safetyBackup): void
    {
        $info = BackupFile::parse(basename($path));
        if ($info === null) {
            throw new RuntimeException('Unknown backup file: ' . basename($path));
        }
        // Format v2 carries the kind in the authenticated header: a renamed file is refused
        $header = BackupCrypto::readHeader($path);
        if (($header['format'] ?? 0) === 2 && ($header['kind'] ?? '') !== $info['kind']) {
            throw new RuntimeException('The file name does not match the content (file says: ' . ($header['kind'] ?? '?') . '). Aborted.');
        }
        if (($header['format'] ?? 0) === 2 && ($header['site'] ?? '') !== BackupCrypto::siteId()) {
            $this->job->log('Note: the backup comes from ' . ($header['site'] ?? '?') . ', this website is ' . BackupCrypto::siteId() . '. URLs are not changed.');
        }

        $this->verify($path);

        if ($safetyBackup) {
            $this->job->log('Safety backup of the current state before restoring ...');
            $this->backup($info['kind'], 'prerestore');
        } else {
            $this->job->log('No safety backup (explicitly disabled).');
        }

        $start = microtime(true);
        if ($info['kind'] === 'db') {
            $this->job->log('Restoring the database ...');
            (new DbRestorer())->restore($path, $this->crypto, $this->vaultPath);
            wp_cache_flush();
            $this->job->log(sprintf('Database restored (%.1f s).', microtime(true) - $start));
        } else {
            $this->job->log('Extracting files into wp-content ...');
            (new FileRestorer())->restore($path, WP_CONTENT_DIR, $this->crypto, $this->vaultPath);
            $this->job->log(sprintf('Files restored (%.1f s). Existing files were overwritten, files that are not in the backup were kept.', microtime(true) - $start));
        }
    }

    /**
     * Takes an uploaded .enc file into the vault. The kind (database or files) comes from the
     * file; a file that belongs to another key is rejected.
     */
    public static function importUpload(string $tmpFile, string $vaultPath, BackupCrypto $crypto): string
    {
        $kind = $crypto->identify($tmpFile);
        $name = BackupFile::name($kind, 'upload');
        $dest = $vaultPath . DIRECTORY_SEPARATOR . $name;
        if (!@move_uploaded_file($tmpFile, $dest) && !@rename($tmpFile, $dest)) {
            throw new RuntimeException('The uploaded file could not be moved into the vault.');
        }
        @chmod($dest, 0600);
        return $name;
    }
}
