<?php
declare(strict_types=1);

namespace Bakkuappu\Cli;

use WP_CLI;
use WP_CLI_Command;
use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Crypt\KeyRing;
use Bakkuappu\Crypt\StreamCipher;
use Bakkuappu\Service\BackupService;
use Bakkuappu\Storage\BackupFile;
use Bakkuappu\Storage\VaultManager;
use Bakkuappu\Support\BackupTypes;
use Bakkuappu\Support\JobLog;
use Bakkuappu\Support\Notifier;
use Throwable;

/**
 * Encrypted backups and restores.
 */
class BackupCommand extends WP_CLI_Command
{
    private function ring(): KeyRing
    {
        $ring = KeyRing::get();
        foreach ($ring->problems() as $p) WP_CLI::warning($p);
        return $ring;
    }

    private function requireBackupKey(KeyRing $ring): void
    {
        if (!$ring->canBackup()) {
            WP_CLI::error('No key for backups: BAKKUAPPU_MASTER_KEY or BAKKUAPPU_PUBLIC_KEY is missing (secrets file ' . KeyRing::secretsFile() . ' or wp-config.php).');
        }
    }

    /**
     * Private key for backups made with the public key: --private-key-file, the environment
     * variable BAKKUAPPU_PRIVATE_KEY, or a hidden prompt. Never as a plain argument, because
     * arguments are visible in the process list. Throws, so that inside a job the error is
     * written to the job log (and shown in the admin).
     */
    private function loadPrivateKey(KeyRing $ring, array $assoc, bool $needed): void
    {
        $hex = '';
        $file = (string) ($assoc['private-key-file'] ?? '');
        if ($file !== '') {
            $hex = trim((string) @file_get_contents($file));
            // Temporary key files written by the admin are removed right after reading
            if (preg_match('/^bkp-pk-[0-9a-f]{16}\.tmp$/', basename($file))) @unlink($file);
            if ($hex === '') throw new \RuntimeException('Private key file not readable: ' . $file);
        } elseif (($env = getenv('BAKKUAPPU_PRIVATE_KEY')) !== false && $env !== '') {
            $hex = $env;
        } elseif ($needed && function_exists('posix_isatty') && @posix_isatty(STDIN)) {
            WP_CLI::out('Private key (input is hidden): ');
            @system('stty -echo');
            $hex = trim((string) fgets(STDIN));
            @system('stty echo');
            WP_CLI::line();
        }
        if ($hex === '') {
            if ($needed) throw new \RuntimeException('This backup needs the private key: --private-key-file=<file> or the environment variable BAKKUAPPU_PRIVATE_KEY.');
            return;
        }
        $id = $ring->setPrivateKey($hex);
        WP_CLI::log('Private key loaded (key ID ' . $id . ').');
    }

    private static function isSealed(string $path): bool
    {
        $h = BackupCrypto::readHeader($path);
        return ($h['format'] ?? 0) === 2 && ($h['mode'] ?? '') === 'sealed';
    }

    private function vault(): string
    {
        $vm = new VaultManager();
        try {
            $path = $vm->ensureVaultExists();
        } catch (Throwable $e) {
            WP_CLI::error($e->getMessage());
        }
        if ($vm->isInsideWebRoot($path)) {
            WP_CLI::warning('The vault is inside the web root (' . $path . '). Set BAKKUAPPU_VAULT_PATH to a folder outside the web root.');
        }
        return $path;
    }

    /**
     * Runs $work as a logged job (lock, log file, e-mail).
     */
    private function job(string $kind, string $detail, array $assoc, callable $work, ?KeyRing $ring = null): void
    {
        $vault = $this->vault();
        $ring = $ring ?? $this->ring();
        $trigger = in_array($assoc['trigger'] ?? '', ['admin', 'schedule'], true) ? $assoc['trigger'] : 'cli';

        $log = new JobLog($vault, fn(string $line) => WP_CLI::log($line));
        if (!$log->start($kind, $detail, $trigger)) {
            WP_CLI::error('A Bakkuappu job is already running. Please wait until it has finished.');
        }
        try {
            $service = new BackupService($vault, new BackupCrypto($ring), $log);
            $summary = (string) $work($service, $vault);
            $job = $log->finish(true, $summary);
            Notifier::jobFinished($job);
            WP_CLI::success($summary);
        } catch (Throwable $e) {
            $log->log('FEHLER: ' . $e->getMessage());
            $job = $log->finish(false, $e->getMessage());
            Notifier::jobFinished($job);
            WP_CLI::error($e->getMessage());
        }
    }

    /**
     * Resolves --file: a file name in the vault, or (CLI only) a path to an .enc file.
     */
    private function resolveFile(string $vault, string $file): string
    {
        if ($file === '') WP_CLI::error('Please specify a backup file with --file=<file>.');
        $path = BackupFile::resolve($vault, $file);
        if ($path === null && is_file($file) && BackupFile::parse(basename($file)) !== null) {
            $path = $file;
        }
        if ($path === null) {
            WP_CLI::error('Backup file not found (name from "wp bakkuappu list" or path to a Bakkuappu .enc file): ' . $file);
        }
        return $path;
    }

    /**
     * Creates an encrypted backup.
     *
     * ## OPTIONS
     *
     * [--type=<type>]
     * : full, db or files.
     * ---
     * default: full
     * options:
     *   - full
     *   - db
     *   - files
     * ---
     *
     * [--trigger=<trigger>]
     * : Internal: admin or schedule.
     */
    public function run(array $args, array $assoc_args): void
    {
        $type = (string) ($assoc_args['type'] ?? 'full');
        if (!BackupTypes::isValid($type)) {
            WP_CLI::error('Unknown type "' . $type . '". Allowed: ' . implode(', ', BackupTypes::ALL) . '.');
        }
        $label = ($assoc_args['trigger'] ?? '') === 'schedule' ? 'schedule' : '';
        $this->requireBackupKey($this->ring());
        $this->job('backup', $type, $assoc_args, function (BackupService $s) use ($type, $label) {
            $files = $s->backup($type, $label);
            return 'Backup finished (' . $type . '): ' . implode(', ', $files);
        });
    }

    /**
     * Restores a backup (database or wp-content files, detected from the file name).
     * The file is verified completely before anything is changed.
     *
     * ## OPTIONS
     *
     * --file=<file>
     * : File name from "wp bakkuappu list" or path to an .enc file.
     *
     * [--[no-]safety-backup]
     * : Back up the current state first (default). --no-safety-backup skips it.
     *
     * [--private-key-file=<file>]
     * : File with the private key (only for backups made with the public key).
     *
     * [--yes]
     * : Do not ask for confirmation.
     *
     * [--trigger=<trigger>]
     * : Internal: admin.
     */
    public function restore(array $args, array $assoc_args): void
    {
        $vault = $this->vault();
        $path = $this->resolveFile($vault, (string) ($assoc_args['file'] ?? ''));
        $info = BackupFile::parse(basename($path));
        $safety = (bool) \WP_CLI\Utils\get_flag_value($assoc_args, 'safety-backup', true);
        $ring = $this->ring();
        if ($safety) $this->requireBackupKey($ring);
        $sealed = self::isSealed($path);

        $header = BackupCrypto::readHeader($path);
        $otherSite = ($header['format'] ?? 0) === 2 && ($header['site'] ?? '') !== BackupCrypto::siteId();

        WP_CLI::confirm(sprintf(
            'Really restore %s from %s? The current state will be overwritten%s.%s',
            $info['kind'] === 'db' ? 'the database' : 'the files (wp-content)',
            basename($path),
            $safety ? ' (a safety backup is created first)' : ' (WITHOUT safety backup)',
            $otherSite ? ' WARNING: the backup comes from ' . $header['site'] . ', not from this website.' : ''
        ), $assoc_args);

        $this->job('restore', basename($path), $assoc_args, function (BackupService $s) use ($path, $safety, $ring, $assoc_args, $sealed) {
            $this->loadPrivateKey($ring, $assoc_args, $sealed);
            $s->restore($path, $safety);
            return 'Restore finished: ' . basename($path);
        }, $ring);
    }

    /**
     * Decrypts a backup completely without writing anything (key, completeness, damage).
     *
     * ## OPTIONS
     *
     * --file=<file>
     * : File name from "wp bakkuappu list" or path to an .enc file.
     *
     * [--private-key-file=<file>]
     * : File with the private key (only for backups made with the public key).
     *
     * [--trigger=<trigger>]
     * : Internal: admin.
     */
    public function verify(array $args, array $assoc_args): void
    {
        $vault = $this->vault();
        $path = $this->resolveFile($vault, (string) ($assoc_args['file'] ?? ''));
        $ring = $this->ring();
        $sealed = self::isSealed($path);
        $this->job('verify', basename($path), $assoc_args, function (BackupService $s) use ($path, $ring, $assoc_args, $sealed) {
            $this->loadPrivateKey($ring, $assoc_args, $sealed);
            $s->verify($path);
            return 'Verification passed: ' . basename($path);
        }, $ring);
    }

    /**
     * Lists the backups in the vault.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : table, json, csv
     * ---
     * default: table
     * ---
     */
    public function list(array $args, array $assoc_args): void
    {
        $rows = [];
        foreach (BackupFile::all($this->vault()) as $b) {
            $h = $b['header'] ?? [];
            $rows[] = [
                'name'   => $b['name'],
                'type'   => $b['kind'],
                'date'   => wp_date('Y-m-d H:i:s', $b['time']),
                'label'  => $b['label'] ?: 'manual',
                'size'   => size_format($b['size']),
                'format' => ($h['format'] ?? 0) === 2 ? 'v2 ' . ($h['mode'] === 'sealed' ? 'public-key' : 'symmetric') : 'v1',
                'key_id' => (string) ($h['key_id'] ?? ''),
                'site'   => (string) ($h['site'] ?? ''),
            ];
        }
        \WP_CLI\Utils\format_items($assoc_args['format'] ?? 'table', $rows, ['name', 'type', 'date', 'label', 'size', 'format', 'key_id', 'site']);
    }

    /**
     * Deletes a backup from the vault.
     *
     * ## OPTIONS
     *
     * --file=<file>
     * : File name from "wp bakkuappu list".
     *
     * [--yes]
     * : Do not ask for confirmation.
     */
    public function delete(array $args, array $assoc_args): void
    {
        $vault = $this->vault();
        $path = BackupFile::resolve($vault, (string) ($assoc_args['file'] ?? ''));
        if ($path === null) WP_CLI::error('Backup file not found in the vault.');
        WP_CLI::confirm('Really delete backup ' . basename($path) . '?', $assoc_args);
        if (!@unlink($path)) WP_CLI::error('File could not be deleted.');
        WP_CLI::success('Deleted: ' . basename($path));
    }

    /**
     * Decrypts a backup file.
     *
     * ## OPTIONS
     *
     * --file=<file>
     * : Encrypted backup (.enc).
     *
     * --out=<out>
     * : Output file (must not exist yet). Database: SQL, files: tar archive.
     *
     * [--private-key-file=<file>]
     * : File with the private key (only for backups made with the public key).
     */
    public function decrypt(array $args, array $assoc_args): void
    {
        $file = (string) ($assoc_args['file'] ?? '');
        $out = (string) ($assoc_args['out'] ?? '');

        if ($file === '' || !is_file($file)) WP_CLI::error('Source file not found.');
        if ($out === '') WP_CLI::error('Please specify an output file with --out=<file>.');
        if (file_exists($out)) WP_CLI::error('The output file already exists: ' . $out);
        $ring = $this->ring();

        WP_CLI::log('Starting decryption stream ...');
        try {
            $this->loadPrivateKey($ring, $assoc_args, self::isSealed($file));
            (new BackupCrypto($ring))->decryptToFile($file, $out);
            WP_CLI::success('File decrypted and fully verified: ' . $out);
        } catch (Throwable $e) {
            WP_CLI::error('Decryption error: ' . $e->getMessage());
        }
    }

    /**
     * Creates a new symmetric master key.
     */
    public function generate_key(): void
    {
        $key = StreamCipher::generateKey();
        WP_CLI::success('New cryptographic master key generated (key ID ' . KeyRing::id(sodium_hex2bin($key)) . ').');
        WP_CLI::log('Secrets file:  \'BAKKUAPPU_MASTER_KEY\' => \'' . $key . '\',');
        WP_CLI::log('When changing keys, move the previous key to BAKKUAPPU_OLD_KEYS, otherwise older backups can no longer be read.');
    }

    /**
     * Creates a key pair. The public key goes to the server, the private key stays with you.
     */
    public function generate_keypair(): void
    {
        [$secret, $public] = KeyRing::generateKeypair();
        WP_CLI::success('New key pair generated (key ID ' . KeyRing::id(sodium_hex2bin($public), true) . ').');
        WP_CLI::log('');
        WP_CLI::log('PUBLIC key - into the secrets file on the server:');
        WP_CLI::log('  \'BAKKUAPPU_PUBLIC_KEY\' => \'' . $public . '\',');
        WP_CLI::log('');
        WP_CLI::log('PRIVATE key - do NOT store it on the server (e.g. password manager):');
        WP_CLI::log('  ' . $secret);
        WP_CLI::log('');
        WP_CLI::log('Without the private key, the new backups cannot be restored.');
    }

    /**
     * Shows which keys are configured.
     */
    public function keys(): void
    {
        $ring = $this->ring();
        $src = fn(string $n) => $ring->source($n) === 'file' ? 'secrets file' : ($ring->source($n) === 'wp-config' ? 'wp-config.php' : '-');
        $rows = [];
        if ($ring->master()) $rows[] = ['key' => 'BAKKUAPPU_MASTER_KEY', 'key_id' => KeyRing::id($ring->master()), 'source' => $src('BAKKUAPPU_MASTER_KEY')];
        foreach ($ring->oldKeys() as $k) $rows[] = ['key' => 'BAKKUAPPU_OLD_KEYS', 'key_id' => KeyRing::id($k), 'source' => $src('BAKKUAPPU_OLD_KEYS')];
        if ($ring->publicKey()) $rows[] = ['key' => 'BAKKUAPPU_PUBLIC_KEY', 'key_id' => KeyRing::id($ring->publicKey(), true), 'source' => $src('BAKKUAPPU_PUBLIC_KEY')];
        \WP_CLI\Utils\format_items('table', $rows, ['key', 'key_id', 'source']);
        WP_CLI::log('New backups: ' . ($ring->mode() === 'sealed' ? 'public key (readable only with the private key)' : 'master key'));
        WP_CLI::log('Secrets file: ' . KeyRing::secretsFile() . (is_file(KeyRing::secretsFile()) ? ' (found)' : ' (not found)'));
    }
}
