<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

use RuntimeException;

/**
 * Job state and log, stored as files in the vault ("jobs/").
 *
 * Not in the database on purpose: a database restore replaces wp_options and would wipe the
 * log of the running restore, or bring back a stale "running" state from the backup.
 * The lock is an flock() on a file: it is released automatically when the process ends,
 * even after a crash.
 */
final class JobLog
{
    private const int KEEP = 30;

    /** @var resource|null */
    private $lockHandle = null;
    private string $dir;
    private array $job = [];
    /** @var callable|null */
    private $echo;

    public function __construct(string $vaultPath, ?callable $echo = null)
    {
        $this->dir = $vaultPath . DIRECTORY_SEPARATOR . 'jobs';
        $this->echo = $echo;
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0750, true) && !is_dir($this->dir)) {
            throw new RuntimeException('Job directory could not be created: ' . $this->dir);
        }
    }

    public static function dirFor(string $vaultPath): string
    {
        return $vaultPath . DIRECTORY_SEPARATOR . 'jobs';
    }

    /**
     * True while another process holds the job lock.
     */
    public static function isRunning(string $vaultPath): bool
    {
        $file = self::dirFor($vaultPath) . DIRECTORY_SEPARATOR . 'job.lock';
        if (!is_file($file)) return false;
        $h = @fopen($file, 'c');
        if (!$h) return false;
        $free = flock($h, LOCK_EX | LOCK_NB);
        if ($free) flock($h, LOCK_UN);
        fclose($h);
        return !$free;
    }

    /**
     * Takes the lock and starts a job. Returns false when another job is running.
     */
    public function start(string $kind, string $detail, string $trigger): bool
    {
        $h = fopen($this->dir . DIRECTORY_SEPARATOR . 'job.lock', 'c');
        if (!$h || !flock($h, LOCK_EX | LOCK_NB)) {
            if ($h) fclose($h);
            return false;
        }
        $this->lockHandle = $h;
        $this->job = [
            'id'       => gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3)),
            'kind'     => $kind,      // backup | restore | verify
            'detail'   => $detail,    // type or file name
            'trigger'  => $trigger,   // manual | admin | schedule | cli
            'status'   => 'running',
            'started'  => time(),
            'finished' => 0,
            'pid'      => getmypid(),
            'log'      => [],
            'files'    => [],
        ];
        $this->write();
        return true;
    }

    public function log(string $line): void
    {
        $this->job['log'][] = ['t' => time(), 'm' => $line];
        if ($this->echo) ($this->echo)($line);
        $this->write();
    }

    public function addFile(string $basename): void
    {
        $this->job['files'][] = $basename;
        $this->write();
    }

    public function finish(bool $ok, string $summary): array
    {
        $this->job['status'] = $ok ? 'done' : 'error';
        $this->job['finished'] = time();
        $this->job['summary'] = $summary;
        $this->write();
        $this->prune();
        if ($this->lockHandle) {
            flock($this->lockHandle, LOCK_UN);
            fclose($this->lockHandle);
            $this->lockHandle = null;
        }
        return $this->job;
    }

    public function current(): array
    {
        return $this->job;
    }

    private function write(): void
    {
        $json = (string) wp_json_encode($this->job, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $file = $this->dir . DIRECTORY_SEPARATOR . 'job-' . $this->job['id'] . '.json';
        @file_put_contents($file . '.tmp', $json, LOCK_EX);
        @rename($file . '.tmp', $file);
        @file_put_contents($this->dir . DIRECTORY_SEPARATOR . 'latest.txt', $this->job['id'], LOCK_EX);
    }

    private function prune(): void
    {
        $files = glob($this->dir . DIRECTORY_SEPARATOR . 'job-*.json') ?: [];
        rsort($files);
        foreach (array_slice($files, self::KEEP) as $old) @unlink($old);
    }

    /**
     * Latest jobs, newest first.
     *
     * @return list<array>
     */
    public static function history(string $vaultPath, int $limit = self::KEEP): array
    {
        $files = glob(self::dirFor($vaultPath) . DIRECTORY_SEPARATOR . 'job-*.json') ?: [];
        rsort($files);
        $out = [];
        foreach (array_slice($files, 0, $limit) as $f) {
            $job = json_decode((string) @file_get_contents($f), true);
            if (is_array($job)) $out[] = self::withLiveStatus($vaultPath, $job);
        }
        return $out;
    }

    public static function latest(string $vaultPath): ?array
    {
        $id = trim((string) @file_get_contents(self::dirFor($vaultPath) . DIRECTORY_SEPARATOR . 'latest.txt'));
        if (!preg_match('/^[0-9A-Za-z-]+$/', $id)) return null;
        $job = json_decode((string) @file_get_contents(self::dirFor($vaultPath) . DIRECTORY_SEPARATOR . 'job-' . $id . '.json'), true);
        return is_array($job) ? self::withLiveStatus($vaultPath, $job) : null;
    }

    /**
     * A job still marked "running" whose process no longer holds the lock was aborted
     * (crash, killed, server restart).
     */
    private static function withLiveStatus(string $vaultPath, array $job): array
    {
        if (($job['status'] ?? '') === 'running' && !self::isRunning($vaultPath)) {
            $job['status'] = 'aborted';
        }
        return $job;
    }
}
