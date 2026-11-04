<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use Bakkuappu\Support\Process;

/**
 * Free space check before a backup, so the disk does not run full in the middle of a dump.
 */
final class DiskSpace
{
    // Safety margin on top of the estimate
    private const int MARGIN = 100 * 1024 * 1024;

    public static function free(string $path): ?int
    {
        $free = @disk_free_space($path);
        return $free === false ? null : (int) $free;
    }

    /**
     * Estimated size of the next backup of $kind: the last backup of that kind plus 20 %,
     * otherwise the database size or the size of wp-content.
     */
    public static function estimate(string $vaultPath, string $kind): ?int
    {
        foreach (BackupFile::all($vaultPath) as $b) {
            if ($b['kind'] === $kind) return (int) ($b['size'] * 1.2);
        }
        if ($kind === 'db') {
            global $wpdb;
            $size = $wpdb->get_var($wpdb->prepare(
                'SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = %s',
                DB_NAME
            ));
            return $size !== null ? (int) $size : null;
        }
        // wp-content without the vault; du is fast compared with the backup itself
        if (!function_exists('exec') || Process::which('du') === null) return null;
        $out = [];
        $code = 1;
        @exec('du -sk ' . escapeshellarg(WP_CONTENT_DIR) . ' 2>/dev/null', $out, $code);
        if ($code !== 0 || !preg_match('/^(\d+)/', (string) ($out[0] ?? ''), $m)) return null;
        return (int) $m[1] * 1024;
    }

    /**
     * @return array{ok:bool,free:?int,needed:?int}
     */
    public static function check(string $vaultPath, string $kind): array
    {
        $free = self::free($vaultPath);
        $estimate = self::estimate($vaultPath, $kind);
        if ($free === null || $estimate === null) {
            return ['ok' => true, 'free' => $free, 'needed' => null];
        }
        $needed = $estimate + self::MARGIN;
        return ['ok' => $free >= $needed, 'free' => $free, 'needed' => $needed];
    }
}
