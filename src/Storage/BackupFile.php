<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use Bakkuappu\Crypt\BackupCrypto;

/**
 * Backup files in the vault.
 *
 * Name: "<kind>_<YYYY-MM-DD_HH-MM-SS>[_<label>]_<random>.enc"
 *   kind  = db | files
 *   label = schedule | prerestore | upload (no label = started manually)
 * Names of Bakkuappu 1.0/1.1 ("db_<time>_<random>.enc") are recognized as well.
 */
final class BackupFile
{
    public const array LABELS = ['schedule', 'prerestore', 'upload'];

    public static function name(string $kind, string $label = ''): string
    {
        $label = in_array($label, self::LABELS, true) ? '_' . $label : '';
        return $kind . '_' . gmdate('Y-m-d_H-i-s') . $label . '_' . bin2hex(random_bytes(8)) . '.enc';
    }

    /**
     * @return array{kind:string,time:int,label:string}|null
     */
    public static function parse(string $basename): ?array
    {
        if (!preg_match('/^(db|files)_(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})(?:_(schedule|prerestore|upload))?(?:_[0-9a-f]{8,32})?\.enc$/', $basename, $m)) {
            return null;
        }
        $time = strtotime($m[2] . ' ' . $m[3] . ':' . $m[4] . ':' . $m[5] . ' UTC');
        return ['kind' => $m[1], 'time' => $time ?: 0, 'label' => $m[6] ?? ''];
    }

    /**
     * Only plain file names of existing backups in the vault are accepted (no paths).
     */
    public static function resolve(string $vaultPath, string $basename): ?string
    {
        if ($basename !== basename($basename) || self::parse($basename) === null) return null;
        $path = $vaultPath . DIRECTORY_SEPARATOR . $basename;
        return is_file($path) ? $path : null;
    }

    /**
     * @return list<array{name:string,path:string,kind:string,time:int,label:string,size:int,header:?array}>
     */
    public static function all(string $vaultPath): array
    {
        $out = [];
        foreach (glob($vaultPath . DIRECTORY_SEPARATOR . '*.enc') ?: [] as $path) {
            $name = basename($path);
            $info = self::parse($name);
            if ($info === null) continue;
            $out[] = ['name' => $name, 'path' => $path, 'size' => (int) filesize($path), 'header' => BackupCrypto::readHeader($path)] + $info;
        }
        usort($out, fn($a, $b) => $b['time'] <=> $a['time'] ?: strcmp($b['name'], $a['name']));
        return $out;
    }
}
