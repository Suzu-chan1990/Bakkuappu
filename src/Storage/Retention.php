<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use Bakkuappu\Support\Settings;

/**
 * Deletes old backups according to the retention settings.
 *
 * Groups: database backups, file backups (manual + scheduled), and the automatic
 * "before restore" backups (per kind). Uploaded backups are never deleted automatically.
 * Only called after a successful backup, so the newest good backup always stays.
 */
final class Retention
{
    /**
     * @param list<string> $protect file names that must never be deleted (e.g. just created)
     * @return list<string> deleted file names
     */
    public static function apply(string $vaultPath, array $protect = []): array
    {
        $s = Settings::get();
        $groups = [];
        foreach (BackupFile::all($vaultPath) as $b) {
            if ($b['label'] === 'upload') continue;
            if ($b['label'] === 'prerestore') {
                $groups['prerestore-' . $b['kind']][] = $b;
            } else {
                $groups[$b['kind']][] = $b;
            }
        }

        $limits = [
            'db'               => $s['keep_db'],
            'files'            => $s['keep_files'],
            'prerestore-db'    => $s['keep_prerestore'],
            'prerestore-files' => $s['keep_prerestore'],
        ];

        $deleted = [];
        foreach ($groups as $group => $items) {
            $keep = $limits[$group] ?? 0;
            if ($keep < 1 || count($items) <= $keep) continue;
            // BackupFile::all() is sorted newest first
            foreach (array_slice($items, $keep) as $old) {
                if (in_array($old['name'], $protect, true)) continue;
                if (@unlink($old['path'])) $deleted[] = $old['name'];
            }
        }
        return $deleted;
    }
}
