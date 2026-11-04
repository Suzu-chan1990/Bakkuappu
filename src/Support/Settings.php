<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

/**
 * Plugin settings (one option, validated on save).
 */
final class Settings
{
    public const string OPTION = 'bakkuappu_settings';

    public const array DEFAULT_EXCLUDES = [
        './cache',
        './updraft',
        './bakkuappu_vault',
        '*.log',
        '*.part',
        '.DS_Store',
    ];

    /**
     * @return array{schedule:string,schedule_type:string,schedule_day:int,schedule_time:string,excludes:list<string>,email:string,email_to:string,keep_db:int,keep_files:int,keep_prerestore:int}
     */
    public static function defaults(): array
    {
        return [
            'schedule'      => 'off',     // off | daily | weekly
            'schedule_type' => 'full',    // full | db | files
            'schedule_day'  => 1,         // 0 = Sunday ... 6 = Saturday (weekly)
            'schedule_time' => '03:30',   // site time HH:MM
            'excludes'      => self::DEFAULT_EXCLUDES,
            'email'         => 'error',   // never | error | always
            'email_to'      => '',        // empty = site admin e-mail
            // Retention: number of backups kept per kind, 0 = keep all. Uploads are never deleted.
            'keep_db'         => 0,
            'keep_files'      => 0,
            'keep_prerestore' => 0,
        ];
    }

    public static function get(): array
    {
        $stored = get_option(self::OPTION, []);
        return self::sanitize(is_array($stored) ? $stored + self::defaults() : self::defaults());
    }

    public static function sanitize(array $in): array
    {
        $d = self::defaults();
        $out = [];
        $out['schedule'] = in_array($in['schedule'] ?? '', ['off', 'daily', 'weekly'], true) ? $in['schedule'] : $d['schedule'];
        $out['schedule_type'] = BackupTypes::isValid((string) ($in['schedule_type'] ?? '')) ? (string) $in['schedule_type'] : $d['schedule_type'];
        $day = (int) ($in['schedule_day'] ?? $d['schedule_day']);
        $out['schedule_day'] = ($day >= 0 && $day <= 6) ? $day : $d['schedule_day'];
        $time = (string) ($in['schedule_time'] ?? '');
        $out['schedule_time'] = preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $time) ? $time : $d['schedule_time'];

        $ex = $in['excludes'] ?? $d['excludes'];
        if (is_string($ex)) $ex = preg_split('/\R/', $ex);
        $clean = [];
        foreach ((array) $ex as $line) {
            // tar --exclude patterns: printable characters only, no option injection
            $line = trim(preg_replace('/[\x00-\x1F\x7F]/', '', (string) $line));
            if ($line === '' || str_starts_with($line, '-') || strlen($line) > 200) continue;
            $clean[] = $line;
        }
        // The vault and unfinished files must never end up in the archive
        foreach (['./bakkuappu_vault', '*.part'] as $must) {
            if (!in_array($must, $clean, true)) $clean[] = $must;
        }
        $out['excludes'] = array_values(array_unique($clean));

        $out['email'] = in_array($in['email'] ?? '', ['never', 'error', 'always'], true) ? $in['email'] : $d['email'];
        $to = sanitize_email((string) ($in['email_to'] ?? ''));
        $out['email_to'] = is_email($to) ? $to : '';
        foreach (['keep_db', 'keep_files', 'keep_prerestore'] as $k) {
            $out[$k] = max(0, min(999, (int) ($in[$k] ?? $d[$k])));
        }
        return $out;
    }

    public static function save(array $values): array
    {
        $clean = self::sanitize($values);
        update_option(self::OPTION, $clean, false);
        return $clean;
    }
}
