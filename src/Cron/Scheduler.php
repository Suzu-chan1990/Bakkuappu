<?php
declare(strict_types=1);

namespace Bakkuappu\Cron;

use Bakkuappu\Storage\VaultManager;
use Bakkuappu\Support\Background;
use Bakkuappu\Support\JobLog;
use Bakkuappu\Support\Notifier;
use Bakkuappu\Support\Settings;

/**
 * Scheduled backups via WP-Cron. The cron request only starts WP-CLI in the background,
 * the backup itself does not run inside a web request.
 */
final class Scheduler
{
    public const string HOOK = 'bakkuappu_scheduled_backup';

    public static function init(): void
    {
        add_action(self::HOOK, [self::class, 'runScheduled']);
        // Repair a missing event (e.g. after a database restore or a manual cron cleanup)
        add_action('init', static function (): void {
            $s = Settings::get();
            if ($s['schedule'] !== 'off' && !wp_next_scheduled(self::HOOK)) {
                self::reschedule();
            }
        });
    }

    /**
     * Next run in site time, as a UTC timestamp, or null when the schedule is off.
     */
    public static function nextRun(?array $settings = null, ?int $now = null): ?int
    {
        $s = $settings ?? Settings::get();
        if ($s['schedule'] === 'off') return null;
        $tz = wp_timezone();
        $now = $now ?? time();
        [$h, $m] = array_map('intval', explode(':', $s['schedule_time']));
        $candidate = (new \DateTimeImmutable('@' . $now))->setTimezone($tz)->setTime($h, $m);
        if ($s['schedule'] === 'weekly') {
            $diff = ($s['schedule_day'] - (int) $candidate->format('w') + 7) % 7;
            $candidate = $candidate->modify('+' . $diff . ' days');
            if ($candidate->getTimestamp() <= $now) $candidate = $candidate->modify('+7 days');
        } elseif ($candidate->getTimestamp() <= $now) {
            $candidate = $candidate->modify('+1 day');
        }
        return $candidate->getTimestamp();
    }

    public static function reschedule(): void
    {
        wp_clear_scheduled_hook(self::HOOK);
        $next = self::nextRun();
        if ($next !== null) {
            wp_schedule_single_event($next, self::HOOK);
        }
    }

    public static function unschedule(): void
    {
        wp_clear_scheduled_hook(self::HOOK);
    }

    public static function runScheduled(): void
    {
        $s = Settings::get();
        self::reschedule(); // next run first, so a failure does not stop the schedule
        if ($s['schedule'] === 'off') return;

        [$ok, $message] = Background::start(['run', '--type=' . $s['schedule_type'], '--trigger=schedule']);
        if ($ok) return;

        // Could not start WP-CLI: record it like a failed job and notify
        try {
            $vault = (new VaultManager())->ensureVaultExists();
            $log = new JobLog($vault);
            if ($log->start('backup', $s['schedule_type'], 'schedule')) {
                $log->log('ERROR: the scheduled backup could not be started. ' . $message);
                Notifier::jobFinished($log->finish(false, $message));
            }
        } catch (\Throwable $e) {
            // Nothing else to report to
        }
    }
}
