<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

/**
 * E-mail after a job, depending on the settings (never / only errors / always).
 */
final class Notifier
{
    public static function jobFinished(array $job): void
    {
        $settings = Settings::get();
        $failed = ($job['status'] ?? '') !== 'done';
        if ($settings['email'] === 'never' || ($settings['email'] === 'error' && !$failed)) return;

        $to = $settings['email_to'] !== '' ? $settings['email_to'] : (string) get_option('admin_email');
        if (!is_email($to)) return;

        $kinds = ['backup' => 'Backup', 'restore' => 'Restore', 'verify' => 'Verification'];
        $what = ($kinds[$job['kind'] ?? ''] ?? 'Job') . ' (' . ($job['detail'] ?? '') . ')';
        $site = wp_parse_url(home_url(), PHP_URL_HOST) ?: home_url();
        $subject = sprintf('[Bakkuappu] %s %s: %s', $what, $failed ? 'FAILED' : 'successful', $site);

        $lines = [];
        foreach ((array) ($job['log'] ?? []) as $entry) {
            $lines[] = wp_date('Y-m-d H:i:s', (int) ($entry['t'] ?? 0)) . '  ' . ($entry['m'] ?? '');
        }
        $body = $what . ' on ' . $site . ': ' . ($failed ? 'FAILED' : 'successful') . "\n"
            . ($job['summary'] ?? '') . "\n\n"
            . "Log:\n" . implode("\n", $lines) . "\n\n"
            . admin_url('admin.php?page=bakkuappu&tab=log') . "\n";

        wp_mail($to, $subject, $body);
    }
}
