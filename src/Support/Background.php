<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

/**
 * Starts a WP-CLI command in the background as the PHP user (admin buttons, schedule).
 */
final class Background
{
    public static function wpCli(): ?string
    {
        if (defined('BAKKUAPPU_WP_CLI') && is_string(BAKKUAPPU_WP_CLI) && BAKKUAPPU_WP_CLI !== '') return BAKKUAPPU_WP_CLI;
        if (defined('WP_CLI_PATH') && is_string(WP_CLI_PATH) && WP_CLI_PATH !== '') return WP_CLI_PATH;
        return Process::which('wp');
    }

    /**
     * @param list<string> $args Arguments after "wp bakkuappu"
     * @return array{0:bool,1:string} [started, message]
     */
    public static function start(array $args): array
    {
        if (!function_exists('exec')) {
            return [false, 'exec() is disabled on this server. Run the command with WP-CLI: wp bakkuappu ' . implode(' ', $args)];
        }
        $wp = self::wpCli();
        if ($wp === null) {
            return [false, 'WP-CLI (wp) was not found for the PHP user. Set the path in wp-config.php: define(\'BAKKUAPPU_WP_CLI\', \'/usr/local/bin/wp\');'];
        }

        $cmd = escapeshellarg($wp) . ' --path=' . escapeshellarg(ABSPATH) . ' bakkuappu';
        foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);

        $output = [];
        $code = 0;
        exec('nohup ' . $cmd . ' > /dev/null 2>&1 &', $output, $code);
        if ($code !== 0) {
            return [false, 'The background process could not be started (code ' . $code . ').'];
        }
        return [true, 'Started.'];
    }
}
