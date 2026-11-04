<?php
/**
 * Plugin Name: Bakkuappu
 * Description: High-performance, modular backup and restore system with XChaCha20-Poly1305 stream encryption (libsodium).
 * Version: 2.0.2
 * Author: Saguya
 * Requires PHP: 8.4
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('BAKKUAPPU_VERSION', '2.0.2');
define('BAKKUAPPU_FILE', __FILE__);

// Simple native autoloader for the src/ structure
spl_autoload_register(function (string $class) {
    $prefix = 'Bakkuappu\\';
    $base_dir = __DIR__ . '/src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

// Register the WP-CLI commands only when WP-CLI is running
if (defined('WP_CLI') && WP_CLI) {
    WP_CLI::add_command('bakkuappu', \Bakkuappu\Cli\BackupCommand::class);
}

// Scheduled backups (WP-Cron starts WP-CLI in the background)
\Bakkuappu\Cron\Scheduler::init();
register_deactivation_hook(__FILE__, [\Bakkuappu\Cron\Scheduler::class, 'unschedule']);

// Initialize the admin UI
if (is_admin()) {
    \Bakkuappu\Admin\AdminUI::init();
}

add_action('init', function () {
    if ( ! is_admin() ) {
        return;
    }

    $puc_path = Bakkuappu_PATH . 'lib/plugin-update-checker/plugin-update-checker.php';
    if ( ! file_exists($puc_path) ) {
        return; 
    }

    require_once $puc_path;

    // Build checker
    $updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/Suzu-chan1990/Bakkuappu',
        __FILE__,
        'bakkuappu'
    );

    $updateChecker->getVcsApi()->enableReleaseAssets();
});
