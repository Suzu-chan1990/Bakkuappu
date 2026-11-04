<?php
declare(strict_types=1);

namespace Bakkuappu\Admin;

use Bakkuappu\Cron\Scheduler;
use Bakkuappu\Crypt\BackupCrypto;
use Bakkuappu\Crypt\KeyRing;
use Bakkuappu\Service\BackupService;
use Bakkuappu\Storage\BackupFile;
use Bakkuappu\Storage\DiskSpace;
use Bakkuappu\Storage\VaultManager;
use Bakkuappu\Support\Background;
use Bakkuappu\Support\BackupTypes;
use Bakkuappu\Support\JobLog;
use Bakkuappu\Support\Settings;

/**
 * Admin interface (Tegatai look): overview, backups, settings, log.
 * Long jobs never run inside a web request: the buttons start WP-CLI in the background.
 */
final class AdminUI
{
    private const string SLUG = 'bakkuappu';

    public static function init(): void
    {
        add_action('admin_menu', [self::class, 'registerMenu']);
        add_action('admin_enqueue_scripts', [self::class, 'enqueue']);
        add_action('admin_head', [self::class, 'menuIconStyle']);
        add_action('wp_ajax_bakkuappu_start', [self::class, 'ajaxStart']);
        add_action('wp_ajax_bakkuappu_status', [self::class, 'ajaxStatus']);
        add_action('admin_post_bakkuappu_download', [self::class, 'handleDownload']);
        add_action('admin_post_bakkuappu_delete', [self::class, 'handleDelete']);
        add_action('admin_post_bakkuappu_upload', [self::class, 'handleUpload']);
        add_action('admin_post_bakkuappu_save_settings', [self::class, 'handleSaveSettings']);
        add_action('admin_init', [self::class, 'detectOversizedUpload']);
    }

    /**
     * A request larger than post_max_size arrives with empty $_POST and $_FILES, so WordPress
     * would show a blank page. The upload form marks its URL to recognize that case.
     */
    public static function detectOversizedUpload(): void
    {
        if (!isset($_GET['bkp_upload']) || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !empty($_POST) || !empty($_FILES)) return; // phpcs:ignore WordPress.Security.NonceVerification -- only detects a dropped request
        if (!current_user_can('manage_options')) return;
        $limit = size_format(wp_convert_hr_to_bytes((string) ini_get('post_max_size')));
        wp_safe_redirect(self::url('backups', ['bkp_msg' => 'upload_fail', 'bkp_detail' => 'The file is larger than the PHP limit (post_max_size ' . $limit . '). Put larger backups into the vault via SFTP.']));
        exit;
    }

    public static function registerMenu(): void
    {
        add_menu_page('Bakkuappu', 'Bakkuappu', 'manage_options', self::SLUG, [self::class, 'render'], plugin_dir_url(BAKKUAPPU_FILE) . 'assets/menu-icon.png', 80);
    }

    /**
     * Sizes the colored menu icon. WordPress styles image menu icons for 16 px and dims
     * them, so this small rule runs on every admin page where the menu is shown.
     */
    public static function menuIconStyle(): void
    {
        if (!current_user_can('manage_options')) return;
        echo '<style>#adminmenu .toplevel_page_' . esc_attr(self::SLUG) . ' .wp-menu-image img{width:20px;height:20px;padding:7px 0 0;opacity:1}</style>';
    }

    public static function enqueue(string $hook): void
    {
        if ($hook !== 'toplevel_page_' . self::SLUG) return;
        $base = plugin_dir_url(BAKKUAPPU_FILE) . 'assets/';
        $dir = plugin_dir_path(BAKKUAPPU_FILE) . 'assets/';
        wp_enqueue_style('bakkuappu-admin', $base . 'admin.css', [], (string) @filemtime($dir . 'admin.css'));
        wp_enqueue_script('bakkuappu-admin', $base . 'admin.js', [], (string) @filemtime($dir . 'admin.js'), true);
        wp_localize_script('bakkuappu-admin', 'BakkuappuAdmin', [
            'ajax'  => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('bakkuappu_admin'),
        ]);
    }

    /** A key for new backups exists (master key or public key). */
    private static function hasKey(): bool
    {
        return KeyRing::get()->canBackup();
    }

    private static function url(string $tab, array $args = []): string
    {
        return add_query_arg(array_merge(['page' => self::SLUG, 'tab' => $tab], $args), admin_url('admin.php'));
    }

    private static function check(string $nonceField = '_wpnonce'): void
    {
        if (!current_user_can('manage_options')) wp_die('Access denied.', 403);
        check_admin_referer('bakkuappu_admin', $nonceField);
    }

    // ---------------------------------------------------------------------------------
    // Page
    // ---------------------------------------------------------------------------------

    public static function render(): void
    {
        if (!current_user_can('manage_options')) return;
        $tabs = ['overview' => 'Overview', 'backups' => 'Backups', 'keys' => 'Keys', 'settings' => 'Settings', 'log' => 'Log'];
        $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only
        if (!isset($tabs[$tab])) $tab = 'overview';

        $vm = new VaultManager();
        $vault = $vm->getVaultPath();

        echo '<div class="bkp-wrap">';
        echo '<div class="bkp-header"><div class="bkp-title"><img class="bkp-logo" src="' . esc_url(plugin_dir_url(BAKKUAPPU_FILE) . 'assets/logo.png') . '" width="64" height="64" alt=""> Bakkuappu <span class="bkp-badge">v' . esc_html(BAKKUAPPU_VERSION) . '</span></div>';
        echo '<div class="bkp-header-sub">Encrypted backups · XChaCha20-Poly1305</div></div>';

        self::renderNotice();

        echo '<nav class="bkp-nav">';
        foreach ($tabs as $id => $label) {
            echo '<a class="bkp-tab' . ($id === $tab ? ' active' : '') . '" href="' . esc_url(self::url($id)) . '">' . esc_html($label) . '</a>';
        }
        echo '</nav>';

        if (!self::hasKey()) {
            echo '<div class="bkp-alert bkp-alert-danger"><strong>No key:</strong> neither <code>BAKKUAPPU_MASTER_KEY</code> nor <code>BAKKUAPPU_PUBLIC_KEY</code> is set up. '
                . 'Backups are blocked without a key. Instructions in the <a href="' . esc_url(self::url('keys')) . '">Keys</a> tab.</div>';
        }
        foreach (KeyRing::get()->problems() as $problem) {
            echo '<div class="bkp-alert bkp-alert-danger">' . esc_html($problem) . '</div>';
        }
        if ($vm->isInsideWebRoot($vault)) {
            echo '<div class="bkp-alert bkp-alert-warn">The vault is inside the web root (<code>' . esc_html($vault) . '</code>). Set <code>BAKKUAPPU_VAULT_PATH</code> in wp-config.php to a folder outside the web root.</div>';
        }

        match ($tab) {
            'backups'  => self::tabBackups($vault),
            'settings' => self::tabSettings(),
            'log'      => self::tabLog($vault),
            'keys'     => self::tabKeys(),
            default    => self::tabOverview($vault),
        };
        echo '</div>';
    }

    private static function renderNotice(): void
    {
        $msg = isset($_GET['bkp_msg']) ? sanitize_key(wp_unslash($_GET['bkp_msg'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $detail = isset($_GET['bkp_detail']) ? sanitize_text_field(wp_unslash($_GET['bkp_detail'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $map = [
            'saved'       => ['ok', 'Settings saved.'],
            'deleted'     => ['ok', 'Backup deleted.'],
            'uploaded'    => ['ok', 'Backup uploaded, key recognized: '],
            'upload_fail' => ['danger', 'Upload failed: '],
            'delete_fail' => ['danger', 'Deleting failed.'],
            'busy'        => ['warn', 'A job is running right now. Please wait until it has finished.'],
        ];
        if (!isset($map[$msg])) return;
        [$kind, $text] = $map[$msg];
        echo '<div class="bkp-alert bkp-alert-' . esc_attr($kind) . '">' . esc_html($text . $detail) . '</div>';
    }

    private static function jobConsole(): void
    {
        echo '<div class="bkp-card bkp-span"><h3>Current job</h3>';
        echo '<div class="bkp-job-head"><span class="bkp-pill" id="bkp-job-status">–</span> <span id="bkp-job-title" class="bkp-muted">Loading status …</span></div>';
        echo '<pre class="bkp-console" id="bkp-console">&gt; Waiting for status …</pre></div>';
    }

    private static function tabOverview(string $vault): void
    {
        $backups = BackupFile::all($vault);
        $lastDb = $lastFiles = null;
        foreach ($backups as $b) {
            if ($b['kind'] === 'db' && !$lastDb) $lastDb = $b;
            if ($b['kind'] === 'files' && !$lastFiles) $lastFiles = $b;
        }
        $next = wp_next_scheduled(Scheduler::HOOK);
        $settings = Settings::get();
        $total = array_sum(array_column($backups, 'size'));
        $wp = Background::wpCli();

        echo '<div class="bkp-grid">';

        echo '<div class="bkp-card"><h3>Start backup</h3>';
        echo '<p class="bkp-desc">Runs in the background via WP-CLI. Progress below under "Current job".</p>';
        echo '<div class="bkp-actions">';
        foreach (['full' => 'Full backup', 'db' => 'Database only', 'files' => 'Files only'] as $type => $label) {
            echo '<button type="button" class="button ' . ($type === 'full' ? 'button-primary' : 'button-secondary') . ' bkp-start" data-kind="backup" data-type="' . esc_attr($type) . '"' . (self::hasKey() ? '' : ' disabled') . '>' . esc_html($label) . '</button>';
        }
        echo '</div></div>';

        echo '<div class="bkp-card"><h3>Status</h3><div class="bkp-kv">';
        $ring = KeyRing::get();
        if ($ring->mode() === 'sealed') {
            self::kv('Encryption', '<span class="bkp-ok">public key</span>');
            self::kv('Key ID', esc_html(KeyRing::id((string) $ring->publicKey(), true)));
        } elseif ($ring->master() !== null) {
            self::kv('Encryption', '<span class="bkp-ok">master key</span>');
            self::kv('Key ID', esc_html(KeyRing::id($ring->master())));
        } else {
            self::kv('Encryption', '<span class="bkp-bad">no key</span>');
        }
        self::kv('WP-CLI', $wp ? '<span class="bkp-ok">found</span>' : '<span class="bkp-bad">not found</span>');
        self::kv('Last database backup', $lastDb ? esc_html(wp_date('Y-m-d H:i', $lastDb['time'])) : '–');
        self::kv('Last files backup', $lastFiles ? esc_html(wp_date('Y-m-d H:i', $lastFiles['time'])) : '–');
        self::kv('Backups in the vault', esc_html(count($backups) . ' · ' . size_format($total)));
        $free = is_dir($vault) ? DiskSpace::free($vault) : null;
        self::kv('Free space (vault)', $free !== null ? esc_html(size_format($free)) : '–');
        $keep = [];
        if ($settings['keep_db'] > 0) $keep[] = $settings['keep_db'] . ' database';
        if ($settings['keep_files'] > 0) $keep[] = $settings['keep_files'] . ' files';
        self::kv('Retention', $keep ? esc_html('last ' . implode(' / ', $keep)) : 'keep all');
        self::kv('Next scheduled backup', $next ? esc_html(wp_date('Y-m-d H:i', $next) . ' (' . $settings['schedule_type'] . ')') : 'schedule off');
        echo '</div><p class="bkp-mini">Vault: <code>' . esc_html($vault) . '</code></p></div>';

        self::jobConsole();
        echo '</div>';
    }

    private static function kv(string $k, string $vHtml): void
    {
        echo '<div class="k">' . esc_html($k) . '</div><div class="v">' . wp_kses($vHtml, ['span' => ['class' => true]]) . '</div>';
    }

    private static function tabBackups(string $vault): void
    {
        $backups = BackupFile::all($vault);
        $labels = ['' => 'Manual', 'schedule' => 'Schedule', 'prerestore' => 'Before restore', 'upload' => 'Upload'];
        $ring = KeyRing::get();
        $site = BackupCrypto::siteId();

        echo '<div class="bkp-grid">';
        echo '<div class="bkp-card bkp-span"><h3>Backups in the vault</h3>';
        if (!$backups) {
            echo '<p class="bkp-muted">No backups yet.</p>';
        } else {
            echo '<div class="bkp-table-wrap"><table class="bkp-table"><thead><tr><th>Date</th><th>Type</th><th>Source</th><th>Size</th><th>Key</th><th>File</th><th class="bkp-right">Actions</th></tr></thead><tbody>';
            foreach ($backups as $b) {
                $download = wp_nonce_url(add_query_arg(['action' => 'bakkuappu_download', 'file' => $b['name']], admin_url('admin-post.php')), 'bakkuappu_admin');
                echo '<tr>';
                echo '<td>' . esc_html(wp_date('Y-m-d H:i:s', $b['time'])) . '</td>';
                echo '<td><span class="bkp-type bkp-type-' . esc_attr($b['kind']) . '">' . esc_html($b['kind'] === 'db' ? 'Database' : 'Files') . '</span></td>';
                echo '<td>' . esc_html($labels[$b['label']] ?? $b['label']) . '</td>';
                echo '<td>' . esc_html(size_format($b['size'])) . '</td>';
                $h = $b['header'] ?? [];
                $v2 = ($h['format'] ?? 0) === 2;
                $sealed = $v2 && ($h['mode'] ?? '') === 'sealed';
                $otherSite = $v2 && ($h['site'] ?? '') !== $site;
                // Can this backup be opened without asking for a private key?
                $readable = $sealed ? true : ($v2 ? $ring->symmetricById((string) ($h['key_id'] ?? '')) !== null : $ring->symmetricKeys() !== []);
                echo '<td>';
                if (!$v2) echo '<span class="bkp-tag">Format v1</span>';
                elseif ($sealed) echo '<span class="bkp-tag bkp-tag-sealed" title="Readable only with the private key">Public key</span> <code class="bkp-file">' . esc_html((string) $h['key_id']) . '</code>';
                else echo '<span class="bkp-tag">Master key</span> <code class="bkp-file">' . esc_html((string) ($h['key_id'] ?? '')) . '</code>';
                if (!$readable) echo ' <span class="bkp-bad" title="No matching key available">✖</span>';
                if ($otherSite) echo '<br><span class="bkp-warn-text">from ' . esc_html((string) $h['site']) . '</span>';
                echo '</td>';
                echo '<td><code class="bkp-file">' . esc_html($b['name']) . '</code></td>';
                echo '<td class="bkp-right bkp-row-actions">';
                echo '<a class="button button-secondary" href="' . esc_url($download) . '">Download</a>';
                $attrs = ' data-file="' . esc_attr($b['name']) . '" data-sealed="' . ($sealed ? '1' : '') . '" data-site="' . esc_attr($otherSite ? (string) $h['site'] : '') . '"';
                echo '<button type="button" class="button button-secondary bkp-verify"' . $attrs . ($readable ? '' : ' disabled') . '>Verify</button>';
                echo '<button type="button" class="button button-secondary bkp-restore"' . $attrs . ' data-label="' . esc_attr(($b['kind'] === 'db' ? 'Database' : 'Files (wp-content)') . ' from ' . wp_date('Y-m-d H:i', $b['time'])) . '"' . ($readable ? '' : ' disabled') . '>Restore</button>';
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="bkp-inline" onsubmit="return confirm(\'Really delete this backup?\');">';
                wp_nonce_field('bakkuappu_admin');
                echo '<input type="hidden" name="action" value="bakkuappu_delete"><input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<button type="submit" class="button button-secondary bkp-danger">Delete</button></form>';
                echo '</td></tr>';
            }
            echo '</tbody></table></div>';
        }
        echo '</div>';

        echo '<div class="bkp-card"><h3>Upload backup</h3>';
        echo '<p class="bkp-desc">A Bakkuappu file (.enc) from another site or server. It must be encrypted with a key of this site (master key, old key or the same public key); database or files is detected automatically. Maximum size according to PHP: <strong>' . esc_html(size_format(wp_max_upload_size())) . '</strong>. Put larger files into the vault via SFTP; they appear in the list automatically when the file name follows the Bakkuappu scheme.</p>';
        echo '<form method="post" enctype="multipart/form-data" action="' . esc_url(add_query_arg('bkp_upload', '1', admin_url('admin-post.php'))) . '">';
        wp_nonce_field('bakkuappu_admin');
        echo '<input type="hidden" name="action" value="bakkuappu_upload">';
        echo '<input type="file" name="bakkuappu_file" accept=".enc" class="bkp-input" required>';
        echo '<button type="submit" class="button button-primary">Upload</button></form></div>';

        self::jobConsole();
        echo '</div>';

        // Restore dialog
        echo '<div class="bkp-modal" id="bkp-restore-modal" hidden><div class="bkp-modal-box">';
        echo '<h3>Restore backup</h3><p id="bkp-restore-what" class="bkp-strong"></p>';
        echo '<p class="bkp-desc">The current state will be overwritten. The file is verified completely first; if it is damaged, nothing is changed.</p>';
        echo '<div class="bkp-alert bkp-alert-warn" id="bkp-restore-site" hidden></div>';
        echo '<div id="bkp-restore-pk" hidden><label class="bkp-label">Private key (not stored)</label><input type="password" id="bkp-restore-pk-input" class="bkp-input" autocomplete="off" spellcheck="false" placeholder="64 hex characters"></div>';
        echo '<label class="bkp-check"><input type="checkbox" id="bkp-restore-safety" checked> Create a safety backup of the current state first (recommended)</label>';
        echo '<label class="bkp-check"><input type="checkbox" id="bkp-restore-confirm"> I understand that the current state will be overwritten.</label>';
        echo '<div class="bkp-actions"><button type="button" class="button button-primary" id="bkp-restore-go" disabled>Restore now</button><button type="button" class="button button-secondary" id="bkp-restore-cancel">Cancel</button></div>';
        echo '</div></div>';

        // Private key dialog for verifying backups made with the public key
        echo '<div class="bkp-modal" id="bkp-pk-modal" hidden><div class="bkp-modal-box">';
        echo '<h3>Verify backup</h3><p class="bkp-desc">This backup is encrypted with the public key. The private key is needed to verify it. It is used only for this one job and is not stored.</p>';
        echo '<label class="bkp-label">Private key</label><input type="password" id="bkp-pk-input" class="bkp-input" autocomplete="off" spellcheck="false" placeholder="64 hex characters">';
        echo '<div class="bkp-actions"><button type="button" class="button button-primary" id="bkp-pk-go">Verify</button><button type="button" class="button button-secondary" id="bkp-pk-cancel">Cancel</button></div>';
        echo '</div></div>';
    }

    private static function tabSettings(): void
    {
        $s = Settings::get();
        $days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('bakkuappu_admin');
        echo '<input type="hidden" name="action" value="bakkuappu_save_settings">';
        echo '<div class="bkp-grid">';

        echo '<div class="bkp-card"><h3>Schedule</h3>';
        echo '<label class="bkp-label">Automatic backup</label><select name="bkp[schedule]" class="bkp-input">';
        foreach (['off' => 'Off', 'daily' => 'Daily', 'weekly' => 'Weekly'] as $v => $l) {
            echo '<option value="' . esc_attr($v) . '"' . selected($s['schedule'], $v, false) . '>' . esc_html($l) . '</option>';
        }
        echo '</select>';
        echo '<label class="bkp-label">Type</label><select name="bkp[schedule_type]" class="bkp-input">';
        foreach (['full' => 'Full (database + files)', 'db' => 'Database only', 'files' => 'Files only'] as $v => $l) {
            echo '<option value="' . esc_attr($v) . '"' . selected($s['schedule_type'], $v, false) . '>' . esc_html($l) . '</option>';
        }
        echo '</select>';
        echo '<label class="bkp-label">Weekday (weekly)</label><select name="bkp[schedule_day]" class="bkp-input">';
        foreach ($days as $i => $l) {
            echo '<option value="' . (int) $i . '"' . selected($s['schedule_day'], $i, false) . '>' . esc_html($l) . '</option>';
        }
        echo '</select>';
        echo '<label class="bkp-label">Time (site time zone: ' . esc_html(wp_timezone_string()) . ')</label><input type="time" name="bkp[schedule_time]" value="' . esc_attr($s['schedule_time']) . '" class="bkp-input">';
        echo '<p class="bkp-desc">The schedule uses WP-Cron and starts WP-CLI in the background. WP-Cron only runs when the website is visited or a system cron runs <code>wp cron event run --due-now</code>. Alternatively directly via system cron: <code>wp bakkuappu run --type=full</code>.</p>';
        echo '</div>';

        echo '<div class="bkp-card"><h3>Exclusions (files backup)</h3>';
        echo '<p class="bkp-desc">One tar pattern per line, relative to <code>wp-content</code>. <code>./cache</code> = only the folder directly in wp-content, <code>cache</code> = every folder with this name, <code>*.log</code> = all .log files. The vault and unfinished files (*.part) are always excluded.</p>';
        echo '<textarea name="bkp[excludes]" class="bkp-input bkp-textarea" rows="9">' . esc_textarea(implode("\n", $s['excludes'])) . '</textarea>';
        echo '</div>';

        echo '<div class="bkp-card"><h3>Retention</h3>';
        echo '<p class="bkp-desc">How many backups are kept. Older ones are deleted after each <strong>successful</strong> backup, so the newest always stays. 0 = keep all. Uploaded backups are never deleted automatically.</p>';
        foreach (['keep_db' => 'Database backups (manual + schedule)', 'keep_files' => 'Files backups (manual + schedule)', 'keep_prerestore' => '"Before restore" backups (per type)'] as $k => $label) {
            echo '<label class="bkp-label">' . esc_html($label) . '</label><input type="number" min="0" max="999" name="bkp[' . esc_attr($k) . ']" value="' . (int) $s[$k] . '" class="bkp-input">';
        }
        echo '</div>';

        echo '<div class="bkp-card"><h3>E-mail notification</h3>';
        echo '<label class="bkp-label">Send</label><select name="bkp[email]" class="bkp-input">';
        foreach (['never' => 'Never', 'error' => 'Only on errors', 'always' => 'Always (success and errors)'] as $v => $l) {
            echo '<option value="' . esc_attr($v) . '"' . selected($s['email'], $v, false) . '>' . esc_html($l) . '</option>';
        }
        echo '</select>';
        echo '<label class="bkp-label">Recipient</label><input type="email" name="bkp[email_to]" value="' . esc_attr($s['email_to']) . '" placeholder="' . esc_attr((string) get_option('admin_email')) . '" class="bkp-input">';
        echo '<p class="bkp-desc">Empty = the admin e-mail of the site. Applies to backups, verifications and restores.</p>';
        echo '</div>';

        echo '</div><p><button type="submit" class="button button-primary">Save settings</button></p></form>';
    }

    private static function tabKeys(): void
    {
        $ring = KeyRing::get();
        $file = KeyRing::secretsFile();
        $exists = @is_file($file);
        $src = static fn(string $name): string => match ($ring->source($name)) {
            'file' => 'secrets file',
            'wp-config' => 'wp-config.php',
            default => '–',
        };

        echo '<div class="bkp-grid">';
        echo '<div class="bkp-card"><h3>Status</h3><div class="bkp-kv">';
        self::kv('New backups', $ring->mode() === 'sealed' ? '<span class="bkp-ok">public key</span>' : ($ring->master() ? '<span class="bkp-ok">master key</span>' : '<span class="bkp-bad">no key</span>'));
        self::kv('Master key', $ring->master() ? esc_html(KeyRing::id($ring->master()) . ' · ' . $src('BAKKUAPPU_MASTER_KEY')) : '–');
        $oldIds = array_map(static fn(string $k): string => KeyRing::id($k), $ring->oldKeys());
        self::kv('Old keys', $oldIds ? esc_html(implode(', ', $oldIds) . ' · ' . $src('BAKKUAPPU_OLD_KEYS')) : '–');
        self::kv('Public key', $ring->publicKey() ? esc_html(KeyRing::id($ring->publicKey(), true) . ' · ' . $src('BAKKUAPPU_PUBLIC_KEY')) : '–');
        if ($exists) {
            $perms = substr(sprintf('%o', (int) @fileperms($file)), -4);
            self::kv('Secrets file', $perms === '0600' || $perms === '0400' ? '<span class="bkp-ok">found (' . esc_html($perms) . ')</span>' : '<span class="bkp-bad">found, permissions ' . esc_html($perms) . ' - 0600 recommended</span>');
        } else {
            self::kv('Secrets file', 'not found');
        }
        echo '</div><p class="bkp-mini">Path: <code>' . esc_html($file) . '</code><br>No line in wp-config.php needed: Bakkuappu loads the file itself. Only for another location: <code>define(\'BAKKUAPPU_SECRETS_FILE\', \'/path/bakkuappu-secrets.php\');</code>. The folder must be inside the PHP <code>open_basedir</code> of the site.</p>';
        echo '<p class="bkp-desc">If a value is in both wp-config.php and the secrets file, wp-config.php wins. Keys are never shown, only their key ID.</p></div>';

        echo '<div class="bkp-card"><h3>Option A: master key</h3>';
        echo '<p class="bkp-desc">One key to encrypt and decrypt. Simple, but whoever takes over the server can read the backups with that key.</p>';
        echo '<pre class="bkp-console bkp-cmd">wp bakkuappu generate_key</pre>';
        echo '<p class="bkp-desc">Put the output as <code>BAKKUAPPU_MASTER_KEY</code> into the secrets file. <strong>Changing the key:</strong> enter the new key as <code>BAKKUAPPU_MASTER_KEY</code> and move the previous one to <code>BAKKUAPPU_OLD_KEYS</code>. New backups use the new key, older ones stay readable.</p></div>';

        echo '<div class="bkp-card"><h3>Option B: public key (recommended)</h3>';
        echo '<p class="bkp-desc">Only the public key is on the server: it can create backups but not read them. Only you have the private key (e.g. in a password manager). Even on a hacked server the backups stay unreadable. To verify or restore, Bakkuappu asks for the private key; it is used only for that job and is not stored.</p>';
        echo '<pre class="bkp-console bkp-cmd">wp bakkuappu generate_keypair</pre>';
        echo '<p class="bkp-desc">Put the public key as <code>BAKKUAPPU_PUBLIC_KEY</code> into the secrets file. An existing master key can stay: it is then only used to read older backups. <strong>If the private key is lost, the backups made with it can no longer be restored.</strong></p></div>';

        echo '<div class="bkp-card"><h3>Secrets file template</h3>';
        echo '<pre class="bkp-console">' . esc_html("<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

return [
    'BAKKUAPPU_MASTER_KEY' => '...64 hex characters...',
    // 'BAKKUAPPU_OLD_KEYS'  => ['...old key...'],
    // 'BAKKUAPPU_PUBLIC_KEY' => '...64 hex characters...',
];") . '</pre>';
        echo '<p class="bkp-desc">Permissions: <code>chmod 600</code>, owned by the PHP user of the site. The private key does <strong>not</strong> belong in this file.</p></div>';
        echo '</div>';
    }

    private static function tabLog(string $vault): void
    {
        $jobs = JobLog::history($vault);
        $kinds = ['backup' => 'Backup', 'restore' => 'Restore', 'verify' => 'Verification'];
        $triggers = ['admin' => 'Admin', 'schedule' => 'Schedule', 'cli' => 'WP-CLI'];
        $states = ['done' => ['ok', 'Successful'], 'error' => ['bad', 'Error'], 'running' => ['run', 'Running'], 'aborted' => ['bad', 'Aborted']];

        echo '<div class="bkp-card"><h3>Log (last 30 jobs)</h3>';
        if (!$jobs) {
            echo '<p class="bkp-muted">No jobs yet.</p></div>';
            return;
        }
        foreach ($jobs as $job) {
            [$cls, $stateLabel] = $states[$job['status'] ?? ''] ?? ['bad', (string) ($job['status'] ?? '?')];
            $duration = !empty($job['finished']) ? max(0, (int) $job['finished'] - (int) $job['started']) : null;
            echo '<details class="bkp-job"><summary>';
            echo '<span class="bkp-pill bkp-pill-' . esc_attr($cls) . '">' . esc_html($stateLabel) . '</span> ';
            echo '<strong>' . esc_html($kinds[$job['kind'] ?? ''] ?? (string) ($job['kind'] ?? '')) . '</strong> · ' . esc_html((string) ($job['detail'] ?? ''));
            echo ' <span class="bkp-muted">· ' . esc_html(wp_date('Y-m-d H:i:s', (int) ($job['started'] ?? 0))) . ' · ' . esc_html($triggers[$job['trigger'] ?? ''] ?? '') . ($duration !== null ? ' · ' . esc_html($duration . ' s') : '') . '</span>';
            echo '</summary><pre class="bkp-console">';
            foreach ((array) ($job['log'] ?? []) as $line) {
                echo esc_html(wp_date('H:i:s', (int) ($line['t'] ?? 0)) . '  ' . ($line['m'] ?? '')) . "\n";
            }
            echo '</pre></details>';
        }
        echo '</div>';
    }

    // ---------------------------------------------------------------------------------
    // Actions
    // ---------------------------------------------------------------------------------

    public static function ajaxStart(): void
    {
        if (!check_ajax_referer('bakkuappu_admin', 'nonce', false)) {
            wp_send_json_error(['message' => 'Security check failed. Please reload the page.'], 403);
        }
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => 'Access denied.'], 403);

        $vault = (new VaultManager())->getVaultPath();
        if (JobLog::isRunning($vault)) {
            wp_send_json_error(['message' => 'A job is already running. Please wait until it has finished.']);
        }

        $kind = sanitize_key(wp_unslash($_POST['kind'] ?? ''));
        if ($kind === 'backup') {
            $type = sanitize_key(wp_unslash($_POST['type'] ?? ''));
            if (!BackupTypes::isValid($type)) wp_send_json_error(['message' => 'Unknown backup type.'], 400);
            if (!self::hasKey()) wp_send_json_error(['message' => 'No key for backups is set up.']);
            $args = ['run', '--type=' . $type, '--trigger=admin'];
            $what = 'Backup (' . $type . ')';
        } elseif ($kind === 'verify' || $kind === 'restore') {
            $file = sanitize_file_name(wp_unslash($_POST['file'] ?? ''));
            if (BackupFile::resolve($vault, $file) === null) wp_send_json_error(['message' => 'Backup file not found.'], 400);
            $args = [$kind, '--file=' . $file, '--trigger=admin'];
            if ($kind === 'restore') {
                $args[] = '--yes';
                if (empty($_POST['safety'])) $args[] = '--no-safety-backup';
            }
            $what = ($kind === 'verify' ? 'Verification' : 'Restore') . ' (' . $file . ')';

            // Private key for backups made with the public key: handed over in a 0600 file
            // that the WP-CLI process deletes right after reading (never as an argument,
            // arguments are visible in the process list)
            $pk = isset($_POST['private_key']) ? trim(sanitize_text_field(wp_unslash($_POST['private_key']))) : '';
            if ($pk !== '') {
                if (!KeyRing::isHexKey($pk)) wp_send_json_error(['message' => 'The private key must have 64 hex characters.']);
                $pkFile = $vault . DIRECTORY_SEPARATOR . 'bkp-pk-' . bin2hex(random_bytes(8)) . '.tmp';
                $old = umask(0077);
                $written = @file_put_contents($pkFile, $pk);
                umask($old);
                if ($written === false) wp_send_json_error(['message' => 'Temporary key file could not be created.']);
                @chmod($pkFile, 0600);
                $args[] = '--private-key-file=' . $pkFile;
            }
        } else {
            wp_send_json_error(['message' => 'Unknown action.'], 400);
        }

        [$ok, $message] = Background::start($args);
        if (!$ok) {
            if (isset($pkFile)) @unlink($pkFile);
            wp_send_json_error(['message' => $message]);
        }
        wp_send_json_success(['message' => $what . ' started in the background.']);
    }

    public static function ajaxStatus(): void
    {
        if (!check_ajax_referer('bakkuappu_admin', 'nonce', false) || !current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Access denied.'], 403);
        }
        $vault = (new VaultManager())->getVaultPath();
        // Private key hand-over files that were never picked up (e.g. WP-CLI failed to start)
        foreach (glob($vault . DIRECTORY_SEPARATOR . 'bkp-pk-*.tmp') ?: [] as $stale) {
            if (@filemtime($stale) < time() - 600) @unlink($stale);
        }
        $job = JobLog::latest($vault);
        $lines = [];
        foreach (array_slice((array) ($job['log'] ?? []), -200) as $l) {
            $lines[] = wp_date('H:i:s', (int) ($l['t'] ?? 0)) . '  ' . (string) ($l['m'] ?? '');
        }
        wp_send_json_success([
            'running' => JobLog::isRunning($vault),
            'job'     => $job ? [
                'kind'    => (string) $job['kind'],
                'detail'  => (string) $job['detail'],
                'status'  => (string) $job['status'],
                'started' => wp_date('Y-m-d H:i:s', (int) $job['started']),
                'summary' => (string) ($job['summary'] ?? ''),
                'lines'   => $lines,
            ] : null,
        ]);
    }

    public static function handleDownload(): void
    {
        if (!current_user_can('manage_options')) wp_die('Access denied.', 403);
        check_admin_referer('bakkuappu_admin');
        $vault = (new VaultManager())->getVaultPath();
        $path = BackupFile::resolve($vault, sanitize_file_name(wp_unslash($_GET['file'] ?? '')));
        if ($path === null) wp_die('Backup file not found.', 404);

        while (ob_get_level()) ob_end_clean();
        nocache_headers();
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($path) . '"');
        header('Content-Length: ' . (string) filesize($path));
        header('X-Content-Type-Options: nosniff');
        $h = fopen($path, 'rb');
        if ($h) {
            while (!feof($h)) {
                echo fread($h, 1048576); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- binary download
                flush();
            }
            fclose($h);
        }
        exit;
    }

    public static function handleDelete(): void
    {
        self::check();
        $vault = (new VaultManager())->getVaultPath();
        $path = BackupFile::resolve($vault, sanitize_file_name(wp_unslash($_POST['file'] ?? '')));
        $ok = $path !== null && @unlink($path);
        wp_safe_redirect(self::url('backups', ['bkp_msg' => $ok ? 'deleted' : 'delete_fail']));
        exit;
    }

    public static function handleUpload(): void
    {
        self::check();
        $back = fn(string $msg, string $detail = '') => wp_safe_redirect(self::url('backups', array_filter(['bkp_msg' => $msg, 'bkp_detail' => $detail])));

        $f = $_FILES['bakkuappu_file'] ?? null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated below
        if (!is_array($f) || !isset($f['error'], $f['tmp_name']) || is_array($f['error'])) { $back('upload_fail', 'No file.'); exit; }
        if ((int) $f['error'] !== UPLOAD_ERR_OK) {
            $why = in_array((int) $f['error'], [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true) ? 'The file is larger than the PHP upload limit.' : 'Error code ' . (int) $f['error'] . '.';
            $back('upload_fail', $why); exit;
        }
        if (!is_uploaded_file($f['tmp_name'])) { $back('upload_fail', 'Invalid upload.'); exit; }

        try {
            $vault = (new VaultManager())->ensureVaultExists();
            $name = BackupService::importUpload($f['tmp_name'], $vault, new BackupCrypto(KeyRing::get()));
            $back('uploaded', $name);
        } catch (\Throwable $e) {
            @unlink($f['tmp_name']);
            $back('upload_fail', $e->getMessage());
        }
        exit;
    }

    public static function handleSaveSettings(): void
    {
        self::check();
        $in = isset($_POST['bkp']) && is_array($_POST['bkp']) ? wp_unslash($_POST['bkp']) : []; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Settings::sanitize()
        Settings::save($in);
        Scheduler::reschedule();
        wp_safe_redirect(self::url('settings', ['bkp_msg' => 'saved']));
        exit;
    }
}
