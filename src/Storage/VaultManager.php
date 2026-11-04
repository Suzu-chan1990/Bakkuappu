<?php
declare(strict_types=1);

namespace Bakkuappu\Storage;

use RuntimeException;

/**
 * Manages the storage location of the backups (the vault).
 */
readonly class VaultManager
{
    public function getVaultPath(): string
    {
        // 1. Fixed path from wp-config.php
        if (defined('BAKKUAPPU_VAULT_PATH') && is_string(BAKKUAPPU_VAULT_PATH) && BAKKUAPPU_VAULT_PATH !== '') {
            return rtrim(BAKKUAPPU_VAULT_PATH, '/\\');
        }

        // 2. One level above the WordPress root (outside the web root). Only if PHP may use
        //    that directory: a restrictive open_basedir makes is_writable() fail with a warning.
        $aboveWpRoot = dirname(rtrim(ABSPATH, '/\\'));
        $secureVault = $aboveWpRoot . DIRECTORY_SEPARATOR . 'bakkuappu_vault';
        if (self::allowedByOpenBasedir($secureVault) && (@is_dir($secureVault) || @is_writable($aboveWpRoot))) {
            return $secureVault;
        }

        // 3. Fallback inside wp-content (web reachable, see isInsideWebRoot())
        return WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'bakkuappu_vault';
    }

    /**
     * True when PHP's open_basedir allows access to $path (or no open_basedir is set).
     */
    public static function allowedByOpenBasedir(string $path): bool
    {
        $basedir = (string) ini_get('open_basedir');
        if ($basedir === '') return true;
        $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
        foreach (explode(PATH_SEPARATOR, $basedir) as $allowed) {
            $allowed = str_replace('\\', '/', trim($allowed));
            if ($allowed === '') continue;
            if ($allowed === '.' ) $allowed = (string) getcwd();
            $allowed = rtrim($allowed, '/') . '/';
            if (str_starts_with($path, $allowed)) return true;
        }
        return false;
    }

    /**
     * True when the vault lies inside the WordPress directory and could be served by the web server.
     */
    public function isInsideWebRoot(?string $path = null): bool
    {
        $path = rtrim(str_replace('\\', '/', $path ?? $this->getVaultPath()), '/') . '/';
        $root = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';
        $content = rtrim(str_replace('\\', '/', WP_CONTENT_DIR), '/') . '/';
        return str_starts_with($path, $root) || str_starts_with($path, $content);
    }

    public function ensureVaultExists(): string
    {
        $path = $this->getVaultPath();

        if (!is_dir($path)) {
            if (!mkdir($path, 0750, true) && !is_dir($path)) {
                throw new RuntimeException('Vault directory could not be created: ' . $path);
            }
        }
        if (!is_writable($path)) {
            throw new RuntimeException('Vault directory is not writable: ' . $path);
        }

        // Safety net for the fallback inside the web root. Apache 2.2 and 2.4 syntax;
        // nginx ignores .htaccess, therefore the file names also contain a random part.
        $htaccess = $path . DIRECTORY_SEPARATOR . '.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n");
        }

        $index = $path . DIRECTORY_SEPARATOR . 'index.html';
        if (!file_exists($index)) {
            file_put_contents($index, '');
        }

        return $path;
    }

    /**
     * Path for a new backup file: "<prefix>_<UTC time>_<random>.enc". The random part makes
     * the names impossible to guess if the vault is ever reachable over the web.
     */
    public function newBackupPath(string $vaultPath, string $prefix): string
    {
        return $vaultPath . DIRECTORY_SEPARATOR . $prefix . '_' . gmdate('Y-m-d_H-i-s') . '_' . bin2hex(random_bytes(8)) . '.enc';
    }
}
