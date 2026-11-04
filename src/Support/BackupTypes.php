<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

/**
 * Allowed backup types. Kept outside the WP-CLI command class: that class extends
 * WP_CLI_Command, which does not exist in normal admin/AJAX requests.
 */
final class BackupTypes
{
    public const array ALL = ['full', 'db', 'files'];

    public static function isValid(string $type): bool
    {
        return in_array($type, self::ALL, true);
    }
}
