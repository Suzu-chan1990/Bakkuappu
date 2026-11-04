# Changelog

## 2.0.2 – Logo

- **Logo:** New Bakkuappu logo in the header of the plugin page and a colored icon in the admin menu (`assets/logo.png`, `assets/menu-icon.png`).

## 2.0.1 – English Interface

- **Language:** All texts in the admin (tabs, cards, dialogs, messages), the admin JavaScript, WP-CLI output, error messages and notification e-mails are now in English.
- **Dates:** Dates are shown as `YYYY-MM-DD HH:MM:SS`.
- No changes to features or the backup format.

## 2.0.0 – Encryption v2 and Keys

- **Backup format v2 (`BKP2`):** New file format with an authenticated JSON header (type, creation time, site, mode, key ID, compression, plugin version). The header is the additional data of every encrypted chunk, so a modified header, a backup of the wrong type or a truncated file is detected.
- **Compression:** Data is compressed with raw deflate before encryption (database level 6, files level 1).
- **Secrets file:** Keys are read from `secrets/bakkuappu-secrets.php` one level above the WordPress directory (other path via `BAKKUAPPU_SECRETS_FILE`). Constants in `wp-config.php` still work and take precedence.
- **Public key mode:** With `BAKKUAPPU_PUBLIC_KEY`, every backup gets a random stream key that is sealed with the public key. The server can create backups but cannot read them; the private key is only given for a restore and never stored. A private key found on the server is ignored and reported.
- **Key rotation:** `BAKKUAPPU_OLD_KEYS` holds previous keys for reading older backups. Every backup stores a non-secret key ID, so the right key is picked automatically.
- **Verification after backup:** Every new backup is verified with its own stream key, also in public key mode.
- **Restore checks:** The backup type is taken from the authenticated header; restoring a backup from another site logs a note.
- **Keys tab:** Shows the configured keys, their IDs and sources, the secrets file and how to create keys.
- **WP-CLI:** New commands `generate_keypair` and `keys`; `--private-key-file` for `restore`, `verify` and `decrypt`.
- **Compatibility:** Backups in format v1 and from 1.0.0 can still be read.

## 1.3.0 – Retention and Disk Space

- **Retention:** Keep the last *n* database, file and "Before restore" backups (0 = keep all). Old backups are only deleted after a successful new backup; uploaded backups are never deleted automatically.
- **Disk space check:** Before a backup, the free space in the vault is compared with the expected size (last backup of the same type + 20 %, otherwise database or `wp-content` size). The backup stops early if the space is clearly not enough.
- **Verification after backup:** Every new backup is fully decrypted and checked right after it was written.

## 1.2.0 – Restore and New Admin

- **Restore:** Database and `wp-content` restore from the admin and with `wp bakkuappu restore`. The backup is fully verified before anything is changed; a safety backup of the current state is created first (can be turned off).
- **New admin:** New design with the tabs Overview, Backups, Settings and Log.
- **Backups list:** Download, verify, restore and delete; upload of a Bakkuappu backup file.
- **Background jobs:** Jobs started from the admin run as WP-CLI processes in the background, with live log and status. Only one job runs at a time (job lock). Job logs are stored in the vault and survive a database restore.
- **Schedule:** Daily or weekly backups via WP-Cron (type, day and time).
- **Excludes:** `tar` exclude patterns for the file backup.
- **E-mail notifications:** Never, on error or always; custom recipient.
- **WP-CLI:** New commands `restore`, `verify`, `list` and `delete`.

## 1.1.0 – MariaDB and Fixes

- **MariaDB:** `mariadb-dump` is used when available, `mysqldump` as a fallback. `--column-statistics=0` is only passed to tools that support it.
- **Database credentials:** Read from `wp-config.php` (`DB_HOST` with port or socket, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_CHARSET`) and passed in a temporary 0600 options file, so the password never appears in the process list.
- **File format v1 (`BKUP`):** Magic and version byte, length-prefixed frames and a final tag, so truncated files are detected. Backups from 1.0.0 can still be read.
- **Fix:** Starting a backup from the admin failed with "connection error" (fatal error in the AJAX request).
- **Vault:** `open_basedir` is respected when choosing the vault directory; a vault inside the web root is reported.
- **Code:** All comments in English.

## 1.0.0

- Initial release: encrypted database and `wp-content` backups with XChaCha20-Poly1305 (libsodium) and WP-CLI.
