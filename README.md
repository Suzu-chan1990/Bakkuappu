<p align="center"><img src="assets/readme-banner.png" width="700" alt="Bakkuappu"></p>

![WordPress](https://img.shields.io/badge/WordPress-7.x%2B-blue)
![PHP](https://img.shields.io/badge/PHP-8.4%2B-purple)
![License](https://img.shields.io/badge/license-GPLv2%2B-green)
![Encryption](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-red)
![Status](https://img.shields.io/badge/status-testing-orange)

# <img src="assets/logo.png" width="48" align="center" alt=""> Bakkuappu (WordPress Backup & Restore)

**Bakkuappu** (バックアップ) is an encrypted backup and restore plugin for WordPress. It backs up the database and `wp-content`, encrypts everything on the fly with **XChaCha20-Poly1305** (libsodium) and stores the backups in a vault outside the web root.

Nothing is ever written to disk unencrypted: the database dump and the file archive are streamed straight from `mariadb-dump`/`mysqldump` and `tar` into the encryption, and on restore the decrypted data is streamed straight back into the database client and `tar`.

> **Status:** Bakkuappu is currently being tested. Please test restores on a staging site before you rely on it for production.

---

# 🚀 Key Features

* **Streaming encryption:** XChaCha20-Poly1305 (libsodium secretstream) in 64 KB chunks. No temporary SQL or tar files – memory usage stays flat, even for large sites.
* **Database, files or both:** Database (`full`, `db`) and `wp-content` (`full`, `files`) as separate encrypted files.
* **MariaDB and MySQL:** Uses `mariadb-dump`/`mariadb` when available and falls back to `mysqldump`/`mysql`. The credentials are read from `wp-config.php` and passed in a temporary 0600 options file, so the password never shows up in the process list.
* **Restore with safety net:** Every backup is fully decrypted and verified before anything is changed. By default, a safety backup of the current state is created before a restore.
* **Public key mode (optional):** New backups can be encrypted with a public key. The server can create backups but cannot read them – only the private key, which never lives on the server, can restore them.
* **Key rotation:** Old keys stay usable for reading older backups.
* **Tamper protection:** The backup header (type, site, key, compression) is authenticated with every chunk. A modified header, a truncated file or a wrong key is detected.
* **Compression:** Raw deflate before encryption (database level 6, files level 1).
* **Background jobs:** Backups and restores started in the admin run as WP-CLI processes in the background – no PHP timeouts. Live log and progress in the admin.
* **Schedule:** Daily or weekly backups via WP-Cron.
* **Retention:** Keep the last *n* backups per type; old backups are only deleted after a successful new backup.
* **Disk space check:** Stops before a backup if the vault clearly does not have enough free space.
* **E-mail notifications:** Never, on error, or always.
* **WP-CLI first:** Everything the admin can do also works on the command line.

---

# 📋 Requirements

| Requirement | Notes |
|---|---|
| WordPress | 7.x |
| PHP | 8.4 or newer, with the `sodium` and `zlib` extensions |
| PHP functions | `proc_open` (backup/restore), `exec` (only for starting jobs from the admin) |
| WP-CLI | Needed for jobs started from the admin and for scheduled backups |
| System tools | `tar` and `mariadb-dump`/`mariadb` or `mysqldump`/`mysql`, available to the PHP user |
| OS | Linux/Unix servers |

If `exec()` is disabled, backups and restores still work with WP-CLI; only starting them from the admin is not possible.

---

# 📦 Installation

1. Upload the `bakkuappu` folder to `wp-content/plugins/` and activate the plugin.
2. Create a key (see [Keys](#-keys)) and put it into the secrets file.
3. Open **Bakkuappu → Overview** and check that the vault, the keys and the tools are found.
4. If WP-CLI is not found automatically, set its path in `wp-config.php`:

```php
define('BAKKUAPPU_WP_CLI', '/usr/local/bin/wp');
```

---

# 🔐 Keys

Bakkuappu reads its keys from a **secrets file outside the web root**:

```
/path/to/site/
├── secrets/
│   └── bakkuappu-secrets.php   ← keys
└── public_html/                ← WordPress (ABSPATH)
```

Default location: one level above the WordPress directory, `secrets/bakkuappu-secrets.php`. Another path can be set in `wp-config.php` with `BAKKUAPPU_SECRETS_FILE`. A constant with the same name in `wp-config.php` takes precedence over the secrets file.

```php
<?php
// bakkuappu-secrets.php
return [
    'BAKKUAPPU_MASTER_KEY' => '64 hex characters',
    // Previous keys, only used to read older backups
    'BAKKUAPPU_OLD_KEYS'   => ['64 hex characters'],
    // Optional: public key mode
    // 'BAKKUAPPU_PUBLIC_KEY' => '64 hex characters',
];
```

Recommended permissions: directory `0700`, file `0600`, owned by the user PHP runs as.

> **Important:** If PHP runs with `open_basedir`, the `secrets` directory (and the vault) must be inside the allowed paths, otherwise PHP cannot read them. Add the directory in your PHP or hosting panel settings.

## Master key (symmetric mode)

```bash
wp bakkuappu generate_key
```

The server can create, verify and restore backups on its own.

## Public key mode (sealed mode)

```bash
wp bakkuappu generate_keypair
```

* The **public key** goes into the secrets file as `BAKKUAPPU_PUBLIC_KEY`.
* The **private key** does **not** go onto the server. Keep it in a password manager.

Each backup gets a random stream key, which is sealed with the public key (`crypto_box_seal`). An attacker who gets full access to the server cannot decrypt the backups. For a restore, the private key is entered in the admin (or passed with `--private-key-file`); it is used for this one job only and never stored.

> Without the private key, backups made in public key mode **cannot be restored**.

## Key rotation

1. Create a new key.
2. Move the old key to `BAKKUAPPU_OLD_KEYS`.
3. Put the new key into `BAKKUAPPU_MASTER_KEY`.

Each backup stores a non-secret key ID, so Bakkuappu picks the right key automatically. `wp bakkuappu keys` shows all configured keys, their IDs and where they are loaded from.

A private key (`BAKKUAPPU_PRIVATE_KEY`) found on the server is ignored and reported as a warning.

---

# 🗃️ Vault

Backups are stored in the vault, in this order:

1. `BAKKUAPPU_VAULT_PATH` from `wp-config.php`
2. `bakkuappu_vault` one level above the WordPress directory (outside the web root)
3. `wp-content/bakkuappu_vault` as a fallback – the admin shows a warning, because this folder is reachable from the web

```php
define('BAKKUAPPU_VAULT_PATH', '/path/to/site/bakkuappu_vault');
```

The vault also holds the job logs, so they survive a database restore.

---

# 🖥️ Admin

**Bakkuappu** in the admin menu (administrators only):

| Tab | Content |
|---|---|
| **Overview** | Start a backup, status of vault, keys, tools, schedule and last job |
| **Backups** | All backups with type, source, size and key – download, verify, restore, delete; upload a backup |
| **Keys** | Configured keys, key IDs, secrets file, how to create keys |
| **Settings** | Schedule, excludes, retention, e-mail notifications |
| **Log** | Log of the current and the last jobs |

Uploads in the admin are limited by PHP's `upload_max_filesize`/`post_max_size`. Larger backups can be copied into the vault directly (e.g. via SFTP); they show up in the list as long as the file name follows the Bakkuappu naming scheme.

---

# ⌨️ WP-CLI

Run WP-CLI as the user that owns the site files (the user PHP runs as), **not as root**.

```bash
# Backups
wp bakkuappu run --type=full            # full | db | files
wp bakkuappu list
wp bakkuappu verify --file=<file>
wp bakkuappu delete --file=<file>

# Restore (database or files, detected from the backup)
wp bakkuappu restore --file=<file>
wp bakkuappu restore --file=<file> --no-safety-backup --yes
wp bakkuappu restore --file=<file> --private-key-file=/path/to/private.key

# Decrypt to a file (database: SQL, files: tar archive)
wp bakkuappu decrypt --file=<file> --out=/path/to/output

# Keys
wp bakkuappu generate_key
wp bakkuappu generate_keypair
wp bakkuappu keys
```

`--file` takes a file name from `wp bakkuappu list` or a path to a Bakkuappu `.enc` file.

---

# ⏰ Scheduled Backups

The schedule (Settings tab) uses WP-Cron, which only runs when the site gets visits. For reliable times, disable the WP-Cron page trigger and call it from a system cron job as the site user:

```php
define('DISABLE_WP_CRON', true);
```

```cron
*/5 * * * * cd /path/to/wordpress && wp cron event run --due-now --quiet
```

---

# ♻️ Restore Notes

* **Database:** The dump is imported into the current database. The site URL is not changed – when restoring a backup from another site, Bakkuappu logs a note.
* **Files:** Files from the backup overwrite existing files in `wp-content`. Files that are not in the backup are left alone.
* **Safety backup:** Created by default before every restore (marked as *Before restore*); it can be turned off per restore.
* Only one Bakkuappu job runs at a time.

---

# 📄 Backup File Format (v2)

```
"BKP2" | 0x02 | header length (4 bytes, big endian) | header (JSON)
| secretstream header (24 bytes)
| frames: 4-byte length | XChaCha20-Poly1305 chunk (last chunk: TAG_FINAL)
```

The JSON header contains `kind` (db/files), `created`, `site`, `mode` (symmetric/sealed), `key_id`, `wrapped_key` (sealed only), `compression` and the plugin version. A hash of the header is the additional data of every chunk, so any change to the header makes decryption fail.

File names: `<db|files>_<YYYY-MM-DD>_<HH-MM-SS UTC>[_schedule|_prerestore|_upload]_<random>.enc`, e.g. `db_2026-11-04_07-18-09_5afe1787c13e79f5.enc`

Backups from older Bakkuappu versions (format v1 and 1.0.0) can still be read.

---

# 🛡️ Security

Please report security issues privately – see [SECURITY.md](SECURITY.md).

# 📜 License

GPLv2 or later – see [LICENSE](LICENSE).
