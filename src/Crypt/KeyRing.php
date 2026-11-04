<?php
declare(strict_types=1);

namespace Bakkuappu\Crypt;

use RuntimeException;

/**
 * All keys Bakkuappu knows about.
 *
 * Sources (a constant in wp-config.php wins over the secrets file):
 *   BAKKUAPPU_MASTER_KEY  current symmetric key (64 hex)
 *   BAKKUAPPU_OLD_KEYS    previous symmetric keys, only used to read older backups
 *   BAKKUAPPU_PUBLIC_KEY  X25519 public key (64 hex). When set, new backups are encrypted so
 *                         that only the matching private key can open them; the private key
 *                         is never stored on the server and is given only for a restore.
 *
 * Secrets file: one level above the WordPress directory, secrets/bakkuappu-secrets.php,
 * or the path in BAKKUAPPU_SECRETS_FILE. It returns an array with the names above.
 */
final class KeyRing
{
    public const array NAMES = ['BAKKUAPPU_MASTER_KEY', 'BAKKUAPPU_OLD_KEYS', 'BAKKUAPPU_PUBLIC_KEY'];

    private ?string $master = null;
    /** @var list<string> */
    private array $old = [];
    private ?string $public = null;
    private ?string $privateKeypair = null;
    /** @var array<string,string> name => 'wp-config' | 'file' */
    private array $sources = [];
    /** @var list<string> */
    private array $problems = [];

    private static ?KeyRing $instance = null;

    public static function get(): self
    {
        return self::$instance ??= self::load();
    }

    public static function secretsFile(): string
    {
        if (defined('BAKKUAPPU_SECRETS_FILE') && is_string(BAKKUAPPU_SECRETS_FILE) && BAKKUAPPU_SECRETS_FILE !== '') {
            return BAKKUAPPU_SECRETS_FILE;
        }
        return dirname(rtrim(ABSPATH, '/\\')) . '/secrets/bakkuappu-secrets.php';
    }

    /**
     * @return array<string,mixed>
     */
    public static function readSecretsFile(): array
    {
        $file = self::secretsFile();
        if (!@is_file($file) || !@is_readable($file)) return [];
        $data = include $file;
        return is_array($data) ? $data : [];
    }

    public static function load(): self
    {
        $ring = new self();
        $file = self::readSecretsFile();
        $value = static function (string $name) use ($file, $ring) {
            if (defined($name)) {
                $ring->sources[$name] = 'wp-config';
                return constant($name);
            }
            if (array_key_exists($name, $file)) {
                $ring->sources[$name] = 'file';
                return $file[$name];
            }
            return null;
        };

        $master = $value('BAKKUAPPU_MASTER_KEY');
        if (is_string($master) && $master !== '') {
            if (self::isHexKey($master)) $ring->master = sodium_hex2bin($master);
            else $ring->problems[] = 'BAKKUAPPU_MASTER_KEY is not a 64-character hex key.';
        }

        $old = $value('BAKKUAPPU_OLD_KEYS');
        if (is_string($old)) $old = preg_split('/[\s,;]+/', $old, -1, PREG_SPLIT_NO_EMPTY);
        foreach ((array) $old as $k) {
            if (is_string($k) && self::isHexKey($k)) $ring->old[] = sodium_hex2bin($k);
            elseif ($k !== '' && $k !== null) $ring->problems[] = 'An entry in BAKKUAPPU_OLD_KEYS is not a 64-character hex key.';
        }

        $public = $value('BAKKUAPPU_PUBLIC_KEY');
        if (is_string($public) && $public !== '') {
            if (self::isHexKey($public)) $ring->public = sodium_hex2bin($public);
            else $ring->problems[] = 'BAKKUAPPU_PUBLIC_KEY is not a 64-character hex key.';
        }

        // The private key must never live on the server
        if (defined('BAKKUAPPU_PRIVATE_KEY') || array_key_exists('BAKKUAPPU_PRIVATE_KEY', $file)) {
            $ring->problems[] = 'A private key (BAKKUAPPU_PRIVATE_KEY) is stored on the server and is ignored. It does not belong on the server - remove it.';
        }
        return $ring;
    }

    public static function isHexKey(string $hex): bool
    {
        return strlen($hex) === 64 && ctype_xdigit($hex);
    }

    /**
     * Short, non-secret key identifier (16 hex). For symmetric keys a keyed hash is used,
     * so the identifier reveals nothing about the key.
     */
    public static function id(string $binaryKey, bool $public = false): string
    {
        $context = $public ? 'bakkuappu-public-key-id' : 'bakkuappu-key-id-v2';
        // generichash needs at least 16 bytes of output; 8 are enough for an identifier
        return sodium_bin2hex(substr(sodium_crypto_generichash($context, $binaryKey, 16), 0, 8));
    }

    public function master(): ?string { return $this->master; }
    public function publicKey(): ?string { return $this->public; }
    /** @return list<string> */
    public function oldKeys(): array { return $this->old; }
    /** @return list<string> */
    public function problems(): array { return $this->problems; }
    public function source(string $name): ?string { return $this->sources[$name] ?? null; }

    /** New backups use the public key when one is configured. */
    public function mode(): string
    {
        return $this->public !== null ? 'sealed' : 'symmetric';
    }

    public function canBackup(): bool
    {
        return $this->public !== null || $this->master !== null;
    }

    /**
     * Symmetric keys for reading: current first, then the old ones.
     *
     * @return list<string>
     */
    public function symmetricKeys(): array
    {
        return array_values(array_filter(array_merge([$this->master], $this->old)));
    }

    public function symmetricById(string $id): ?string
    {
        foreach ($this->symmetricKeys() as $k) {
            if (hash_equals(self::id($k), $id)) return $k;
        }
        return null;
    }

    /**
     * Private key given for one restore/verify (never stored).
     */
    public function setPrivateKey(#[\SensitiveParameter] string $hex): string
    {
        $hex = trim($hex);
        if (!self::isHexKey($hex)) {
            throw new RuntimeException('The private key must have 64 hex characters.');
        }
        $secret = sodium_hex2bin($hex);
        $public = sodium_crypto_box_publickey_from_secretkey($secret);
        $this->privateKeypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secret, $public);
        return self::id($public, true);
    }

    public function privateKeypair(): ?string
    {
        return $this->privateKeypair;
    }

    /**
     * New key pair: [secret hex, public hex].
     *
     * @return array{0:string,1:string}
     */
    public static function generateKeypair(): array
    {
        $kp = sodium_crypto_box_keypair();
        return [sodium_bin2hex(sodium_crypto_box_secretkey($kp)), sodium_bin2hex(sodium_crypto_box_publickey($kp))];
    }
}
