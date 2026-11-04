<?php
declare(strict_types=1);

namespace Bakkuappu\Crypt;

use RuntimeException;

/**
 * XChaCha20-Poly1305 secretstream encryption (libsodium) from stream to stream.
 *
 * File format v1:
 *   "BKUP" | version byte (0x01) | secretstream header (24 bytes)
 *   then frames: 4-byte big-endian length | encrypted chunk
 * The last frame carries TAG_FINAL; a file without it is reported as truncated.
 *
 * Files written by Bakkuappu 1.0.0 (no "BKUP" magic, fixed-size chunks) can still be decrypted.
 */
readonly class StreamCipher
{
    private const int CHUNK_SIZE = 65536;
    private const int LEGACY_CHUNK_SIZE = 8192;
    private const string MAGIC = 'BKUP';
    private const int FORMAT_VERSION = 1;
    // Upper bound for one frame, protects against corrupt length fields
    private const int MAX_FRAME = self::CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    private string $key;

    public function __construct(#[\SensitiveParameter] string $hexKey)
    {
        if (strlen($hexKey) !== 64 || !ctype_xdigit($hexKey)) {
            throw new RuntimeException('Invalid key: 64 hex characters (0-9, a-f) expected.');
        }
        $binaryKey = sodium_hex2bin($hexKey);
        if (strlen($binaryKey) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new RuntimeException('Invalid key length after decoding.');
        }
        $this->key = $binaryKey;
    }

    public static function generateKey(): string
    {
        return sodium_bin2hex(sodium_crypto_secretstream_xchacha20poly1305_keygen());
    }

    public static function isValidKey(string $hexKey): bool
    {
        return strlen($hexKey) === 64 && ctype_xdigit($hexKey);
    }

    /**
     * Reads until $length bytes are collected or the stream ends.
     * Pipes (tar, mariadb-dump) often return fewer bytes per fread() than requested.
     */
    private static function readFull($stream, int $length): string
    {
        $buffer = '';
        while (strlen($buffer) < $length && !feof($stream)) {
            $part = fread($stream, $length - strlen($buffer));
            if ($part === false) {
                throw new RuntimeException('Read error in the input stream.');
            }
            if ($part === '') {
                // Non-blocking or interrupted read: wait briefly instead of spinning
                if (!feof($stream)) usleep(1000);
                continue;
            }
            $buffer .= $part;
        }
        return $buffer;
    }

    private static function writeAll($stream, string $data): void
    {
        $total = strlen($data);
        $written = 0;
        while ($written < $total) {
            $n = fwrite($stream, substr($data, $written));
            if ($n === false || $n === 0) {
                throw new RuntimeException('Write error (disk full?).');
            }
            $written += $n;
        }
    }

    private static function additionalData(): string
    {
        return self::MAGIC . chr(self::FORMAT_VERSION);
    }

    /**
     * Encrypts everything from $source into $dest. The final chunk always carries TAG_FINAL,
     * also for an empty source, so truncation is detected on decryption.
     */
    public function encryptResource($source, $dest): void
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        self::writeAll($dest, self::MAGIC . chr(self::FORMAT_VERSION) . $header);
        $ad = self::additionalData();

        $current = self::readFull($source, self::CHUNK_SIZE);
        while (true) {
            // Look ahead one chunk to know whether the current one is the last
            $next = $current === '' ? '' : self::readFull($source, self::CHUNK_SIZE);
            $final = $next === '';
            $tag = $final ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($state, $current, $ad, $tag);
            self::writeAll($dest, pack('N', strlen($encrypted)) . $encrypted);
            if ($final) break;
            $current = $next;
        }
        sodium_memzero($state);
    }

    /**
     * Encrypts a file into $destPath. The result is written to "$destPath.part" and renamed
     * only after success, so an aborted run never leaves a file that looks complete.
     */
    public function encryptFile(string $sourcePath, string $destPath): void
    {
        $source = fopen($sourcePath, 'rb');
        if (!$source) throw new RuntimeException('Source file could not be opened.');
        try {
            $this->encryptToPath($source, $destPath);
        } finally {
            fclose($source);
        }
    }

    /**
     * Encrypts a stream into $destPath via a ".part" file that is renamed on success.
     */
    public function encryptToPath($source, string $destPath): void
    {
        $part = $destPath . '.part';
        $dest = fopen($part, 'xb');
        if (!$dest) throw new RuntimeException('Target file could not be created: ' . $part);
        // Backups are readable only by the PHP user
        @chmod($part, 0600);
        try {
            $this->encryptResource($source, $dest);
            if (!fflush($dest)) throw new RuntimeException('Write error while finishing the target file.');
            fclose($dest);
            $dest = null;
            if (!rename($part, $destPath)) throw new RuntimeException('Target file could not be renamed.');
        } catch (\Throwable $e) {
            if ($dest) fclose($dest);
            if (file_exists($part)) unlink($part);
            throw $e;
        }
    }

    /**
     * Decrypts $source into $dest ($dest = null only checks the file).
     * Throws on a wrong key, corrupt data or a missing final chunk.
     */
    public function decryptResource($source, $dest): void
    {
        $magic = self::readFull($source, 4);
        if ($magic !== self::MAGIC) {
            $this->decryptLegacy($magic, $source, $dest);
            return;
        }
        $version = self::readFull($source, 1);
        if ($version === '' || ord($version) !== self::FORMAT_VERSION) {
            throw new RuntimeException('Unknown backup format version.');
        }
        $header = self::readFull($source, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('Backup file is damaged (incomplete header).');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
        $ad = self::additionalData();

        $finished = false;
        while (true) {
            $lenRaw = self::readFull($source, 4);
            if ($lenRaw === '') break;
            if (strlen($lenRaw) !== 4) throw new RuntimeException('Backup file is damaged (incomplete length field).');
            $len = unpack('N', $lenRaw)[1];
            if ($len < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $len > self::MAX_FRAME) {
                throw new RuntimeException('Backup file is damaged (invalid block size).');
            }
            $frame = self::readFull($source, $len);
            if (strlen($frame) !== $len) throw new RuntimeException('Backup file is truncated.');

            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame, $ad);
            if ($result === false) {
                throw new RuntimeException('Decryption failed: wrong key or damaged data.');
            }
            [$plain, $tag] = $result;
            if ($dest !== null) self::writeAll($dest, $plain);
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                $finished = true;
                break;
            }
        }
        sodium_memzero($state);

        if (!$finished) throw new RuntimeException('Backup file is truncated (end marker missing).');
        if (self::readFull($source, 1) !== '') throw new RuntimeException('Backup file contains data after the end marker.');
    }

    /**
     * Format of Bakkuappu 1.0.0: header + fixed 8192-byte chunks. $first holds the 4 bytes
     * already read while checking for the magic.
     */
    private function decryptLegacy(string $first, $source, $dest): void
    {
        $header = $first . self::readFull($source, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES - strlen($first));
        if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('Backup file is damaged (incomplete header).');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
        $finished = false;
        while (true) {
            $chunk = self::readFull($source, self::LEGACY_CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            if ($chunk === '') break;
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk);
            if ($result === false) {
                throw new RuntimeException('Decryption failed: wrong key or damaged data.');
            }
            [$plain, $tag] = $result;
            if ($dest !== null) self::writeAll($dest, $plain);
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                $finished = true;
                break;
            }
        }
        sodium_memzero($state);
        if (!$finished) throw new RuntimeException('Backup file (old format) is truncated or has no end marker.');
    }

    /**
     * Decrypts the whole file without writing anything: proves the key is right and the file
     * is complete and undamaged.
     */
    public function verifyFile(string $sourcePath): void
    {
        $source = fopen($sourcePath, 'rb');
        if (!$source) throw new RuntimeException('Source file could not be opened.');
        try {
            $this->decryptResource($source, null);
        } finally {
            fclose($source);
        }
    }

    /**
     * Returns the first decrypted bytes (first authenticated chunk only), e.g. to tell a
     * database dump from a tar archive. Throws when the key does not fit.
     */
    public function decryptHead(string $sourcePath, int $max = 1024): string
    {
        $source = fopen($sourcePath, 'rb');
        if (!$source) throw new RuntimeException('Source file could not be opened.');
        try {
            $magic = self::readFull($source, 4);
            if ($magic === self::MAGIC) {
                self::readFull($source, 1);
                $header = self::readFull($source, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
                $lenRaw = self::readFull($source, 4);
                if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES || strlen($lenRaw) !== 4) {
                    throw new RuntimeException('Backup file is damaged.');
                }
                $len = unpack('N', $lenRaw)[1];
                if ($len < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $len > self::MAX_FRAME) {
                    throw new RuntimeException('Backup file is damaged.');
                }
                $frame = self::readFull($source, $len);
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame, self::additionalData());
            } else {
                $header = $magic . self::readFull($source, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES - 4);
                $chunk = self::readFull($source, self::LEGACY_CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
                if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                    throw new RuntimeException('Backup file is damaged.');
                }
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk);
            }
            if ($result === false) {
                throw new RuntimeException('The file cannot be decrypted with this key (different master key or not a Bakkuappu file).');
            }
            return substr($result[0], 0, $max);
        } finally {
            fclose($source);
        }
    }

    /**
     * Decrypts a file. The output is written to "$destPath.part" and renamed on success;
     * on any error the partial output is deleted.
     */
    public function decryptFile(string $sourcePath, string $destPath): void
    {
        $source = fopen($sourcePath, 'rb');
        if (!$source) throw new RuntimeException('Source file could not be opened.');
        $part = $destPath . '.part';
        $dest = fopen($part, 'xb');
        if (!$dest) {
            fclose($source);
            throw new RuntimeException('Target file could not be created: ' . $part);
        }
        try {
            $this->decryptResource($source, $dest);
            fclose($dest);
            $dest = null;
            if (!rename($part, $destPath)) throw new RuntimeException('Target file could not be renamed.');
        } catch (\Throwable $e) {
            if ($dest) fclose($dest);
            if (file_exists($part)) unlink($part);
            throw $e;
        } finally {
            fclose($source);
        }
    }
}
