<?php
declare(strict_types=1);

namespace Bakkuappu\Crypt;

use RuntimeException;

/**
 * Backup file format v2.
 *
 *   "BKP2" | 0x02 | header length (4 bytes, big endian) | header (JSON, plaintext)
 *   | secretstream header (24 bytes)
 *   | frames: 4-byte length | XChaCha20-Poly1305 chunk (last one TAG_FINAL)
 *
 * Header: kind (db/files), created, site, mode (symmetric/sealed), key_id, wrapped_key
 * (sealed only), compression (deflate/none), plugin version.
 * The whole header is the additional data of every chunk: changing any header field
 * (e.g. claiming "db" for a files backup, or another site) makes decryption fail.
 *
 * Modes:
 *   symmetric  the stream key is BAKKUAPPU_MASTER_KEY
 *   sealed     a random stream key per backup, wrapped with BAKKUAPPU_PUBLIC_KEY
 *              (crypto_box_seal); only the private key can unwrap it
 *
 * Data is compressed (raw deflate) before encryption.
 * Files of format v1 ("BKUP") and of 1.0.0 are read through StreamCipher.
 */
final class BackupCrypto
{
    private const string MAGIC = 'BKP2';
    private const int VERSION = 2;
    private const int CHUNK = 65536;
    private const int MAX_HEADER = 65536;
    private const int MAX_FRAME = self::CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    public function __construct(private readonly KeyRing $ring)
    {
    }

    // ------------------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------------------

    /**
     * Encrypts $source into $destPath (via "$destPath.part", renamed on success).
     * Returns the stream key so the caller can verify the new file right away, also in
     * sealed mode where the server cannot decrypt later.
     *
     * @param array{kind:string} $meta
     */
    public function encryptToPath($source, string $destPath, array $meta): string
    {
        $part = $destPath . '.part';
        $dest = fopen($part, 'xb');
        if (!$dest) throw new RuntimeException('Target file could not be created: ' . $part);
        @chmod($part, 0600);
        try {
            $key = $this->encryptResource($source, $dest, $meta);
            if (!fflush($dest)) throw new RuntimeException('Write error while finishing the target file.');
            fclose($dest);
            $dest = null;
            if (!rename($part, $destPath)) throw new RuntimeException('Target file could not be renamed.');
            return $key;
        } catch (\Throwable $e) {
            if ($dest) fclose($dest);
            if (file_exists($part)) unlink($part);
            throw $e;
        }
    }

    private function encryptResource($source, $dest, array $meta): string
    {
        $mode = $this->ring->mode();
        if ($mode === 'sealed') {
            $key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
            $header = [
                'mode'        => 'sealed',
                'key_id'      => KeyRing::id((string) $this->ring->publicKey(), true),
                'wrapped_key' => sodium_bin2base64(sodium_crypto_box_seal($key, (string) $this->ring->publicKey()), SODIUM_BASE64_VARIANT_ORIGINAL),
            ];
        } else {
            $key = $this->ring->master();
            if ($key === null) throw new RuntimeException('No key for new backups (BAKKUAPPU_MASTER_KEY or BAKKUAPPU_PUBLIC_KEY).');
            $header = ['mode' => 'symmetric', 'key_id' => KeyRing::id($key)];
        }

        $kind = (string) ($meta['kind'] ?? '');
        $level = $kind === 'db' ? 6 : 1; // archives are mostly already compressed media
        $header = [
            'kind'        => $kind,
            'created'     => time(),
            'site'        => self::siteId(),
            'compression' => 'deflate',
            'plugin'      => defined('BAKKUAPPU_VERSION') ? BAKKUAPPU_VERSION : '',
        ] + $header;

        $json = (string) wp_json_encode($header, JSON_UNESCAPED_SLASHES);
        $prefix = self::MAGIC . chr(self::VERSION) . pack('N', strlen($json)) . $json;
        $ad = hash('sha256', $prefix, true);

        [$state, $ssHeader] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        self::writeAll($dest, $prefix . $ssHeader);

        $deflate = deflate_init(ZLIB_ENCODING_RAW, ['level' => $level]);
        $buffer = '';
        while (!feof($source)) {
            $chunk = self::readFull($source, self::CHUNK);
            if ($chunk === '') break;
            $buffer .= deflate_add($deflate, $chunk, ZLIB_NO_FLUSH);
            while (strlen($buffer) > self::CHUNK) {
                self::writeFrame($dest, $state, substr($buffer, 0, self::CHUNK), $ad, false);
                $buffer = substr($buffer, self::CHUNK);
            }
        }
        $buffer .= deflate_add($deflate, '', ZLIB_FINISH);
        while (strlen($buffer) > self::CHUNK) {
            self::writeFrame($dest, $state, substr($buffer, 0, self::CHUNK), $ad, false);
            $buffer = substr($buffer, self::CHUNK);
        }
        // The last frame always carries TAG_FINAL (also when it is empty)
        self::writeFrame($dest, $state, $buffer, $ad, true);
        sodium_memzero($state);
        return $key;
    }

    private static function writeFrame($dest, string &$state, string $plain, string $ad, bool $final): void
    {
        $tag = $final ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        $ct = sodium_crypto_secretstream_xchacha20poly1305_push($state, $plain, $ad, $tag);
        self::writeAll($dest, pack('N', strlen($ct)) . $ct);
    }

    public static function siteId(): string
    {
        $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        $path = rtrim((string) wp_parse_url(home_url(), PHP_URL_PATH), '/');
        return strtolower($host . $path);
    }

    // ------------------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------------------

    /**
     * Plaintext header of a v2 file (not yet authenticated – that happens on decryption),
     * or ['format' => 1] for older files, or null when the file is unreadable.
     */
    public static function readHeader(string $path): ?array
    {
        $h = @fopen($path, 'rb');
        if (!$h) return null;
        try {
            return self::parseHeader($h)[0];
        } catch (\Throwable $e) {
            return null;
        } finally {
            fclose($h);
        }
    }

    /**
     * @return array{0:array,1:string} [header, prefix bytes] – prefix is empty for old formats
     */
    private static function parseHeader($h): array
    {
        $magic = self::readFull($h, 4);
        if ($magic !== self::MAGIC) {
            return [['format' => 1], ''];
        }
        $ver = self::readFull($h, 1);
        if ($ver === '' || ord($ver) !== self::VERSION) throw new RuntimeException('Unknown backup format version.');
        $lenRaw = self::readFull($h, 4);
        if (strlen($lenRaw) !== 4) throw new RuntimeException('Backup file is damaged (header).');
        $len = unpack('N', $lenRaw)[1];
        if ($len < 2 || $len > self::MAX_HEADER) throw new RuntimeException('Backup file is damaged (header length).');
        $json = self::readFull($h, $len);
        $header = json_decode($json, true);
        if (strlen($json) !== $len || !is_array($header)) throw new RuntimeException('Backup file is damaged (header).');
        $header['format'] = 2;
        return [$header, $magic . $ver . $lenRaw . $json];
    }

    /**
     * Stream key for a v2 header, from the key ring (symmetric) or the given private key (sealed).
     */
    private function keyFor(array $header): string
    {
        if (($header['mode'] ?? '') === 'sealed') {
            $kp = $this->ring->privateKeypair();
            if ($kp === null) {
                throw new RuntimeException('This backup is encrypted with the public key (key ID ' . ($header['key_id'] ?? '?') . '). The private key is required to verify or restore it.');
            }
            if (!hash_equals((string) ($header['key_id'] ?? ''), KeyRing::id(sodium_crypto_box_publickey($kp), true))) {
                throw new RuntimeException('The given private key does not match this backup (key ID ' . ($header['key_id'] ?? '?') . ').');
            }
            $wrapped = sodium_base642bin((string) ($header['wrapped_key'] ?? ''), SODIUM_BASE64_VARIANT_ORIGINAL);
            $key = sodium_crypto_box_seal_open($wrapped, $kp);
            if ($key === false) throw new RuntimeException('The backup key could not be unwrapped (wrong private key or damaged file).');
            return $key;
        }
        $key = $this->ring->symmetricById((string) ($header['key_id'] ?? ''));
        if ($key === null) {
            throw new RuntimeException('No matching key is available for this backup (key ID ' . ($header['key_id'] ?? '?') . '). If the key was changed, add the old one to BAKKUAPPU_OLD_KEYS.');
        }
        return $key;
    }

    /**
     * Decrypts $path into $dest (null = only check). $streamKey forces a key (used to verify
     * a backup right after creating it).
     */
    public function decryptToStream(string $path, $dest, ?string $streamKey = null): array
    {
        $h = fopen($path, 'rb');
        if (!$h) throw new RuntimeException('Backup file could not be opened.');
        try {
            [$header, $prefix] = self::parseHeader($h);
            if ($header['format'] === 1) {
                fclose($h);
                $h = null;
                $this->decryptOldFormat($path, $dest);
                return $header;
            }
            $key = $streamKey ?? $this->keyFor($header);
            $this->decryptFrames($h, $dest, $key, hash('sha256', $prefix, true), (string) ($header['compression'] ?? 'none'));
            return $header;
        } finally {
            if ($h) fclose($h);
        }
    }

    private function decryptFrames($h, $dest, string $key, string $ad, string $compression): void
    {
        $ssHeader = self::readFull($h, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (strlen($ssHeader) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('Backup file is damaged (incomplete header).');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($ssHeader, $key);
        $inflate = $compression === 'deflate' ? inflate_init(ZLIB_ENCODING_RAW) : null;
        if ($compression !== 'deflate' && $compression !== 'none') throw new RuntimeException('Unknown compression: ' . $compression);

        $finished = false;
        while (true) {
            $lenRaw = self::readFull($h, 4);
            if ($lenRaw === '') break;
            if (strlen($lenRaw) !== 4) throw new RuntimeException('Backup file is damaged (length field).');
            $len = unpack('N', $lenRaw)[1];
            if ($len < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $len > self::MAX_FRAME) {
                throw new RuntimeException('Backup file is damaged (invalid block size).');
            }
            $frame = self::readFull($h, $len);
            if (strlen($frame) !== $len) throw new RuntimeException('Backup file is truncated.');

            $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame, $ad);
            if ($res === false) {
                throw new RuntimeException('Decryption failed: wrong key, damaged data or modified header.');
            }
            [$plain, $tag] = $res;
            $final = $tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
            if ($inflate) {
                $out = inflate_add($inflate, $plain, $final ? ZLIB_FINISH : ZLIB_SYNC_FLUSH);
                if ($out === false) throw new RuntimeException('Decompressing the data failed.');
                $plain = $out;
            }
            if ($dest !== null && $plain !== '') self::writeAll($dest, $plain);
            if ($final) {
                $finished = true;
                break;
            }
        }
        sodium_memzero($state);
        if (!$finished) throw new RuntimeException('Backup file is truncated (end marker missing).');
        if (self::readFull($h, 1) !== '') throw new RuntimeException('Backup file contains data after the end marker.');
    }

    /**
     * Format v1 / 1.0.0: tries the current and the old symmetric keys.
     */
    private function decryptOldFormat(string $path, $dest): void
    {
        $cipher = $this->oldFormatCipher($path);
        $h = fopen($path, 'rb');
        if (!$h) throw new RuntimeException('Backup file could not be opened.');
        try {
            $cipher->decryptResource($h, $dest);
        } finally {
            fclose($h);
        }
    }

    private function oldFormatCipher(string $path): StreamCipher
    {
        foreach ($this->ring->symmetricKeys() as $k) {
            $c = new StreamCipher(sodium_bin2hex($k));
            try {
                $c->decryptHead($path, 16);
                return $c;
            } catch (\Throwable $e) {
                // try the next key
            }
        }
        throw new RuntimeException('This older backup cannot be opened with any available key (BAKKUAPPU_MASTER_KEY / BAKKUAPPU_OLD_KEYS).');
    }

    public function verify(string $path, ?string $streamKey = null): array
    {
        return $this->decryptToStream($path, null, $streamKey);
    }

    /**
     * Decrypts into a new file (via ".part", deleted on error).
     */
    public function decryptToFile(string $path, string $destPath): array
    {
        $part = $destPath . '.part';
        $dest = fopen($part, 'xb');
        if (!$dest) throw new RuntimeException('Target file could not be created: ' . $part);
        try {
            $header = $this->decryptToStream($path, $dest);
            fclose($dest);
            $dest = null;
            if (!rename($part, $destPath)) throw new RuntimeException('Target file could not be renamed.');
            return $header;
        } catch (\Throwable $e) {
            if ($dest) fclose($dest);
            if (file_exists($part)) unlink($part);
            throw $e;
        }
    }

    /**
     * Kind of an uploaded file and whether one of our keys belongs to it.
     * v2: from the header; old formats: from the decrypted beginning.
     */
    public function identify(string $path): string
    {
        $header = self::readHeader($path);
        if ($header === null) throw new RuntimeException('Not a Bakkuappu file.');
        if ($header['format'] === 2) {
            $kind = (string) ($header['kind'] ?? '');
            if (!in_array($kind, ['db', 'files'], true)) throw new RuntimeException('Unknown backup type in the file.');
            $id = (string) ($header['key_id'] ?? '');
            $known = ($header['mode'] ?? '') === 'sealed'
                ? ($this->ring->publicKey() !== null && hash_equals(KeyRing::id($this->ring->publicKey(), true), $id))
                : $this->ring->symmetricById($id) !== null;
            if (!$known) throw new RuntimeException('The file belongs to another key (key ID ' . $id . ').');
            if (($header['mode'] ?? '') !== 'sealed') $this->decryptHeadV2($path); // proves the key really fits
            return $kind;
        }
        $head = $this->oldFormatCipher($path)->decryptHead($path, 1024);
        if (strlen($head) >= 262 && substr($head, 257, 5) === 'ustar') return 'files';
        if (stripos($head, 'dump') !== false || stripos($head, 'CREATE TABLE') !== false || stripos($head, 'INSERT INTO') !== false || str_starts_with($head, '/*')) return 'db';
        throw new RuntimeException('Content not recognized: neither a database dump nor a file archive.');
    }

    private function decryptHeadV2(string $path): void
    {
        $h = fopen($path, 'rb');
        try {
            [$header, $prefix] = self::parseHeader($h);
            $ss = self::readFull($h, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            $len = unpack('N', self::readFull($h, 4))[1] ?? 0;
            if ($len < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $len > self::MAX_FRAME) throw new RuntimeException('Backup file is damaged.');
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($ss, $this->keyFor($header));
            if (sodium_crypto_secretstream_xchacha20poly1305_pull($state, self::readFull($h, $len), hash('sha256', $prefix, true)) === false) {
                throw new RuntimeException('The file cannot be decrypted with the available key.');
            }
        } finally {
            fclose($h);
        }
    }

    // ------------------------------------------------------------------------------
    // I/O helpers
    // ------------------------------------------------------------------------------

    private static function readFull($stream, int $length): string
    {
        $buffer = '';
        while (strlen($buffer) < $length && !feof($stream)) {
            $part = fread($stream, $length - strlen($buffer));
            if ($part === false) throw new RuntimeException('Read error in the input stream.');
            if ($part === '') {
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
            if ($n === false || $n === 0) throw new RuntimeException('Write error (disk full or receiving process stopped?).');
            $written += $n;
        }
    }
}
