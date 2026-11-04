<?php
declare(strict_types=1);

namespace Bakkuappu\Support;

use RuntimeException;

/**
 * Runs an external command and connects one end as a stream:
 *  - mode "read":  the command's stdout is available as $this->stream (tar -c, mariadb-dump)
 *  - mode "write": the command's stdin is available as $this->stream (tar -x, mariadb client)
 *
 * Other output goes into a temporary file instead of a second pipe: a pipe that is only read
 * at the end can fill up (e.g. many tar warnings) and block both processes.
 */
final class Process
{
    /** @var resource */
    private $process;
    /** @var resource|null */
    public $stream;
    /** Kept for callers of 1.1.0 (read mode) */
    public $stdout;
    private string $logFile;
    private string $mode;

    /**
     * @param list<string> $command Program and arguments; no shell is involved.
     */
    public function __construct(array $command, string $tmpDir, string $mode = 'read')
    {
        $this->mode = $mode;
        $log = tempnam($tmpDir, 'bkp-err-');
        if ($log === false) {
            throw new RuntimeException('Temporary file for the error output could not be created.');
        }
        $this->logFile = $log;

        if ($mode === 'write') {
            $spec = [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']];
        } else {
            // stdin is a pipe that is closed right away (no /dev/null: blocked by some open_basedir setups)
            $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $log, 'a']];
        }

        $process = proc_open($command, $spec, $pipes);
        if (!is_resource($process)) {
            @unlink($log);
            throw new RuntimeException('Process could not be started: ' . $command[0]);
        }
        $this->process = $process;

        if ($mode === 'write') {
            $this->stream = $pipes[0];
        } else {
            fclose($pipes[0]);
            $this->stream = $pipes[1];
            $this->stdout = $pipes[1];
        }
    }

    /**
     * Closes the stream, waits for the process and returns [exit code, collected output].
     *
     * @return array{0:int,1:string}
     */
    public function finish(): array
    {
        if (is_resource($this->stream)) {
            if ($this->mode === 'read') {
                // Drain anything left so the process can exit
                while (!feof($this->stream) && fread($this->stream, 65536) !== false) {
                }
            }
            fclose($this->stream);
        }
        $this->stream = null;
        $this->stdout = null;
        $code = proc_close($this->process);
        $size = (int) @filesize($this->logFile);
        // Keep the end of long outputs: the error is usually at the bottom
        $err = (string) @file_get_contents($this->logFile, false, null, max(0, $size - 8192));
        @unlink($this->logFile);
        return [$code, trim($err)];
    }

    /**
     * Finds an executable in PATH. Uses the shell ("command -v") because file checks on
     * /usr/bin fail under a restrictive open_basedir, while running the program still works.
     */
    public static function which(string $name): ?string
    {
        if (!function_exists('exec')) return null;
        $out = [];
        $code = 1;
        @exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null', $out, $code);
        return ($code === 0 && !empty($out[0])) ? trim($out[0]) : null;
    }
}
