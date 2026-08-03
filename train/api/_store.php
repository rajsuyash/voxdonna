<?php
// Shared flat-file store for the training portal.
// Hostinger shared hosting: no daemons, no database — JSON files under a
// directory that sits OUTSIDE every webroot, guarded by flock.

declare(strict_types=1);

// Helpers only — refuse to run as an endpoint even if the webserver config that
// blocks it is ever lost.
if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    http_response_code(403);
    exit("forbidden\n");
}

const MAX_BODY_BYTES     = 24576;
const MAX_TRAINEES_PER_ORG = 2000;
const MAX_DONE_ENTRIES     = 400;   // ~62 lesson ids per curriculum, with headroom
const RATE_WINDOW_SECONDS  = 60;
const RATE_MAX_REQUESTS    = 30;

/**
 * Resolve the data directory. It must never be reachable over HTTP, so we
 * anchor it above `public_html` when deployed and above the served `train/`
 * directory when running locally.
 */
function data_dir(): string {
    $here = str_replace('\\', '/', __DIR__);
    $pos  = strrpos($here, '/public_html');
    $dir  = $pos !== false
        ? substr($here, 0, $pos) . '/train-data'
        : dirname(__DIR__, 2) . '/train-data';

    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir;
}

function json_out(array $payload, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode($payload);
    exit;
}

function fail(string $message, int $status = 400): void {
    json_out(['ok' => false, 'error' => $message], $status);
}

/** Read a JSON file, returning [] when absent or unparseable. */
function read_json(string $path): array {
    if (!is_readable($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

/**
 * Read-modify-write under an exclusive lock. $mutator receives the current
 * contents and returns what should be written.
 */
function mutate_json(string $path, callable $mutator) {
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        fail('store unavailable', 500);
    }
    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        fail('store busy', 503);
    }

    $raw     = stream_get_contents($handle);
    $current = is_string($raw) && $raw !== '' ? json_decode($raw, true) : [];
    if (!is_array($current)) {
        $current = [];
    }

    $result = $mutator($current);
    $next   = is_array($result) ? $result : $current;

    ftruncate($handle, 0);
    rewind($handle);
    fwrite($handle, json_encode($next, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);
    @chmod($path, 0600);

    return $result;
}

/** Fixed-window per-IP throttle shared by every endpoint. */
function rate_limit(string $bucket): void {
    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = $bucket . '|' . $ip;
    $now = time();

    $over = false;

    mutate_json(data_dir() . '/ratelimit.json', function (array $hits) use ($key, $now, &$over) {
        foreach ($hits as $k => $seen) {
            if (($seen['start'] ?? 0) < $now - RATE_WINDOW_SECONDS * 5) {
                unset($hits[$k]);
            }
        }
        $entry = $hits[$key] ?? ['start' => $now, 'n' => 0];
        if (($entry['start'] ?? 0) < $now - RATE_WINDOW_SECONDS) {
            $entry = ['start' => $now, 'n' => 0];
        }
        $entry['n']++;
        $hits[$key] = $entry;
        $over = $entry['n'] > RATE_MAX_REQUESTS;
        return $hits;
    });

    if ($over) {
        fail('too many requests', 429);
    }
}

/** A slug is valid only if it names a real org config in the webroot. */
function valid_org(?string $slug): ?string {
    if (!is_string($slug) || !preg_match('/^[a-z0-9-]{1,40}$/', $slug)) {
        return null;
    }
    $config = __DIR__ . '/../orgs/' . $slug . '.json';
    $real   = realpath($config);
    $base   = realpath(__DIR__ . '/../orgs');
    if ($real === false || $base === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) {
        return null;
    }
    return $slug;
}

function org_company(string $slug): string {
    $config = read_json(__DIR__ . '/../orgs/' . $slug . '.json');
    $name   = $config['companyName'] ?? $slug;
    return is_string($name) ? clean_text($name, 120) : $slug;
}

/** Strip control characters and clamp length. */
function clean_text($value, int $max): string {
    if (!is_string($value)) {
        return '';
    }
    $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '';
    $value = trim($value);
    return mb_substr($value, 0, $max);
}

function read_body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false) {
        fail('empty body');
    }
    if (strlen($raw) > MAX_BODY_BYTES) {
        fail('payload too large', 413);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fail('malformed json');
    }
    return $data;
}
