<?php
declare(strict_types=1);

/**
 * Shared helpers for the VoxDonna Video Ads Manager signup/checkout/admin
 * endpoints (video-ads-subscribe.php, video-ads-confirm.php,
 * video-ads-admin.php). Follows the patterns already in this repo:
 *   - load_env() style from whatsapp-confirm.php
 *   - data dir resolved OUTSIDE public_html, like train/api/_store.php
 *   - the "refuse to run as an endpoint" guard from train/api/_store.php
 *
 * Storage: a single SQLite file, data_dir()/subscribers.sqlite.
 */

// Helper-only file — refuse to run as an endpoint even if .htaccess ever
// fails to block it (see the matching -lib.php deny rule in .htaccess).
if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo '{"ok":false,"error":"forbidden"}';
    exit;
}

const VIDEO_ADS_TOTAL_COUNT = 120; // Razorpay subscription cycle cap (10 years of monthly billing).

/** Read KEY=VALUE pairs from .env next to this file. Missing file -> []. */
function va_load_env(): array {
    $path = __DIR__ . '/.env';
    $env = [];
    if (!file_exists($path)) {
        return $env;
    }
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $env[trim($parts[0])] = trim($parts[1], " \t\"'");
        }
    }
    return $env;
}

/**
 * Data directory outside the served tree, mirroring train/api/_store.php's
 * data_dir(): anchored above public_html when deployed, above the repo
 * checkout when running locally.
 */
function va_data_dir(): string {
    $here = str_replace('\\', '/', __DIR__);
    $pos  = strrpos($here, '/public_html');
    $dir  = $pos !== false
        ? substr($here, 0, $pos) . '/video-ads-data'
        : dirname($here) . '/video-ads-data';

    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir;
}

/** Fail with a safe JSON error. Detail stays out of the response, logged separately by the caller. */
function va_fail(int $status, string $error, array $extra = []): void {
    http_response_code($status);
    echo json_encode(['ok' => false, 'error' => $error] + $extra);
    exit;
}

/** 503 (never fatal) when a required .env key is missing. */
function va_require_env(array $env, array $keys): void {
    foreach ($keys as $key) {
        if (empty($env[$key])) {
            va_fail(503, 'not_configured');
        }
    }
}

/** Open (creating if needed) the SQLite store and ensure the schema exists. */
function va_db(string $dir): PDO {
    $pdo = new PDO('sqlite:' . $dir . '/subscribers.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=5000');
    va_init_schema($pdo);
    return $pdo;
}

function va_init_schema(PDO $pdo): void {
    $pdo->exec('CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        business_name TEXT NOT NULL,
        contact_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        city TEXT NOT NULL,
        social TEXT,
        subscription_id TEXT UNIQUE,
        status TEXT NOT NULL DEFAULT "created",
        payment_id TEXT,
        paid_at TEXT,
        thank_you_claimed_at TEXT,
        thank_you_sent_at TEXT,
        ip TEXT
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS rate_limits (
        bucket TEXT NOT NULL,
        ip TEXT NOT NULL,
        ts INTEGER NOT NULL
    )');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_rate_limits_bucket_ip_ts ON rate_limits(bucket, ip, ts)');
}

/** Fixed-window per-IP rate limit, e.g. 5 requests per 600s. Returns false when over. */
function va_rate_limit_ok(PDO $pdo, string $bucket, string $ip, int $max, int $windowSeconds): bool {
    $now    = time();
    $cutoff = $now - $windowSeconds;
    $pdo->prepare('DELETE FROM rate_limits WHERE bucket = :b AND ts < :cutoff')
        ->execute([':b' => $bucket, ':cutoff' => $cutoff]);
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM rate_limits WHERE bucket = :b AND ip = :ip AND ts >= :cutoff');
    $stmt->execute([':b' => $bucket, ':ip' => $ip, ':cutoff' => $cutoff]);
    if ((int)$stmt->fetchColumn() >= $max) {
        return false;
    }
    $pdo->prepare('INSERT INTO rate_limits (bucket, ip, ts) VALUES (:b, :ip, :ts)')
        ->execute([':b' => $bucket, ':ip' => $ip, ':ts' => $now]);
    return true;
}

/** Strip control characters and clamp length (same approach as train/api/_store.php clean_text). */
function va_clean_text($value, int $max): string {
    if (!is_string($value)) {
        return '';
    }
    $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '';
    $value = trim($value);
    return mb_substr($value, 0, $max);
}

/**
 * Normalise an Indian mobile number to +91XXXXXXXXXX. Accepts a bare
 * 10-digit mobile, 91-prefixed, or +91-prefixed. Anything else -> null,
 * rather than guessing a country code (same posture as whatsapp-confirm.php).
 */
function va_normalize_indian_mobile(string $raw): ?string {
    $digits = preg_replace('/[^\d]/', '', $raw) ?? '';
    if (preg_match('/^[6-9]\d{9}$/', $digits)) {
        return '+91' . $digits;
    }
    if (preg_match('/^91[6-9]\d{9}$/', $digits)) {
        return '+' . $digits;
    }
    return null;
}

/**
 * Validate + clean a signup payload. Returns [errors, cleaned]. cleaned is
 * always safe to use even when errors is non-empty (never null fields).
 */
function va_validate_signup(array $body): array {
    $errors = [];

    $businessName = va_clean_text($body['business_name'] ?? '', 120);
    $contactName  = va_clean_text($body['contact_name'] ?? '', 120);
    $city         = va_clean_text($body['city'] ?? '', 80);
    $social       = va_clean_text($body['social'] ?? '', 200);
    $email        = trim((string)($body['email'] ?? ''));
    $phoneRaw     = trim((string)($body['phone'] ?? ''));

    if ($businessName === '') {
        $errors[] = 'business_name required';
    }
    if ($contactName === '') {
        $errors[] = 'contact_name required';
    }
    if ($city === '') {
        $errors[] = 'city required';
    }
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'valid email required';
    }
    $phone = va_normalize_indian_mobile($phoneRaw);
    if ($phone === null) {
        $errors[] = 'valid Indian mobile required';
    }

    return [$errors, [
        'business_name' => $businessName,
        'contact_name'  => $contactName,
        'email'         => $email,
        'phone'         => $phone ?? '',
        'city'          => $city,
        'social'        => $social,
    ]];
}

/** Razorpay signature check: hmac_sha256(payment_id|subscription_id, key_secret). */
function va_verify_signature(string $paymentId, string $subscriptionId, string $secret, string $signature): bool {
    $expected = hash_hmac('sha256', $paymentId . '|' . $subscriptionId, $secret);
    return hash_equals($expected, $signature);
}

/**
 * Basic-auth JSON request to the Razorpay API. Returns [httpCode, decodedBodyOrNull].
 * httpCode 0 means the request itself failed (network/curl error, logged here).
 */
function va_razorpay_request(string $method, string $path, array $env, ?array $body = null): array {
    $ch = curl_init('https://api.razorpay.com/v1' . $path);
    $opts = [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_USERPWD        => $env['RAZORPAY_KEY_ID'] . ':' . $env['RAZORPAY_KEY_SECRET'],
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    ];
    if ($body !== null) {
        $opts[CURLOPT_POSTFIELDS] = json_encode($body);
    }
    curl_setopt_array($ch, $opts);
    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    // No curl_close(): deprecated as a no-op since PHP 8.0 (the handle is
    // freed when $ch goes out of scope), and calling it anyway throws a
    // deprecation notice that — with display_errors on — prepends HTML to
    // this JSON response and breaks every client-side JSON.parse().

    if ($resp === false) {
        error_log('video-ads: razorpay request failed (' . $method . ' ' . $path . '): ' . $err);
        return [0, null];
    }
    return [$code, json_decode((string)$resp, true)];
}

/** POST to Resend. Returns true on 2xx. Swapped out in tests via the $http param. */
function va_send_resend_email(array $env, string $to, string $subject, string $html, string $text, ?callable $http = null): bool {
    $http = $http ?? 'va_resend_http_post';
    [$code] = $http($env['RESEND_API_KEY'], [
        'from'     => 'VoxDonna <hello@send.voxdonna.com>',
        'reply_to' => 'hello@voxdonna.com',
        'to'       => [$to],
        'subject'  => $subject,
        'html'     => $html,
        'text'     => $text,
    ]);
    return $code >= 200 && $code < 300;
}

function va_resend_http_post(string $apiKey, array $payload): array {
    $ch = curl_init('https://api.resend.com/emails');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Authorization: Bearer ' . $apiKey],
        CURLOPT_POSTFIELDS     => json_encode($payload),
    ]);
    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    // See the comment in va_razorpay_request(): curl_close() is a deprecated
    // no-op here and left out on purpose.
    return [$code, $resp];
}

/**
 * Build the thank-you email. Every subscriber-supplied value is escaped for
 * the HTML part; the text part carries the raw (already-cleaned) values,
 * which is safe because it is never rendered as markup.
 */
function va_thank_you_email(array $row): array {
    $name     = htmlspecialchars((string)$row['contact_name'], ENT_QUOTES, 'UTF-8');
    $business = htmlspecialchars((string)$row['business_name'], ENT_QUOTES, 'UTF-8');

    $subject = 'VoxDonna Video Ads — you are in';

    $html = "<div style=\"font-family:Arial,sans-serif;color:#1a1a1a;line-height:1.6;max-width:560px\">"
        . "<p>Hi {$name},</p>"
        . "<p><strong>{$business}</strong> is now on VoxDonna Video Ads Manager. Two video ads a month, ready to post.</p>"
        . "<p>What happens next: we will reach out within 1 business day for your brief and product photos. "
        . "Send us what you want featured and any notes on tone; we script, produce and revise from there.</p>"
        . "<p>You can manage or cancel the subscription any time through the Razorpay payment link in your confirmation email.</p>"
        . "<p>Thanks,<br>VoxDonna</p>"
        . "</div>";

    $textName     = (string)$row['contact_name'];
    $textBusiness = (string)$row['business_name'];
    $text = "Hi {$textName},\n\n"
        . "{$textBusiness} is now on VoxDonna Video Ads Manager. Two video ads a month, ready to post.\n\n"
        . "What happens next: we will reach out within 1 business day for your brief and product photos. "
        . "Send us what you want featured and any notes on tone; we script, produce and revise from there.\n\n"
        . "You can manage or cancel the subscription any time through the Razorpay payment link in your confirmation email.\n\n"
        . "Thanks,\nVoxDonna";

    return [$subject, $html, $text];
}

/**
 * Atomically claim the right to send the thank-you email, then send it.
 * Returns "sent", "skipped" (already claimed/sent — the idempotent path for
 * a repeat confirm call), or "failed" (claim taken, send failed, claim
 * cleared so a later retry can try again).
 */
function va_claim_and_send_thank_you(PDO $pdo, array $row, callable $sendFn): string {
    $now = gmdate('Y-m-d H:i:s');
    $stmt = $pdo->prepare(
        'UPDATE subscribers SET thank_you_claimed_at = :now
         WHERE id = :id AND thank_you_sent_at IS NULL AND thank_you_claimed_at IS NULL'
    );
    $stmt->execute([':now' => $now, ':id' => $row['id']]);
    if ($stmt->rowCount() !== 1) {
        return 'skipped';
    }

    $ok = false;
    try {
        $ok = (bool)$sendFn($row);
    } catch (Throwable $e) {
        error_log('video-ads: thank-you send threw for subscriber ' . $row['id'] . ': ' . $e->getMessage());
        $ok = false;
    }

    if ($ok) {
        $pdo->prepare('UPDATE subscribers SET thank_you_sent_at = :now WHERE id = :id')
            ->execute([':now' => gmdate('Y-m-d H:i:s'), ':id' => $row['id']]);
        return 'sent';
    }

    $pdo->prepare('UPDATE subscribers SET thank_you_claimed_at = NULL WHERE id = :id')
        ->execute([':id' => $row['id']]);
    error_log('video-ads: thank-you email send failed for subscriber ' . $row['id']);
    return 'failed';
}
