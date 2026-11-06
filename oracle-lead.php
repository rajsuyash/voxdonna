<?php
/**
 * "Ask Donna" homepage hero lead endpoint.
 * hero.js POSTs {lead:{name,email,company,website,industry,problem,volume}, hp:""}
 * once the voice intake finishes. We validate, log to .oracle-leads.jsonl and
 * email the team. Same shape as qualify.php; no secrets needed.
 *
 * .env (web root, optional): LEAD_EMAIL=hello@voxdonna.com
 */

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function reply(int $code, array $body): void {
    http_response_code($code);
    echo json_encode($body);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    reply(405, ['ok' => false, 'error' => 'method_not_allowed']);
}

function load_env($path) {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1], " \t\"'");
    }
    return $env;
}

const MAX_BODY_BYTES = 20000;
const RATE_LIMIT_PER_HOUR = 5;

$env        = load_env(__DIR__ . '/.env');
$lead_email = $env['LEAD_EMAIL'] ?? 'hello@voxdonna.com';
$log_file   = __DIR__ . '/.oracle-leads.jsonl';

$raw = file_get_contents('php://input');
if (strlen($raw) > MAX_BODY_BYTES) reply(413, ['ok' => false, 'error' => 'payload_too_large']);

$in = json_decode($raw, true);
if (!is_array($in)) reply(400, ['ok' => false, 'error' => 'bad_json']);

// Honeypot: bots fill every field. hero.js always sends "".
if (trim((string)($in['hp'] ?? '')) !== '') reply(200, ['ok' => true]);

$src = is_array($in['lead'] ?? null) ? $in['lead'] : null;
if ($src === null) reply(400, ['ok' => false, 'error' => 'validation', 'fields' => ['lead']]);

// Single-line fields: strip CR/LF so nothing can reach a mail header.
function field(array $in, string $key, int $max): string {
    $v = $in[$key] ?? '';
    $v = is_string($v) ? trim($v) : '';
    $v = preg_replace('/[\r\n]+/', ' ', $v);
    return mb_substr($v, 0, $max);
}

$lead = [
    'name'     => field($src, 'name', 120),
    'email'    => field($src, 'email', 160),
    'company'  => field($src, 'company', 160),
    'website'  => field($src, 'website', 200),
    'industry' => field($src, 'industry', 120),
    'volume'   => field($src, 'volume', 80),
    'problem'  => mb_substr(is_string($src['problem'] ?? null) ? trim($src['problem']) : '', 0, 2000),
];

// Optional next-step choice from the end of intake; keep only known values, in a fixed order.
$next = [];
if (is_array($in['next'] ?? null)) {
    foreach (['plan', 'demo', 'call'] as $step) {
        if (in_array($step, $in['next'], true)) $next[] = $step;
    }
}

$errors = [];
if ($lead['name'] === '') $errors[] = 'name';
if (!filter_var($lead['email'], FILTER_VALIDATE_EMAIL)) $errors[] = 'email';
if ($lead['problem'] === '') $errors[] = 'problem';
if ($errors) reply(400, ['ok' => false, 'error' => 'validation', 'fields' => $errors]);

$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Rate limit: counted off the log tail, as qualify.php does.
if (file_exists($log_file)) {
    $recent = 0;
    $lines  = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach (array_slice($lines, -200) as $line) {
        $row = json_decode($line, true);
        if (!$row) continue;
        if (($row['ip'] ?? '') === $ip && strtotime($row['ts'] ?? '') > time() - 3600) $recent++;
    }
    if ($recent >= RATE_LIMIT_PER_HOUR) reply(429, ['ok' => false, 'error' => 'rate_limited']);
}

$record = $lead + ['next' => $next] + [
    'ts'       => date('c'),
    'ip'       => $ip,
    'referrer' => mb_substr((string)($_SERVER['HTTP_REFERER'] ?? ''), 0, 300),
];
if (@file_put_contents($log_file, json_encode($record, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX) === false) {
    reply(500, ['ok' => false, 'error' => 'store_failed']);
}

$who     = $lead['company'] !== '' ? $lead['company'] : 'no company given';
$tag     = $next ? 'Ask Donna · ' . implode('+', $next) : 'Ask Donna';
$subject = "[{$tag}] {$who} — {$lead['name']}";
$body    = "Ask Donna lead (homepage voice intake)\n=======================================\n";
$body   .= 'When: ' . date('r') . "\n\n";
foreach ($lead as $k => $v) {
    if ($v === '' || $k === 'problem') continue;
    $body .= str_pad(ucfirst($k) . ':', 11) . $v . "\n";
}
$body .= "\nProblem, in their words\n-----------------------\n{$lead['problem']}\n";
$body .= "\nVisitor chose: " . ($next ? implode(', ', $next) : 'not recorded') . "\n";
if (in_array('plan', $next, true)) $body .= "Plan email goes out automatically from the relay.\n";
if (in_array('call', $next, true)) $body .= "They were sent to the booking page; expect a TidyCal booking.\n";
if (in_array('demo', $next, true)) $body .= "They were sent to the demo gallery.\n";

$headers  = "From: leads@voxdonna.com\r\n";
$headers .= 'Reply-To: ' . preg_replace('/[^\x21-\x7e]/', '', $lead['email']) . "\r\n";
$headers .= 'Content-Type: text/plain; charset=UTF-8';
// Mail can fail on the host; the lead is already on disk.
@mail($lead_email, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers);

reply(200, ['ok' => true]);
