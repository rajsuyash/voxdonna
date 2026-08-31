<?php
/**
 * Discovery-call qualification gate.
 * The #contact form on index.html POSTs JSON here. We validate, score, log to
 * .qualify-leads.jsonl and email the lead. The booking URL is only returned when
 * the lead clears the threshold — it is never in the page source, so the gate
 * cannot be skipped by reading the HTML.
 *
 * .env (web root):
 *   BOOKING_URL=https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent
 *   LEAD_EMAIL=hello@voxdonna.com
 */

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
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

$env         = load_env(__DIR__ . '/.env');
$booking_url = $env['BOOKING_URL'] ?? 'https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent';
$lead_email  = $env['LEAD_EMAIL'] ?? 'hello@voxdonna.com';
$log_file    = __DIR__ . '/.qualify-leads.jsonl';

// Score at or above this books a call. Below it gets an email follow-up instead.
const QUALIFY_THRESHOLD = 45;

$raw = file_get_contents('php://input');
if (strlen($raw) > 20000) {
    http_response_code(413);
    echo json_encode(['ok' => false, 'error' => 'payload_too_large']);
    exit;
}
$in = json_decode($raw, true);
if (!is_array($in)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'bad_json']);
    exit;
}

// Honeypot: bots fill every field. Humans never see this one.
if (trim((string)($in['website'] ?? '')) !== '') {
    echo json_encode(['ok' => true, 'qualified' => false, 'message' => 'received']);
    exit;
}

$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Rate limit: 5 submissions per IP per hour, counted off the log tail.
if (file_exists($log_file)) {
    $recent = 0;
    $lines  = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach (array_slice($lines, -200) as $line) {
        $row = json_decode($line, true);
        if (!$row) continue;
        if (($row['ip'] ?? '') === $ip && strtotime($row['ts'] ?? '') > time() - 3600) $recent++;
    }
    if ($recent >= 5) {
        http_response_code(429);
        echo json_encode(['ok' => false, 'error' => 'rate_limited']);
        exit;
    }
}

function field($in, $key, $max = 300) {
    $v = trim((string)($in[$key] ?? ''));
    $v = preg_replace('/[\r\n]+/', ' ', $v);
    return mb_substr($v, 0, $max);
}

$lead = [
    'name'         => field($in, 'name', 120),
    'email'        => field($in, 'email', 160),
    'phone'        => field($in, 'phone', 40),
    'company'      => field($in, 'company', 160),
    'title'        => field($in, 'title', 120),
    'company_size' => field($in, 'company_size', 40),
    'problem'      => mb_substr(trim((string)($in['problem'] ?? '')), 0, 2000),
    'volume'       => field($in, 'volume', 40),
    'timeline'     => field($in, 'timeline', 40),
    'budget'       => field($in, 'budget', 40),
    'authority'    => field($in, 'authority', 40),
    'source'       => field($in, 'source', 200),
];

$errors = [];
foreach (['name', 'email', 'phone', 'company', 'title', 'company_size', 'volume', 'timeline', 'budget', 'authority'] as $req) {
    if ($lead[$req] === '') $errors[] = $req;
}
if (!filter_var($lead['email'], FILTER_VALIDATE_EMAIL)) $errors[] = 'email';
if (mb_strlen(preg_replace('/\D/', '', $lead['phone'])) < 7) $errors[] = 'phone';
if (mb_strlen($lead['problem']) < 20) $errors[] = 'problem';

if ($errors) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'validation', 'fields' => array_values(array_unique($errors))]);
    exit;
}

// ─── Scoring ───
$points = [
    'authority'    => ['decide' => 25, 'influence' => 18, 'researching' => 5],
    'timeline'     => ['now' => 25, 'quarter' => 18, 'sixmonths' => 8, 'exploring' => 2],
    'budget'       => ['10k+' => 25, '2k-10k' => 22, '500-2k' => 15, 'under-500' => 3, 'unsure' => 8],
    'company_size' => ['1000+' => 15, '201-1000' => 13, '51-200' => 10, '11-50' => 6, '1-10' => 2],
    'volume'       => ['10k+' => 10, '2k-10k' => 9, '500-2k' => 6, 'under-500' => 2, 'unsure' => 4],
];

$score = 0;
foreach ($points as $key => $map) {
    $score += $map[$lead[$key]] ?? 0;
}

// Free mailbox on a "company" enquiry is a weak signal, not a disqualifier.
$free_domains = ['gmail.com', 'yahoo.com', 'yahoo.co.in', 'hotmail.com', 'outlook.com', 'live.com', 'rediffmail.com', 'aol.com', 'icloud.com', 'proton.me', 'protonmail.com'];
$domain = strtolower(substr(strrchr($lead['email'], '@'), 1));
$is_free_email = in_array($domain, $free_domains, true);
if ($is_free_email) $score -= 8;

$qualified = $score >= QUALIFY_THRESHOLD;

$record = $lead + [
    'ts'        => date('c'),
    'ip'        => $ip,
    'score'     => $score,
    'qualified' => $qualified,
    'free_email'=> $is_free_email,
    'referrer'  => mb_substr((string)($_SERVER['HTTP_REFERER'] ?? ''), 0, 300),
];
@file_put_contents($log_file, json_encode($record, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);

$tag  = $qualified ? 'QUALIFIED' : 'low-fit';
$subject = "[$tag $score] Discovery request: {$lead['company']} — {$lead['name']}";
$body  = "Discovery-call request\n======================\n";
$body .= "Score: $score/100  ($tag, threshold " . QUALIFY_THRESHOLD . ")\n";
$body .= "When: " . date('r') . "\n\n";
foreach ($lead as $k => $v) {
    if ($v === '' || $k === 'problem') continue;
    $body .= str_pad(ucwords(str_replace('_', ' ', $k)) . ':', 16) . $v . "\n";
}
if ($is_free_email) $body .= "\nNote: personal email domain ($domain)\n";
$body .= "\nProblem they want to solve\n--------------------------\n{$lead['problem']}\n";

$headers  = "From: leads@voxdonna.com\r\n";
$headers .= 'Reply-To: ' . preg_replace('/[^\x21-\x7e]/', '', $lead['email']) . "\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8";
@mail($lead_email, $subject, $body, $headers);

$response = ['ok' => true, 'qualified' => $qualified];
if ($qualified) {
    $response['booking_url'] = $booking_url
        . (strpos($booking_url, '?') === false ? '?' : '&')
        . http_build_query(['name' => $lead['name'], 'email' => $lead['email']]);
}
echo json_encode($response);
