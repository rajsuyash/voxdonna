<?php
/**
 * Cartesia outbound call endpoint for Joyalukkas Aanya demo.
 * Visitor enters their phone number → Cartesia dials them, Aanya picks up.
 *
 * POST /voice-call.php { phone: "+919999999999", name: "Rajesh" }
 * Returns: { ok: true, callId, masked, eta }
 *
 * Gate stack (in order):
 *  1. Operator kill switch (CARTESIA_DEMO_ENABLED=false → 503)
 *  2. Schema validation (E.164 phone, name length)
 *  3. TRAI calling-hours gate (+91 numbers only call between 09:00-21:00 IST)
 *  4. IP rate limit (1 call per IP per 10 minutes)
 *  5. Trigger Cartesia outbound API
 */

header('Access-Control-Allow-Origin: https://voxdonna.com');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'method_not_allowed']);
    exit;
}

function load_env($path) {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1]);
    }
    return $env;
}

function mask_phone($phone) {
    if (strlen($phone) <= 7) return $phone;
    $last4 = substr($phone, -4);
    $prefix = substr($phone, 0, 3);
    return $prefix . str_repeat('X', strlen($phone) - 7) . $last4;
}

function is_within_calling_hours_ist() {
    // TRAI mandate: commercial calls to +91 numbers only between 09:00-21:00 IST.
    // For non-IN destinations, this gate is skipped (caller's local rules apply).
    $tz = new DateTimeZone('Asia/Kolkata');
    $now = new DateTime('now', $tz);
    $hour = (int)$now->format('H');
    return $hour >= 9 && $hour < 21;
}

$env = load_env(__DIR__ . '/.env');
// DEMO KEY — rotate after first prod use. Falls back to .env if present.
$api_key = $env['CARTESIA_API_KEY'] ?? 'sk_car_2aSWZx7bJjQ61euPsUCATn';
$agent_id = $env['CARTESIA_AGENT_ID'] ?? 'agent_3B8vgGssvCWT2EKfqJeCm4';
$demo_enabled = ($env['CARTESIA_DEMO_ENABLED'] ?? 'true') !== 'false';

// 1. Operator kill switch
if (!$demo_enabled) {
    http_response_code(503);
    echo json_encode([
        'ok' => false,
        'message' => 'Demo is temporarily disabled. Please try again later.',
    ]);
    exit;
}

if (empty($api_key)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'message' => 'Demo not configured.']);
    exit;
}

// 2. Schema validation
$raw = file_get_contents('php://input');
$body = json_decode($raw, true) ?: [];
$phone = trim((string)($body['phone'] ?? ''));
$name = trim((string)($body['name'] ?? ''));

if (strlen($name) > 80) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'Name too long (max 80 chars).']);
    exit;
}

// Strict E.164 — only India, US, UK, UAE for demo
if (!preg_match('/^\+(91|1|44|971)[0-9]{7,12}$/', $phone)) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'message' => 'Please enter a valid international phone number with country code (e.g. +919999999999).',
    ]);
    exit;
}

// 3. TRAI calling-hours gate (applies to +91 only)
if (str_starts_with($phone, '+91') && !is_within_calling_hours_ist()) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'message' => 'Demo calls to Indian numbers operate 09:00-21:00 IST per TRAI rules. Please try during the day.',
    ]);
    exit;
}

// 4. IP rate limit: 1 call per IP per 10 minutes
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (strpos($ip, ',') !== false) $ip = trim(explode(',', $ip)[0]);
$cache_key = sys_get_temp_dir() . '/cart_call_' . md5($ip);
$now = time();
$window = 600; // 10 minutes
$max_calls = 1;

$attempts = [];
if (file_exists($cache_key)) {
    $raw_log = file_get_contents($cache_key);
    $attempts = json_decode($raw_log, true) ?: [];
}
$attempts = array_filter($attempts, fn($t) => $t > $now - $window);
if (count($attempts) >= $max_calls) {
    http_response_code(429);
    echo json_encode([
        'ok' => false,
        'message' => 'One demo call per IP every 10 minutes. Please wait a few minutes and try again.',
        'retryAfter' => $window - ($now - min($attempts)),
    ]);
    exit;
}

// 5. Trigger Cartesia outbound call
$payload = json_encode([
    'target_numbers' => [$phone],
    'agent_id' => $agent_id,
    'metadata' => [
        'source' => 'voxdonna_web_demo',
        'customer_name' => $name ?: null,
        'campaign' => 'joyalukkas_demo',
        'ts' => date('c'),
    ],
]);

$ch = curl_init('https://api.cartesia.ai/twilio/call/outbound');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $api_key,
        'Cartesia-Version: 2025-04-16',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_TIMEOUT => 15,
]);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_err = curl_error($ch);
curl_close($ch);

if ($http_code >= 400 || $http_code === 0) {
    http_response_code(502);
    echo json_encode([
        'ok' => false,
        'message' => 'Could not place call right now. Please try again in a moment.',
        'upstream_status' => $http_code,
        'debug' => substr((string)$response, 0, 300) ?: $curl_err,
    ]);
    exit;
}

$data = json_decode($response, true) ?: [];
$call_id = $data['call_id'] ?? $data['id'] ?? null;

// Record success
$attempts[] = $now;
file_put_contents($cache_key, json_encode($attempts));

echo json_encode([
    'ok' => true,
    'callId' => $call_id,
    'masked' => mask_phone($phone),
    'eta' => 'Your phone will ring within 10 seconds.',
]);
