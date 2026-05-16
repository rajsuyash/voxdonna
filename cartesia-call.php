<?php
/**
 * Cartesia outbound call endpoint.
 * Visitor enters their phone number; we trigger Cartesia to dial them
 * and the Joyalukkas Aanya agent picks up. Showcases real outbound.
 *
 * Frontend: POST /cartesia-call.php { phone: "+919999999999", name: "Rajesh" }
 * Returns: { ok: true } — phone rings within 5-10 seconds.
 */

header('Access-Control-Allow-Origin: https://voxdonna.com');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
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
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1]);
    }
    return $env;
}

$env = load_env(__DIR__ . '/.env');
// DEMO KEY — rotate after first prod use. Falls back to .env if present.
$api_key = $env['CARTESIA_API_KEY'] ?? 'sk_car_2aSWZx7bJjQ61euPsUCATn';
$agent_id = $env['CARTESIA_AGENT_ID'] ?? 'agent_3B8vgGssvCWT2EKfqJeCm4';

if (empty($api_key)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'not_configured']);
    exit;
}

// Parse + validate phone
$raw = file_get_contents('php://input');
$body = json_decode($raw, true) ?: [];
$phone = trim($body['phone'] ?? '');
$name = trim($body['name'] ?? 'दोस्त');

// Strict E.164 validation — only India + a few partners for now
if (!preg_match('/^\+(91|1|44|971)[0-9]{7,12}$/', $phone)) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'invalid_phone',
        'message' => 'Please enter a valid international phone number with country code (e.g. +919999999999).'
    ]);
    exit;
}

// Rate limit: 2 calls per IP per 24h
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$cache_key = sys_get_temp_dir() . '/cart_call_' . md5($ip);
$now = time();
$window = 86400;
$max_calls = 2;

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
        'error' => 'rate_limited',
        'message' => 'You have reached the demo call limit. Please try again tomorrow.'
    ]);
    exit;
}

// Place the outbound call
$ch = curl_init('https://api.cartesia.ai/twilio/call/outbound');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'X-API-Key: ' . $api_key,
        'Cartesia-Version: 2025-04-16',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'target_numbers' => [$phone],
        'agent_id' => $agent_id,
        'metadata' => [
            'source' => 'voxdonna_web_demo',
            'customer_name' => $name,
            'campaign' => 'joyalukkas_demo',
        ],
    ]),
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
        'error' => 'cartesia_error',
        'upstream_status' => $http_code,
        'message' => 'Could not place call right now. Please try again in a moment.',
        'debug' => substr((string)$response, 0, 400) ?: $curl_err,
    ]);
    exit;
}

// Record success
$attempts[] = $now;
file_put_contents($cache_key, json_encode($attempts));

echo json_encode([
    'ok' => true,
    'message' => 'Calling you now. The phone should ring within 10 seconds.',
]);
