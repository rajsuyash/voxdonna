<?php
/**
 * Token mint for the Joyalukkas birthday demo (Anya) — SECOND Cartesia account.
 * Reads CARTESIA_API_KEY_2 + JOY_AGENT_ID from .env. Locked to the one agent;
 * no hardcoded key fallback (fail closed).
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
$api_key  = $env['CARTESIA_API_KEY_2'] ?? '';
$agent_id = $env['JOY_AGENT_ID'] ?? '';   // default: Joyalukkas Amit

// Account-2 demo agents this endpoint may mint for (Joyalukkas Amit, Surya Ghar Suraj).
$allowed = array_filter([
    $env['JOY_AGENT_ID'] ?? null,
    $env['SURYA_AGENT_ID'] ?? null,
]);
$body = json_decode(file_get_contents('php://input'), true) ?: [];
$requested = $body['agentId'] ?? $body['agent_id'] ?? null;
if ($requested !== null && in_array($requested, $allowed, true)) {
    $agent_id = $requested;
}

if (empty($api_key) || empty($agent_id) || (($env['JOY_DEMO_ENABLED'] ?? 'true') === 'false')) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'not_configured']);
    exit;
}

// Rate limit: 10 tokens per IP per 5 minutes
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ip = explode(',', $ip)[0];
$cache_key = sys_get_temp_dir() . '/joy_rl_' . md5($ip);
$now = time();
$attempts = [];
if (file_exists($cache_key)) $attempts = json_decode(file_get_contents($cache_key), true) ?: [];
$attempts = array_values(array_filter($attempts, fn($t) => $t > $now - 300));
if (count($attempts) >= 10) {
    http_response_code(429);
    echo json_encode(['ok' => false, 'error' => 'rate_limited']);
    exit;
}
$attempts[] = $now;
file_put_contents($cache_key, json_encode($attempts));

$ch = curl_init('https://api.cartesia.ai/access-token');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $api_key,
        'Cartesia-Version: 2025-04-16',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'grants' => ['tts' => true, 'stt' => true, 'agent' => true],
        'expires_in' => 300,
    ]),
    CURLOPT_TIMEOUT => 10,
]);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($http_code !== 200) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'mint_failed', 'upstream' => $http_code]);
    exit;
}

$data = json_decode($response, true);
$token = $data['token'] ?? $data['access_token'] ?? null;
if (!$token) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'no_token']);
    exit;
}

echo json_encode([
    'ok' => true,
    'token' => $token,
    'agentId' => $agent_id,
    'version' => '2025-04-16',
]);
