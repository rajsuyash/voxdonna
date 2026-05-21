<?php
/**
 * Cartesia token mint endpoint.
 * Mints a short-lived (5 min) access token for browser WebRTC sessions.
 * Reads CARTESIA_API_KEY from .env (same root as the rest of the site).
 *
 * Frontend calls: POST /cartesia-token.php
 * Returns: {"ok":true,"token":"...","agentId":"..."}
 */

// CORS — allow voxdonna.com origin
header('Access-Control-Allow-Origin: https://voxdonna.com');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
}

// Load .env (simple parser — same dir as this file)
function load_env($path) {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $env[trim($parts[0])] = trim($parts[1]);
        }
    }
    return $env;
}

$env = load_env(__DIR__ . '/.env');
// DEMO KEY — rotate after first prod use. Falls back to .env if present.
$api_key = $env['CARTESIA_API_KEY'] ?? 'sk_car_2aSWZx7bJjQ61euPsUCATn';
$default_agent_id = $env['CARTESIA_AGENT_ID'] ?? 'agent_3B8vgGssvCWT2EKfqJeCm4';

// Whitelist of agent IDs this endpoint is allowed to mint tokens for.
// Tokens themselves are agent-agnostic (grants tts/stt/agent), but the
// client uses the returned agentId for the WebSocket URL. We gate which
// agents the public demos can reach to prevent token reuse for other agents.
$allowed_agents = [
    'agent_3B8vgGssvCWT2EKfqJeCm4',  // legacy default
    'agent_54wqANcE6T89JqJHTBFFQM',  // AI Karyakarta UP browser demo (private)
];

// Read requested agent_id from POST body. Optional — falls back to default.
$body = json_decode(file_get_contents('php://input'), true) ?: [];
$requested = $body['agentId'] ?? $body['agent_id'] ?? null;
if ($requested !== null && in_array($requested, $allowed_agents, true)) {
    $agent_id = $requested;
} else {
    $agent_id = $default_agent_id;
}

if (empty($api_key)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'not_configured']);
    exit;
}

// Simple rate limit: 10 tokens per IP per 5 minutes
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$cache_key = sys_get_temp_dir() . '/cart_rl_' . md5($ip);
$now = time();
$window = 300;
$max_per_window = 10;

$attempts = [];
if (file_exists($cache_key)) {
    $raw = file_get_contents($cache_key);
    $attempts = json_decode($raw, true) ?: [];
}
$attempts = array_filter($attempts, fn($t) => $t > $now - $window);
if (count($attempts) >= $max_per_window) {
    http_response_code(429);
    echo json_encode(['ok' => false, 'error' => 'rate_limited']);
    exit;
}
$attempts[] = $now;
file_put_contents($cache_key, json_encode($attempts));

// Mint the token
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
    echo json_encode(['ok' => false, 'error' => 'mint_failed', 'upstream_status' => $http_code]);
    exit;
}

$data = json_decode($response, true);
$token = $data['token'] ?? $data['access_token'] ?? null;

if (!$token) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'no_token_in_response']);
    exit;
}

echo json_encode([
    'ok' => true,
    'token' => $token,
    'agentId' => $agent_id,
    'version' => '2025-04-16',
]);
