<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

function vton_fail(int $code, string $message): never {
    http_response_code($code);
    echo json_encode(['error' => $message]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    vton_fail(405, 'Use POST to start a session.');
}
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$origins = ['https://voxdonna.com'];
if (PHP_SAPI === 'cli-server') $origins[] = 'http://127.0.0.1:3499';
if (!in_array($origin, $origins, true)) vton_fail(403, 'Open the demo on VoxDonna to start a session.');

$key = getenv('DECART_API_KEY') ?: '';
if ($key === '') {
    $envPath = PHP_SAPI === 'cli-server' ? __DIR__ . '/.env' : dirname(__DIR__) . '/vton.env';
    foreach (@file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        if (preg_match('/^\s*DECART_API_KEY\s*=\s*(.*)$/', $line, $match)) {
            $key = trim($match[1], " \t\r\n\"'");
            break;
        }
    }
}
if ($key === '') vton_fail(503, 'The fitting room is not configured yet. Please contact VoxDonna.');
if (!function_exists('curl_init')) vton_fail(503, 'The fitting room is temporarily unavailable.');

// One locked file bounds both per-IP and total minting, including concurrent requests.
$path = sys_get_temp_dir() . '/voxdonna-vton-' . substr(hash('sha256', __DIR__), 0, 16) . '.json';
$file = @fopen($path, 'c+');
if (!$file || !flock($file, LOCK_EX)) vton_fail(503, 'The fitting room is temporarily unavailable.');
$raw = stream_get_contents($file);
$attempts = $raw === '' ? [] : json_decode($raw, true);
if (!is_array($attempts)) { fclose($file); vton_fail(503, 'The fitting room is temporarily unavailable.'); }
$now = time();
$ip = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
$attempts = array_values(array_filter($attempts, fn($item) => is_array($item) && ($item['time'] ?? 0) > $now - 3600));
$recent = array_filter($attempts, fn($item) => ($item['ip'] ?? '') === $ip && $item['time'] > $now - 600);
if (count($recent) >= 6 || count($attempts) >= 100) {
    fclose($file);
    header('Retry-After: 600');
    vton_fail(429, 'The demo session limit has been reached. Please try again later.');
}
$attempts[] = ['time' => $now, 'ip' => $ip];
$encoded = json_encode($attempts, JSON_THROW_ON_ERROR);
rewind($file);
if (!ftruncate($file, 0) || fwrite($file, $encoded) !== strlen($encoded) || !fflush($file)) {
    fclose($file);
    vton_fail(503, 'The fitting room is temporarily unavailable.');
}
rewind($file);
if (json_decode(stream_get_contents($file), true) !== $attempts) {
    fclose($file);
    vton_fail(503, 'The fitting room is temporarily unavailable.');
}
flock($file, LOCK_UN);
fclose($file);

$request = curl_init('https://api.decart.ai/v1/client/tokens');
curl_setopt_array($request, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 12,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-API-KEY: ' . $key],
    CURLOPT_POSTFIELDS => json_encode([
        'expiresIn' => 60,
        'allowedModels' => ['lucy-vton-latest', 'lucy-vton-3.6'],
        'allowedOrigins' => [$origin],
        'constraints' => ['realtime' => ['maxSessionDuration' => 120]],
    ], JSON_THROW_ON_ERROR),
]);
$response = curl_exec($request);
$code = curl_getinfo($request, CURLINFO_HTTP_CODE);
unset($request);
$data = is_string($response) ? json_decode($response, true) : null;
if ($code !== 200 || !is_string($data['apiKey'] ?? null) || !is_string($data['expiresAt'] ?? null) || str_starts_with($data['apiKey'], 'dct_')) {
    error_log('VoxDonna VTON token mint failed; HTTP ' . $code);
    vton_fail(502, 'The fitting room could not connect. Please try again shortly.');
}
echo json_encode(['apiKey' => $data['apiKey'], 'expiresAt' => $data['expiresAt']], JSON_THROW_ON_ERROR);
