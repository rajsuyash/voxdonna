<?php
/**
 * Live web-search proxy for ConvAI voice agents (Tavily behind a shared secret).
 * The ElevenLabs webhook tool points here and sends only `x-scheme-key`; the
 * Tavily key lives server-side in .env and never touches ElevenLabs.
 *
 * Setup (Hostinger .env, web root):
 *   TAVILY_API_KEY=tvly-...
 *   SCHEME_TOOL_SECRET=<same value put in the tool's x-scheme-key header>
 *
 * Request:  POST { "query": "gold rate today India 22k per gram" }
 * Response: { found, query, answer, source, summary }
 */

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['found' => false, 'error' => 'method_not_allowed']);
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

$env    = load_env(__DIR__ . '/.env');
$secret = $env['SCHEME_TOOL_SECRET'] ?? '';
$tavily = $env['TAVILY_API_KEY'] ?? '';

// Auth: shared secret, constant-time compare.
$given = $_SERVER['HTTP_X_SCHEME_KEY'] ?? '';
if (empty($secret) || !hash_equals($secret, $given)) {
    http_response_code(401);
    echo json_encode(['found' => false, 'error' => 'unauthorized']);
    exit;
}

$body  = json_decode(file_get_contents('php://input'), true);
$query = is_array($body) ? trim((string)($body['query'] ?? '')) : '';
if (strlen($query) < 4 || strlen($query) > 200) {
    http_response_code(400);
    echo json_encode(['found' => false, 'error' => 'invalid_query']);
    exit;
}

$fallback = [
    'found'   => false,
    'query'   => $query,
    'summary' => 'Live search unavailable. Answer from the knowledge base and suggest confirming on an official source. Never invent a figure.',
];

if (empty($tavily)) { echo json_encode($fallback); exit; }

$ch = curl_init('https://api.tavily.com/search');
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 11,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS     => json_encode([
        'api_key'        => $tavily,
        'query'          => $query,
        'search_depth'   => 'basic',
        'include_answer' => 'advanced',
        'max_results'    => 6,
    ]),
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($resp === false || $code !== 200) { echo json_encode($fallback); exit; }

$data   = json_decode($resp, true);
$answer = trim((string)($data['answer'] ?? ''));
if (strlen($answer) >= 20) {
    echo json_encode([
        'found'   => true,
        'query'   => $query,
        'answer'  => $answer,
        'source'  => $data['results'][0]['url'] ?? 'web sources',
        'summary' => $answer,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
echo json_encode($fallback);
// ponytail: no result cache — demo volume is low and Tavily is fast. Add a
// file/APCu cache keyed on the query if repeat gold-rate asks burn credits.
