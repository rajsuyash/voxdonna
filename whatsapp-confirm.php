<?php
/**
 * Visit-confirmation sender for ConvAI voice agents (DM Champ behind a shared secret).
 * The ElevenLabs webhook tool points here and sends only `x-scheme-key`; the DM Champ
 * key lives server-side in .env and never touches ElevenLabs.
 *
 * Setup (Hostinger .env, web root):
 *   DMCHAMP_API=<DM Champ API key with send scope>
 *   SCHEME_TOOL_SECRET=<same value put in the tool's x-scheme-key header>
 *
 * Request:  POST /whatsapp-confirm.php?brand=joyalukkas-ta
 *           { "phone": "+919876543210", "name": "Ramesh", "showroom": "...", "day": "Saturday" }
 * Response: { "sent": bool, "status": "...", "say": "<one line for the agent to read out>" }
 *
 * The brand rides in the URL, never in the model-supplied body: a variant the model
 * picks is a variant it can get wrong, and the logs cannot tell you that it did.
 *
 * The message TEMPLATE is server-side on purpose. The agent supplies only the slot
 * values, so it cannot be talked into sending arbitrary text to an arbitrary number.
 */

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['sent' => false, 'status' => 'method_not_allowed', 'say' => '']);
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
$dmkey  = $env['DMCHAMP_API'] ?? '';

$given = $_SERVER['HTTP_X_SCHEME_KEY'] ?? '';
if (empty($secret) || !hash_equals($secret, $given)) {
    http_response_code(401);
    echo json_encode(['sent' => false, 'status' => 'unauthorized', 'say' => '']);
    exit;
}

// Brand from the URL. Unknown brand fails closed rather than falling back to a default,
// so a typo can never send one client's wording to another client's customer.
$BRANDS = [
    'joyalukkas-ta' => [
        'label' => 'ஜாயலுக்காஸ்',
        'tpl'   => "வணக்கம்%s! ஜாயலுக்காஸ் — உங்க visit details:\n\nஷோரூம்: %s\nநாள்: %s\n\nஇது ஒரு Voxdonna demonstration. showroom-ல உறுதி செய்யப்பட்ட booking இல்ல.",
        'say'   => 'details உங்க WhatsApp-க்கு அனுப்பிட்டேன்',
    ],
    'pc-jewellers' => [
        'label' => 'PC Jewellers',
        'tpl'   => "Namaste%s! PC Jewellers ki taraf se aapki visit details:\n\nShowroom: %s\nDin: %s\n\nYeh ek Voxdonna demonstration hai, showroom par confirmed booking nahi hai.",
        'say'   => 'maine details aapke WhatsApp par bhej diye hain',
    ],
];
$brand = $_GET['brand'] ?? '';
if (!isset($BRANDS[$brand])) {
    http_response_code(400);
    echo json_encode(['sent' => false, 'status' => 'unknown_brand', 'say' => '']);
    exit;
}
$cfg = $BRANDS[$brand];

$body     = json_decode(file_get_contents('php://input'), true) ?: [];
$name     = trim((string)($body['name'] ?? ''));
$showroom = trim((string)($body['showroom'] ?? ''));
$day      = trim((string)($body['day'] ?? ''));
$raw      = trim((string)($body['phone'] ?? ''));

// E.164, defaulting a bare 10-digit Indian mobile to +91. Reject anything else rather
// than guessing a country and messaging a stranger.
$digits = preg_replace('/[^\d]/', '', $raw);
if (strpos($raw, '+') === 0)            $phone = '+' . $digits;
elseif (preg_match('/^[6-9]\d{9}$/', $digits)) $phone = '+91' . $digits;
elseif (preg_match('/^91[6-9]\d{9}$/', $digits)) $phone = '+' . $digits;
else                                     $phone = '';

if ($phone === '' || !preg_match('/^\+[1-9]\d{7,14}$/', $phone) || $showroom === '' || $day === '') {
    http_response_code(400);
    echo json_encode(['sent' => false, 'status' => 'invalid_input', 'say' => '']);
    exit;
}

// Rate limit per destination: a demo agent must never be able to bomb a number.
$bucket = sys_get_temp_dir() . '/wac_' . md5($brand . $phone);
$now    = time();
$hits   = file_exists($bucket) ? (json_decode(file_get_contents($bucket), true) ?: []) : [];
$hits   = array_values(array_filter($hits, fn($t) => $t > $now - 3600));
if (count($hits) >= 3) {
    http_response_code(429);
    echo json_encode(['sent' => false, 'status' => 'rate_limited', 'say' => '']);
    exit;
}

if (empty($dmkey)) {
    echo json_encode(['sent' => false, 'status' => 'not_configured', 'say' => '']);
    exit;
}

$message = sprintf($cfg['tpl'], $name !== '' ? ' ' . $name : '', $showroom, $day);

$ch = curl_init('https://api.dmchamp.com/v1/whatsapp-web/send?apiKey=' . rawurlencode($dmkey));
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS     => json_encode(['phoneNumber' => $phone, 'message' => $message], JSON_UNESCAPED_UNICODE),
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$data = json_decode((string)$resp, true);
$ok   = $code >= 200 && $code < 300 && (($data['success'] ?? true) !== false);

if ($ok) {
    $hits[] = $now;
    file_put_contents($bucket, json_encode($hits));
    echo json_encode(['sent' => true, 'status' => 'queued', 'say' => $cfg['say']], JSON_UNESCAPED_UNICODE);
    exit;
}

// Fail honestly. The agent must be able to tell the customer it did not go, rather
// than claim a send that never happened. 1010 from DM Champ is a rate limit.
error_log("whatsapp-confirm: brand={$brand} http={$code} body=" . substr((string)$resp, 0, 200));
echo json_encode([
    'sent'   => false,
    'status' => $code === 403 ? 'provider_rejected' : 'provider_error',
    'say'    => '',
], JSON_UNESCAPED_UNICODE);
