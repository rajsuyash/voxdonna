<?php
/**
 * Tanishq personal shopper demo — backend for the PersonaPlex voice page.
 * Routes (rewritten from api/<route>): config, session, booking/extract, booking/confirm.
 * Secrets from the site .env: FAL_API_KEY, ANTHROPIC_API_KEY, ELEVENLABS_API_KEY,
 * DMCHAMP_TANISHQ_API_KEY, DMCHAMP_EVENT_ID. Nothing secret leaves this file.
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');
date_default_timezone_set('Asia/Kolkata');

const ALLOWED_ORIGINS = ['https://voxdonna.com', 'https://www.voxdonna.com'];
const HINDI_AGENT = 'agent_1701m263291pfqz8qe2agr929dgg';
const FAL_APP = 'fal-ai/personaplex';
const FAL_ENDPOINT = 'fal-ai/personaplex/realtime';
const LAST_START = '19:30';
const BOOKING_DAYS = 28;
const DAILY_SESSION_CAP = 80;

function out(int $status, array $body): void { http_response_code($status); echo json_encode($body, JSON_UNESCAPED_UNICODE); exit; }

function load_env(string $path): array {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1], " \t\"'");
    }
    return $env;
}

/** Sliding-window counter in the temp dir; returns true when over the limit. */
function limited(string $key, int $max, int $window): bool {
    $file = sys_get_temp_dir() . '/tanishq_' . md5($key);
    $now = time();
    $hits = file_exists($file) ? (json_decode(file_get_contents($file), true) ?: []) : [];
    $hits = array_values(array_filter($hits, fn($t) => $t > $now - $window));
    if (count($hits) >= $max) return true;
    $hits[] = $now;
    file_put_contents($file, json_encode($hits), LOCK_EX);
    return false;
}

function http(string $method, string $url, array $headers, ?array $body = null, int $timeout = 20): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_TIMEOUT => $timeout,
        CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers),
        CURLOPT_POSTFIELDS => $body === null ? null : json_encode($body, JSON_UNESCAPED_UNICODE),
    ]);
    $raw = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$status, json_decode((string) $raw, true)];
}

function stores(): array { return json_decode(file_get_contents(__DIR__ . '/stores.json'), true); }
function store_by_id(?string $id): ?array { foreach (stores()['stores'] as $s) if ($s['id'] === $id) return $s; return null; }
function fmt_time(int $mins): string { $h = intdiv($mins, 60); return sprintf('%d:%02d %s', (($h + 11) % 12) + 1, $mins % 60, $h < 12 ? 'AM' : 'PM'); }
function mins(string $hhmm): int { [$h, $m] = array_map('intval', explode(':', $hhmm)); return $h * 60 + $m; }

function build_prompt(string $name): string {
    $base = explode('## Language configuration', file_get_contents(__DIR__ . '/prompt.md'))[0];
    $today = new DateTime('now');
    $lines = [];
    foreach (stores()['stores'] as $s) $lines[] = "- {$s['city']}, {$s['name']}: {$s['address']}. Closes " . fmt_time(mins($s['closes'])) . '.';
    $visitor = $name !== '' ? "The visitor's name is {$name}; use it once, naturally." : "You do not know the visitor's name; do not ask for it.";
    return trim($base) . "\n\n## Session facts\n\nToday is " . $today->format('l, Y-m-d') . " (India). {$visitor} The visitor's WhatsApp number is already on file; never ask for it.\n\n## Showrooms you can book\n\nAll open from 11:00 AM; the last visit slot is 7:30 PM or thirty minutes before closing, whichever is earlier.\n" . implode("\n", $lines) . "\n";
}

function normalise_phone($raw): ?string {
    $digits = preg_replace('/\D/', '', (string) $raw);
    $national = (strlen($digits) === 12 && str_starts_with($digits, '91')) ? substr($digits, 2) : (strlen($digits) === 10 ? $digits : null);
    return $national !== null && preg_match('/^[6-9]\d{9}$/', $national) ? '+91' . $national : null;
}

function validate_slot(?string $storeId, ?string $date, ?string $time): array {
    $store = store_by_id($storeId);
    if (!$store) return ['ok' => false, 'reason' => 'Pick a store from the list.'];
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) $date) || !preg_match('/^\d{2}:\d{2}$/', (string) $time)) return ['ok' => false, 'reason' => 'Date or time is incomplete.'];
    $now = new DateTime('now');
    $today = new DateTime($now->format('Y-m-d'));
    $day = DateTime::createFromFormat('Y-m-d', $date);
    if (!$day) return ['ok' => false, 'reason' => 'Date or time is incomplete.'];
    $day->setTime(0, 0);
    $offset = (int) $today->diff($day)->format('%r%a');
    if ($offset < 0 || $offset > BOOKING_DAYS) return ['ok' => false, 'reason' => 'Visits can be booked from today up to ' . BOOKING_DAYS . ' days ahead.'];
    if ($offset === 0 && mins($time) <= mins($now->format('H:i')) + 120) return ['ok' => false, 'reason' => 'Same-day visits need at least two hours notice.'];
    $lastStart = min(mins(LAST_START), mins($store['closes']) - 30);
    if (mins($time) < mins(stores()['opens']) || mins($time) > $lastStart || mins($time) % 30) return ['ok' => false, 'reason' => "{$store['name']} takes visits on the half hour from 11:00 AM; the last slot that day is " . fmt_time($lastStart) . '.'];
    $label = $day->format('l, j F') . ' at ' . fmt_time(mins($time)) . ' IST';
    return ['ok' => true, 'store' => $store, 'startISO' => "{$date}T{$time}:00+05:30", 'label' => $label];
}

function confirmation_message(string $name, array $store, string $label): string {
    return "Namaste {$name}, Aanya here from Tanishq. Your showroom visit is confirmed.\n\nTanishq {$store['name']}, {$store['city']}\n{$store['address']}\n{$label}\n\nAn advisor will have pieces ready based on what you shared on the call. The visit is free, with no obligation to buy. Reply here if you would like to move the time.";
}

// ---------------------------------------------------------------------------
$env = load_env(dirname(__DIR__, 2) . '/.env');
$route = $_GET['route'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$booking_ready = !empty($env['ANTHROPIC_API_KEY']) && !empty($env['DMCHAMP_TANISHQ_API_KEY']) && !empty($env['DMCHAMP_EVENT_ID']);

if ($route === 'config') {
    out(200, [
        'englishConfigured' => !empty($env['FAL_API_KEY']) || !empty($env['FAL_KEY']),
        'hindiConfigured' => !empty($env['ELEVENLABS_API_KEY']),
        'bookingConfigured' => $booking_ready,
        'stores' => array_map(fn($s) => ['id' => $s['id'], 'city' => $s['city'], 'name' => $s['name']], stores()['stores']),
    ]);
}

if ($method !== 'POST') out(405, ['error' => 'POST required.']);
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (!in_array($origin, ALLOWED_ORIGINS, true) || ($_SERVER['HTTP_X_DEMO_REQUEST'] ?? '') !== '1') out(403, ['error' => 'Open the demo page before starting a conversation.']);
$body = json_decode(file_get_contents('php://input'), true) ?: [];

if ($route === 'session') {
    $language = $_GET['language'] ?? '';
    if ($language !== 'en' && $language !== 'hi') out(400, ['error' => 'Choose English or Hindi.']);
    if (limited("session:$ip", 6, 600)) out(429, ['error' => 'Too many starts. Please wait a few minutes.']);
    if (limited('session:global:' . date('Y-m-d'), DAILY_SESSION_CAP, 86400)) out(503, ['error' => 'The demo is busy today. Please try again tomorrow.']);
    $name = mb_substr(trim((string) ($body['name'] ?? '')), 0, 60);
    if ($language === 'en') {
        $key = $env['FAL_API_KEY'] ?? $env['FAL_KEY'] ?? '';
        if ($key === '') out(503, ['error' => 'PersonaPlex credentials are not configured.']);
        [$status, $data] = http('POST', 'https://rest.fal.ai/tokens/realtime', ["Authorization: Key {$key}"], ['app' => FAL_APP, 'allowed_apps' => [FAL_ENDPOINT], 'duration' => 120]);
        $token = is_string($data) ? $data : ($data['token'] ?? null);
        if ($status >= 300 || !is_string($token) || $token === '') out(502, ['error' => "PersonaPlex provider rejected the session ({$status}). Please retry shortly."]);
        out(200, ['url' => 'wss://fal.run/' . FAL_ENDPOINT . '?fal_jwt_token=' . rawurlencode($token), 'provider' => 'personaplex', 'sampleRate' => 24000, 'maxSeconds' => 300, 'prompt' => build_prompt($name)]);
    }
    $key = $env['ELEVENLABS_API_KEY'] ?? '';
    if ($key === '') out(503, ['error' => 'Hindi credentials are not configured.']);
    $agent = $env['ELEVENLABS_HINDI_AGENT_ID'] ?? HINDI_AGENT;
    [$status, $data] = http('GET', 'https://api.elevenlabs.io/v1/convai/conversation/get-signed-url?agent_id=' . rawurlencode($agent), ["xi-api-key: {$key}"]);
    $url = $data['signed_url'] ?? '';
    if ($status >= 300 || !str_starts_with($url, 'wss://api.elevenlabs.io/')) out(502, ['error' => "Hindi provider rejected the session ({$status}). Please retry shortly."]);
    out(200, ['url' => $url, 'provider' => 'elevenlabs', 'sampleRate' => 16000, 'maxSeconds' => 300]);
}

if ($route === 'booking/extract') {
    $empty = ['store_id' => null, 'date' => null, 'time' => null, 'agent_announced_booking' => false];
    $transcript = mb_substr((string) ($body['transcript'] ?? ''), -6000);
    if (mb_strlen($transcript) < 20) out(200, $empty);
    if (!$booking_ready) out(503, ['error' => 'Booking is not configured.']);
    if (limited("extract:$ip", 60, 60)) out(429, ['error' => 'Slow down a little.']);
    $today = new DateTime('now');
    $calendar = [];
    for ($i = 0; $i < 15; $i++) { $d = (clone $today)->modify("+{$i} day"); $calendar[] = $d->format('l Y-m-d') . ($i === 0 ? ' (today)' : ($i === 1 ? ' (tomorrow)' : '')); }
    $list = implode("\n", array_map(fn($s) => "{$s['id']}: {$s['city']}, {$s['name']}", stores()['stores']));
    $system = "You read what a jewellery concierge assistant said during a voice call and extract the showroom visit it discussed. Only the assistant's words are available. Today is " . $today->format('l Y-m-d') . " in India. Resolve weekday names with this calendar only, taking the first matching date after today unless \"next\" is said: " . implode(', ', $calendar) . ". Store list (id: city, name):\n{$list}\nUse the latest details the assistant stated; a later correction replaces an earlier value. Never invent a store, date or time the assistant did not say.";
    $schema = ['type' => 'object', 'additionalProperties' => false, 'required' => ['store_id', 'date', 'time', 'agent_announced_booking'], 'properties' => [
        'store_id' => ['type' => ['string', 'null'], 'description' => 'id from the store list, or null if no specific store has been chosen'],
        'date' => ['type' => ['string', 'null'], 'description' => 'YYYY-MM-DD of the agreed visit, resolved from relative words like Saturday or tomorrow; null if none'],
        'time' => ['type' => ['string', 'null'], 'description' => 'HH:MM 24-hour IST start time; null if none'],
        'agent_announced_booking' => ['type' => 'boolean', 'description' => 'true only if the assistant said it is booking / has booked the visit and the WhatsApp confirmation is on its way'],
    ]];
    [$status, $data] = http('POST', 'https://api.anthropic.com/v1/messages', ["x-api-key: {$env['ANTHROPIC_API_KEY']}", 'anthropic-version: 2023-06-01'], [
        'model' => 'claude-haiku-4-5', 'max_tokens' => 300, 'system' => $system,
        'messages' => [['role' => 'user', 'content' => "Assistant transcript:\n{$transcript}"]],
        'output_config' => ['format' => ['type' => 'json_schema', 'schema' => $schema]],
    ], 30);
    $text = '';
    foreach ($data['content'] ?? [] as $block) if (($block['type'] ?? '') === 'text') $text .= $block['text'];
    $parsed = json_decode($text, true);
    if ($status >= 300 || !is_array($parsed)) out(502, ['error' => 'Extraction failed. Use the Confirm button.']);
    out(200, ['store_id' => $parsed['store_id'] ?? null, 'date' => $parsed['date'] ?? null, 'time' => $parsed['time'] ?? null, 'agent_announced_booking' => (bool) ($parsed['agent_announced_booking'] ?? false)]);
}

if ($route === 'booking/confirm') {
    if (!$booking_ready) out(503, ['error' => 'Booking is not configured.']);
    if (limited("confirm:$ip", 6, 60)) out(429, ['error' => 'Too many bookings. Please wait a minute.']);
    $name = mb_substr(trim((string) ($body['name'] ?? '')), 0, 60);
    $phone = normalise_phone($body['phone'] ?? '');
    if ($name === '') out(400, ['error' => 'Please enter your name.']);
    if ($phone === null) out(400, ['error' => 'Enter a valid Indian mobile number.']);
    $slot = validate_slot($body['storeId'] ?? null, $body['date'] ?? null, $body['time'] ?? null);
    if (!$slot['ok']) out(400, ['error' => $slot['reason']]);
    $dedupe = sys_get_temp_dir() . '/tanishq_booked_' . md5($phone . '|' . $slot['startISO']);
    if (file_exists($dedupe) && filemtime($dedupe) > time() - 600) out(200, json_decode(file_get_contents($dedupe), true) + ['repeated' => true]);
    $key = $env['DMCHAMP_TANISHQ_API_KEY'];
    $dm = fn(string $m, string $path, ?array $b = null) => http($m, 'https://api.dmchamp.com/v1' . $path . (str_contains($path, '?') ? '&' : '?') . 'apiKey=' . rawurlencode($key), [], $b);
    $idOf = fn($d) => $d['contactId'] ?? $d['contact_id'] ?? $d['contact']['id'] ?? $d['id'] ?? null;
    $fields = ['firstName' => $name, 'channel' => 'whatsapp_web', 'custom_fields' => ['tanishq_store' => $slot['store']['name'], 'tanishq_visit' => $slot['label']]];
    [, $found] = $dm('GET', '/contacts?phoneNumber=' . rawurlencode($phone));
    $contactId = $idOf($found);
    if ($contactId) { $dm('PUT', "/contacts/{$contactId}", $fields); }
    else {
        [$cs, $created] = $dm('POST', '/contacts', ['phoneNumber' => $phone] + $fields);
        // DM Champ reports a duplicate as HTTP 200 with error_code 409.
        if ($cs === 409 || ($created['error_code'] ?? null) === 409) { [, $again] = $dm('GET', '/contacts?phoneNumber=' . rawurlencode($phone)); $contactId = $idOf($again); }
        elseif ($cs < 300 && ($created['success'] ?? true) !== false) $contactId = $idOf($created);
        if (!$contactId) out(502, ['error' => "Could not save the contact ({$cs})."]);
    }
    [$as, $appt] = $dm('POST', '/appointments', ['contact_id' => $contactId, 'event_id' => $env['DMCHAMP_EVENT_ID'], 'start_time' => $slot['startISO']]);
    if ($as >= 300) out(502, ['error' => $as === 409 ? 'That slot has just been taken. Please pick another time.' : "Booking failed ({$as})."]);
    $appointmentId = $appt['appointment_id'] ?? $appt['appointment']['id'] ?? $appt['id'] ?? 'booked';
    [$ws] = $dm('POST', '/whatsapp-web/send', ['phoneNumber' => $phone, 'message' => confirmation_message($name, $slot['store'], $slot['label'])]);
    if ($ws >= 300) out(502, ['error' => "Booked, but the WhatsApp send failed ({$ws}).", 'appointmentId' => $appointmentId]);
    $result = ['appointmentId' => $appointmentId, 'contactId' => $contactId, 'store' => "{$slot['store']['name']}, {$slot['store']['city']}", 'when' => $slot['label'], 'sentTo' => $phone];
    file_put_contents($dedupe, json_encode($result), LOCK_EX);
    out(200, $result);
}

out(404, ['error' => 'Not found.']);
