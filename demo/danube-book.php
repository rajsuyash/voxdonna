<?php
/**
 * Danube Properties demo — real booking + WhatsApp confirmation for the Anya voice agent
 * (agent_6201m3ak9v4sepv8c1vsed0z29rn). Called directly by the ElevenLabs webhook tool
 * mid-call — there is no browser page posting here. Mirrors the Tanishq personal-shopper
 * agent/book route (demo/tanishq-personal-shopper/api.php) but is self-contained: same
 * DM Champ account (DMCHAMP_TANISHQ_API_KEY — the WhatsApp-Web sender is connected there),
 * a separate event (DMCHAMP_DANUBE_EVENT_ID), and Asia/Dubai hours instead of Asia/Kolkata.
 * Secrets read from the site .env. Nothing secret leaves this file.
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');

const DANUBE_TZ = 'Asia/Dubai';
const DANUBE_UTC_OFFSET = '+04:00';
const DANUBE_OPENS = '10:00';
const DANUBE_LAST_START = '18:30'; // last 30-min slot before the 19:00 close
const DANUBE_BOOKING_DAYS = 28;
const DANUBE_NOTICE_HOURS = 2;

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
    $file = sys_get_temp_dir() . '/danube_' . md5($key);
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

/** The agent says "Saturday", not a date. Resolve spoken days here so it cannot invent one. */
function resolve_danube_date(?string $raw, DateTimeZone $tz, ?DateTimeImmutable $now = null): ?string {
    if (!is_string($raw)) return null;
    $raw = strtolower(trim($raw));
    $now ??= new DateTimeImmutable('now', $tz);
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/D', $raw)) return $raw;
    $words = ['today' => 0, 'tomorrow' => 1];
    if (isset($words[$raw])) return $now->modify('+' . $words[$raw] . ' day')->format('Y-m-d');
    $days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
    foreach ($days as $day) {
        if (!str_contains($raw, $day)) continue;
        $next = $now->modify('next ' . $day);
        $sameDay = strtolower($now->format('l')) === $day;
        return ($sameDay && !str_contains($raw, 'next')) ? $now->format('Y-m-d') : $next->format('Y-m-d');
    }
    return null;
}

/** Accepts "11:00" (24h), "11 AM", "11:30pm", etc. Never lets the model hand us a free-form string. */
function parse_danube_time(?string $raw): ?string {
    if (!is_string($raw)) return null;
    $raw = strtolower(trim($raw));
    if (preg_match('/^([01]?\d|2[0-3]):([0-5]\d)$/D', $raw, $m)) return sprintf('%02d:%02d', (int) $m[1], (int) $m[2]);
    if (preg_match('/^(1[0-2]|0?[1-9])(?:[:.]([0-5]\d))?\s*(am|pm)$/D', $raw, $m)) {
        $h = (int) $m[1];
        $min = isset($m[2]) ? (int) $m[2] : 0;
        $h = $m[3] === 'am' ? ($h === 12 ? 0 : $h) : ($h === 12 ? 12 : $h + 12);
        return sprintf('%02d:%02d', $h, $min);
    }
    return null;
}

function fmt_time(int $mins): string { $h = intdiv($mins, 60); return sprintf('%d:%02d %s', (($h + 11) % 12) + 1, $mins % 60, $h < 12 ? 'AM' : 'PM'); }
function mins(string $hhmm): int { [$h, $m] = array_map('intval', explode(':', $hhmm)); return $h * 60 + $m; }

/**
 * Accepts international numbers with a country code (+33, +971, +91, ...), plus two bare
 * national formats a Dubai-audience demo actually hears: a UAE mobile (05XXXXXXXX) and an
 * Indian mobile (10 digits, 6-9 first digit) — Tanishq's normalise_phone assumes India only,
 * which is wrong for this agent's audience.
 */
function normalise_phone_intl($raw): ?string {
    $raw = trim((string) $raw);
    if ($raw === '') return null;
    $digits = preg_replace('/\D/', '', $raw);
    if (str_starts_with($raw, '+') || str_starts_with($raw, '00')) {
        if (str_starts_with($raw, '00')) $digits = substr($digits, 2);
        if (!preg_match('/^[1-9]\d{7,14}$/D', $digits)) return null;
        // Tighter per-country length checks for the two countries this demo's audience
        // concentrates in. A dialogue model asked to prepend a country code sometimes wraps a
        // bare 10-digit number it heard with the wrong prefix (e.g. turns a caller-recited Indian
        // mobile into "+971" + all 10 digits) — the generic 8-15-digit rule above waves that
        // through as a plausible-looking international number. Reject it instead of booking a
        // number nobody could reach.
        if (str_starts_with($digits, '971')) { $rest = substr($digits, 3); return (strlen($rest) === 8 || strlen($rest) === 9) ? '+' . $digits : null; }
        if (str_starts_with($digits, '91')) return preg_match('/^91[6-9]\d{9}$/D', $digits) ? '+' . $digits : null;
        return '+' . $digits;
    }
    if (strlen($digits) === 10 && $digits[0] === '0' && in_array($digits[1], ['2', '4', '5', '6'], true)) {
        return '+971' . substr($digits, 1); // UAE mobile/landline, e.g. 050 123 4567
    }
    if (strlen($digits) === 9 && in_array($digits[0], ['2', '4', '5', '6'], true)) {
        return '+971' . $digits; // UAE number already missing its leading 0
    }
    if (strlen($digits) === 10 && preg_match('/^[6-9]\d{9}$/D', $digits)) return '+91' . $digits; // Indian mobile
    return null; // ambiguous without a country code — ask the caller to include one
}

function looks_placeholder(string $phone): bool {
    $digits = preg_replace('/\D/', '', $phone);
    if ($digits === '') return true;
    $tail10 = substr($digits, -10);
    $tail9 = substr($digits, -9);
    if (preg_match('/(\d)\1{5,}/', $tail10)) return true; // 6+ consecutive repeated digits, e.g. ...500000000
    $known = ['9876543210', '1234567890', '0123456789', '9999999999', '1111111111', '0000000000',
              '876543210', '123456789', '987654321'];
    return in_array($tail10, $known, true) || in_array($tail9, $known, true);
}

const DANUBE_TYPES = [
    'site_visit' => 'site visit',
    'video_consultation' => 'video consultation',
    'advisor_call' => 'advisor call',
];

function validate_danube_slot($date, $time, DateTimeZone $tz, ?DateTimeImmutable $now = null): array {
    if (!is_string($date) || !is_string($time)) return ['ok' => false, 'reason' => 'Date or time is missing.'];
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $date) || !preg_match('/^(?:[01]\d|2[0-3]):[0-5]\d$/D', $time)) {
        return ['ok' => false, 'reason' => 'Date or time is incomplete.'];
    }
    $now ??= new DateTimeImmutable('now', $tz);
    $today = new DateTime($now->format('Y-m-d'), $tz);
    $day = DateTime::createFromFormat('!Y-m-d', $date, $tz);
    if (!$day || $day->format('Y-m-d') !== $date) return ['ok' => false, 'reason' => 'Choose a valid calendar date.'];
    $day->setTime(0, 0);
    $offset = (int) $today->diff($day)->format('%r%a');
    if ($offset < 0) return ['ok' => false, 'reason' => 'That date has already passed. Ask for another day.'];
    if ($offset > DANUBE_BOOKING_DAYS) return ['ok' => false, 'reason' => 'Appointments can be booked from today up to ' . DANUBE_BOOKING_DAYS . ' days ahead.'];
    $start = new DateTimeImmutable("{$date}T{$time}:00", $tz);
    if ($start < $now->modify('+' . DANUBE_NOTICE_HOURS . ' hours')) return ['ok' => false, 'reason' => 'That time needs at least two hours notice from now, Dubai time. Ask for a later time.'];
    $lastStart = mins(DANUBE_LAST_START);
    if (mins($time) < mins(DANUBE_OPENS) || mins($time) > $lastStart || mins($time) % 30 !== 0) {
        return ['ok' => false, 'reason' => 'The advisor takes appointments on the half hour, ten in the morning to half past six in the evening, Dubai time.'];
    }
    $label = $day->format('l j F') . ', ' . fmt_time(mins($time)) . ' Dubai time';
    return ['ok' => true, 'startISO' => "{$date}T{$time}:00" . DANUBE_UTC_OFFSET, 'label' => $label];
}

function danube_confirmation_message(string $name, string $typeLabel, string $label, ?string $project): string {
    $projectPart = ($project !== null && $project !== '') ? ", for {$project}" : '';
    return "Hi {$name}, your Danube Properties {$typeLabel} is confirmed for {$label}{$projectPart}. Our property advisor will contact you before the meeting. — Danube Properties (demo by Voxdonna)";
}

function dm_data($data): array { return is_array($data) ? (is_array($data['data'] ?? null) ? $data['data'] : $data) : []; }
function dm_ok(int $status, $data): bool {
    $inner = dm_data($data);
    return $status >= 200 && $status < 300 && is_array($data) && $data !== []
        && ($data['success'] ?? true) !== false && ($inner['success'] ?? true) !== false
        && empty($data['error']) && empty($inner['error'])
        && (int) ($data['error_code'] ?? 0) < 400 && (int) ($inner['error_code'] ?? 0) < 400;
}
function dm_id($data, string $kind): ?string {
    $data = dm_data($data);
    $id = $data[$kind . 'Id'] ?? $data[$kind . '_id'] ?? $data[$kind]['id'] ?? $data['id'] ?? null;
    return is_string($id) && preg_match('/^[A-Za-z0-9_-]+$/D', $id) ? $id : null;
}

function save_booking(string $path, array $state): void {
    $json = json_encode($state, JSON_THROW_ON_ERROR);
    $tmp = tempnam(dirname($path), '.booking-');
    if ($tmp === false) throw new RuntimeException('Booking storage is unavailable.');
    try {
        if (file_put_contents($tmp, $json) !== strlen($json)
            || json_decode(file_get_contents($tmp), true, 512, JSON_THROW_ON_ERROR) !== $state
            || !rename($tmp, $path)) throw new RuntimeException('Booking storage is unavailable.');
    } finally { if (file_exists($tmp)) unlink($tmp); }
}

function confirm_danube_booking(array $body, string $eventId, callable $dm, ?string $directory = null): array {
    if (!is_string($body['name'] ?? null) || !is_string($body['phone'] ?? null)) return [400, ['error' => 'Enter a name and phone number.']];
    $name = mb_substr(trim($body['name']), 0, 60);
    $phone = normalise_phone_intl($body['phone']);
    $typeKey = $body['appointment_type'] ?? null;
    if ($name === '' || $phone === null || !isset(DANUBE_TYPES[$typeKey])) return [400, ['error' => 'Enter a name, a valid phone number with country code, and a valid appointment type.']];
    $tz = new DateTimeZone(DANUBE_TZ);
    $slot = validate_danube_slot($body['date'] ?? null, $body['time'] ?? null, $tz);
    if (!$slot['ok']) return [400, ['error' => $slot['reason']]];
    $project = is_string($body['project'] ?? null) ? mb_substr(trim($body['project']), 0, 80) : null;
    $typeLabel = DANUBE_TYPES[$typeKey];
    // ponytail: one PHP host; use shared durable storage before adding another host.
    $directory ??= dirname(__DIR__, 2) . '/.danube-bookings';
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) return [503, ['error' => 'Booking storage is unavailable.']];
    $path = $directory . '/' . hash('sha256', $eventId . '|' . $phone . '|' . $typeKey . '|' . $slot['startISO']);
    $lock = fopen($path . '.lock', 'c');
    if (!$lock) return [503, ['error' => 'Booking storage is unavailable.']];
    if (!flock($lock, LOCK_EX | LOCK_NB)) { fclose($lock); return [409, ['error' => 'Your booking is still processing. Please wait before retrying.']]; }
    try {
        $state = file_exists($path) ? json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR) : [];
        if (!is_array($state)) throw new RuntimeException('Invalid booking record.');
        if (($state['phase'] ?? '') === 'booking_unknown') return [502, ['error' => 'The booking result is unconfirmed. Ask the demo operator to check it before trying again.', 'retryable' => false]];
        if (isset($state['result'])) {
            if ($state['result']['whatsappStatus'] !== 'failed') return [200, $state['result'] + ['repeated' => true]];
            $result = $state['result'];
        } else {
            $fields = ['firstName' => $name, 'channel' => 'whatsapp_web', 'custom_fields' => ['danube_appointment' => "{$typeLabel} — {$slot['label']}", 'danube_project' => $project ?? '']];
            [$cs, $found] = $dm('GET', '/contacts?phoneNumber=' . rawurlencode($phone));
            $contactId = dm_ok($cs, $found) ? dm_id($found, 'contact') : null;
            if (!$contactId) {
                if (!dm_ok($cs, $found) && $cs !== 404) return [502, ['error' => 'Could not look up the contact. Please retry shortly.']];
                [$cs, $created] = $dm('POST', '/contacts', ['phoneNumber' => $phone] + $fields);
                if ($cs === 409 || (int) ($created['error_code'] ?? 0) === 409) {
                    [$cs, $found] = $dm('GET', '/contacts?phoneNumber=' . rawurlencode($phone));
                    $contactId = dm_ok($cs, $found) ? dm_id($found, 'contact') : null;
                } else $contactId = dm_ok($cs, $created) ? dm_id($created, 'contact') : null;
            }
            if (!$contactId) return [502, ['error' => 'Could not save the contact. Please retry shortly.']];
            [$cs, $updated] = $dm('PUT', '/contacts/' . rawurlencode($contactId), $fields);
            if (!dm_ok($cs, $updated)) return [502, ['error' => 'Could not save the appointment details. Please retry shortly.']];
            // Persist before each external write: a lost response must never trigger a duplicate.
            save_booking($path, ['phase' => 'booking_unknown']);
            [$as, $appt] = $dm('POST', '/appointments', ['contact_id' => $contactId, 'event_id' => $eventId, 'start_time' => $slot['startISO']]);
            $appointmentId = dm_ok($as, $appt) ? dm_id($appt, 'appointment') : null;
            if (!$appointmentId) {
                if ($as >= 400 && $as < 500) {
                    save_booking($path, []);
                    return [502, ['error' => $as === 409 ? 'That slot has just been taken. Please offer another time.' : 'The booking was rejected. Please retry shortly.']];
                }
                return [502, ['error' => 'The booking result is unconfirmed. Ask the demo operator to check it before trying again.', 'retryable' => false]];
            }
            $result = ['appointmentId' => $appointmentId, 'contactId' => $contactId, 'when' => $slot['label'], 'sentTo' => $phone, 'whatsappStatus' => 'unknown'];
        }
        $result['whatsappStatus'] = 'unknown';
        save_booking($path, ['result' => $result]);
        [$ws, $sent] = $dm('POST', '/whatsapp-web/send', ['phoneNumber' => $phone, 'message' => danube_confirmation_message($name, $typeLabel, $slot['label'], $project)]);
        $sentData = dm_data($sent);
        if (dm_ok($ws, $sent) && ($sent['success'] ?? $sentData['success'] ?? false) === true && ($sentData['queued'] ?? true) !== false) $result['whatsappStatus'] = 'queued';
        elseif (($ws >= 400 && $ws < 500) || ($ws >= 200 && $ws < 300 && (($sent['success'] ?? null) === false || ($sentData['success'] ?? null) === false))) $result['whatsappStatus'] = 'failed';
        save_booking($path, ['result' => $result]);
        return [200, $result];
    } catch (Throwable $error) {
        error_log('Danube booking failed: ' . get_class($error));
        return [503, ['error' => 'Booking could not finish. Retry the same appointment to check its saved status.']];
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}

if (PHP_SAPI === 'cli' && defined('DANUBE_TEST')) return;

// ---------------------------------------------------------------------------
$env = load_env(dirname(__DIR__) . '/.env');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, ['error' => 'POST required.']);

$ready = !empty($env['DMCHAMP_TANISHQ_API_KEY']) && !empty($env['DMCHAMP_DANUBE_EVENT_ID']);
if (!$ready) out(200, ['ok' => false, 'error' => 'Booking is not configured on the server.']);

// ponytail: transition window only — accepts the rotated DANUBE_TOOL_SECRET or the old
// derived-HMAC token so the live tool keeps working while the ElevenLabs header is updated.
// Remove the legacy branch in the next deploy once the tool is repointed at the new secret.
$given = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
$newSecret = $env['DANUBE_TOOL_SECRET'] ?? '';
$legacyKey = $env['DMCHAMP_TANISHQ_API_KEY'] ?? '';
$validNew = $newSecret !== '' && is_string($given) && hash_equals($newSecret, $given);
$validLegacy = $legacyKey !== '' && is_string($given) && hash_equals(hash_hmac('sha256', 'danube-agent-tool', $legacyKey), $given);
if (!$validNew && !$validLegacy) out(403, ['ok' => false, 'error' => 'Not authorised.']);

$raw = file_get_contents('php://input', false, null, 0, 4097);
$payload = json_decode($raw, true);
if (!is_array($payload)) out(200, ['ok' => false, 'error' => 'Send a JSON object.']);

$callerId = normalise_phone_intl($_SERVER['HTTP_X_CALLER_ID'] ?? '');
if (($payload['phone'] ?? '') === '' && $callerId !== null) $payload['phone'] = $callerId;

foreach (['name', 'phone', 'appointment_type', 'day', 'time'] as $field) {
    if (!isset($payload[$field]) || !is_string($payload[$field])) out(200, ['ok' => false, 'error' => "I still need the {$field}. Ask for it, then call this again."]);
}

if (!isset(DANUBE_TYPES[$payload['appointment_type']])) {
    out(200, ['ok' => false, 'error' => 'The appointment type must be a site visit, a video consultation, or an advisor call. Ask which one, then call this again.']);
}

$phone = normalise_phone_intl($payload['phone']);
if ($phone === null) out(200, ['ok' => false, 'error' => 'That is not a valid WhatsApp number. Ask the caller to say it again with their country code, digit by digit, then call this again.']);

// A language model that must fill a phone field invents a tidy one. Never book those.
if (looks_placeholder($phone) && substr(preg_replace('/\D/', '', $phone), -9) !== substr((string) $callerId, -9)) {
    out(200, ['ok' => false, 'error' => 'That looks like a made-up number, not one the caller actually said. Ask them to say their WhatsApp number again, digit by digit, then call this again with what they said.']);
}

if (limited('danubebook:' . $phone, 10, 3600) || limited('danubebook:global:' . date('Y-m-d'), 200, 86400)) {
    out(200, ['ok' => false, 'error' => 'This number has booked several appointments in the last hour, so I cannot add another one right now.']);
}

$tz = new DateTimeZone(DANUBE_TZ);
$date = resolve_danube_date($payload['day'], $tz);
if ($date === null) out(200, ['ok' => false, 'error' => 'Send the day as a weekday in English, like Saturday, then call this again.']);

$time = parse_danube_time($payload['time']);
if ($time === null) out(200, ['ok' => false, 'error' => 'Send the time in a simple form like 11:00 or 11 AM, then call this again.']);

$key = $env['DMCHAMP_TANISHQ_API_KEY'];
$dm = fn(string $m, string $path, ?array $b = null) => http($m, 'https://api.dmchamp.com/v1' . $path . (str_contains($path, '?') ? '&' : '?') . 'apiKey=' . rawurlencode($key), [], $b);

[$status, $result] = confirm_danube_booking([
    'name' => $payload['name'], 'phone' => $phone, 'appointment_type' => $payload['appointment_type'],
    'date' => $date, 'time' => $time, 'project' => $payload['project'] ?? null,
], $env['DMCHAMP_DANUBE_EVENT_ID'], $dm);

if ($status === 200) {
    out(200, ['ok' => true, 'when' => $result['when'],
              'whatsapp' => $result['whatsappStatus'] === 'failed' ? 'not_sent' : 'sent', 'sentTo' => $result['sentTo']]);
}
// A non-2xx reply reaches the agent as a bare "Error code: N" with no reason, so anything the
// caller can fix on the call comes back 200 with ok:false and a sentence she can read out.
out(200, ['ok' => false, 'error' => $result['error'] ?? 'The booking could not be saved.']);
