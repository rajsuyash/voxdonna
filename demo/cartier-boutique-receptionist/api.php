<?php
/**
 * Cartier boutique receptionist demo — backend for the ElevenLabs voice page (French + English).
 * Routes (rewritten from api/<route>): config, session, agent/book.
 * Secrets from the site .env: ELEVENLABS_API_KEY, DMCHAMP_TANISHQ_API_KEY, DMCHAMP_EVENT_ID
 * (the booking backend is the shared DM Champ account the Tanishq demo uses). Nothing secret leaves this file.
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');
date_default_timezone_set('Europe/Paris');

const ALLOWED_ORIGINS = ['https://voxdonna.com', 'https://www.voxdonna.com'];
const AGENTS = ['fr' => 'agent_3901m5evvdgmf7w8ewzm96xhr22a', 'en' => 'agent_4801m5evvfgcekx872m9dfep15t5'];
const BOOKING_DAYS = 28;
const DAILY_SESSION_CAP = 80;
const SLOT_STEP = 30;

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
    $file = sys_get_temp_dir() . '/cartier_' . md5($key);
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

function stores(): array { return json_decode(file_get_contents(__DIR__ . '/stores.json'), true)['stores']; }
function store_by_id(?string $id): ?array { foreach (stores() as $s) if ($s['id'] === $id) return $s; return null; }
/** Lowercase and strip accents/hyphens/apostrophes so "Élysées", "elysees" and "Saint-Honoré" all match. */
function fold(string $s): string {
    $s = strtr(mb_strtolower(trim($s)), ['é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e', 'à' => 'a', 'â' => 'a', 'î' => 'i', 'ï' => 'i', 'ô' => 'o', 'ù' => 'u', 'û' => 'u', 'ç' => 'c', '-' => ' ', "'" => ' ', '’' => ' ']);
    return preg_replace('/\s+/', ' ', $s);
}
/** Match a boutique the agent named out loud: "Rue de la Paix", "Champs-Elysees", "Nice". */
function store_by_label(?string $label): ?array {
    if (!is_string($label)) return null;
    $needle = fold($label);
    if ($needle === '') return null;
    $all = stores();
    foreach ($all as $s) if (fold($s['id']) === $needle || fold($s['name']) === $needle) return $s;
    foreach ($all as $s) if (str_contains(fold($s['name']), $needle) || str_contains($needle, fold($s['name']))) return $s;
    return null;
}

/** The agent says "Saturday", not a date. Resolve spoken days here so it cannot invent one. */
function resolve_date(?string $raw, ?DateTimeImmutable $now = null): ?string {
    if (!is_string($raw)) return null;
    $raw = strtolower(trim($raw));
    $now ??= new DateTimeImmutable('now');
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/D', $raw)) return $raw;
    $words = ['today' => 0, 'tomorrow' => 1, 'day after tomorrow' => 2];
    if (isset($words[$raw])) return $now->modify('+' . $words[$raw] . ' day')->format('Y-m-d');
    foreach (['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'] as $day) {
        if (!str_contains($raw, $day)) continue;
        $sameDay = strtolower($now->format('l')) === $day;
        return ($sameDay && !str_contains($raw, 'next')) ? $now->format('Y-m-d') : $now->modify('next ' . $day)->format('Y-m-d');
    }
    return null;
}

function mins(string $hhmm): int { [$h, $m] = array_map('intval', explode(':', $hhmm)); return $h * 60 + $m; }

const DAY_NAMES = [
    'fr' => ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'],
    'en' => ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
];
const MONTH_NAMES = [
    'fr' => ['', 'janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'],
    'en' => ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'],
];

function clock(string $hhmm, string $lang): string {
    [$h, $m] = array_map('intval', explode(':', $hhmm));
    if ($lang === 'fr') return $m === 0 ? "{$h}h" : sprintf('%dh%02d', $h, $m);
    $twelve = (($h + 11) % 12) + 1;
    return ($m === 0 ? (string) $twelve : sprintf('%d:%02d', $twelve, $m)) . ($h < 12 ? 'am' : 'pm');
}

/** "du lundi au samedi 11h-19h ; dimanche 12h-19h": consecutive days with the same hours are grouped (Monday first). */
function hours_text(array $store, string $lang): string {
    $order = [1, 2, 3, 4, 5, 6, 0];
    $closed = $lang === 'fr' ? 'fermé' : 'closed';
    $runs = [];
    foreach ($order as $d) {
        $ranges = $store['hours'][$d];
        $text = $ranges ? implode($lang === 'fr' ? ' et ' : ' and ', array_map(fn($r) => clock($r[0], $lang) . '-' . clock($r[1], $lang), $ranges)) : $closed;
        if ($runs && $runs[count($runs) - 1]['text'] === $text) $runs[count($runs) - 1]['days'][] = $d;
        else $runs[] = ['text' => $text, 'days' => [$d]];
    }
    $names = DAY_NAMES[$lang];
    return implode('; ', array_map(function ($run) use ($names, $lang) {
        $first = $names[$run['days'][0]];
        $last = $names[$run['days'][count($run['days']) - 1]];
        $days = count($run['days']) === 1 ? $first : ($lang === 'fr' ? "du {$first} au {$last}" : "{$first} to {$last}");
        return "{$days} {$run['text']}";
    }, $runs));
}

/** Everything the agent may say about today, the visitor and the boutiques; the prompt carries the rules. */
function session_facts(string $name, string $lang): string {
    $today = new DateTime('now');
    $calendar = [];
    for ($i = 0; $i <= BOOKING_DAYS; $i++) {
        $d = (clone $today)->modify("+{$i} day");
        $w = (int) $d->format('w');
        $calendar[] = $lang === 'fr'
            ? DAY_NAMES['fr'][$w] . ' ' . $d->format('j') . ' ' . MONTH_NAMES['fr'][(int) $d->format('n')] . ' ' . $d->format('Y') . " ({$d->format('l')})"
            : $d->format('l j F Y');
    }
    $lines = array_map(fn($s) => $lang === 'fr'
        ? "- {$s['city']}, {$s['name']} : {$s['address']}. Horaires habituels : " . hours_text($s, 'fr') . '.'
        : "- {$s['city']}, {$s['name']}: {$s['address']}. Usual hours: " . hours_text($s, 'en') . '.', stores());
    if ($lang === 'fr') {
        $visitor = $name !== '' ? "Le client s'appelle {$name} ; utilisez son prénom une fois, naturellement." : "Vous ne connaissez pas le prénom du client ; ne le demandez que pour le rendez-vous.";
        return "Nous sommes le " . DAY_NAMES['fr'][(int) $today->format('w')] . ' ' . $today->format('j') . ' ' . MONTH_NAMES['fr'][(int) $today->format('n')] . ' ' . $today->format('Y') . " (heure de Paris, aujourd'hui = " . $today->format('l, Y-m-d') . "). {$visitor} Demandez au client son numéro WhatsApp pendant l'appel, répétez-le, et envoyez vous-même la confirmation avec l'outil. Tout ce qu'il a tapé sur la page ne sert que de repli.\n"
            . "Utilisez ce calendrier pour situer les jours ; n'inventez jamais la date d'un jour de la semaine (le nom anglais entre parenthèses est celui à envoyer à l'outil) : " . implode(' ; ', $calendar) . ".\n\n"
            . "## Boutiques de cette démonstration\n\nToutes ces boutiques sont en France. Les adresses et horaires ci-dessous sont les seuls que vous pouvez donner ; ce sont les horaires habituels du site Cartier, la boutique confirme les jours fériés. Un horaire d'ouverture ne veut pas dire qu'un créneau est libre : l'outil vérifie l'heure du rendez-vous.\n" . implode("\n", $lines) . "\n";
    }
    $visitor = $name !== '' ? "The guest's name is {$name}; use it once, naturally." : "You do not know the guest's name; only ask for it for the booking.";
    return 'Today is ' . $today->format('l, Y-m-d') . " (Paris time). {$visitor} Ask the guest for their WhatsApp number on the call, read it back, and send the confirmation yourself with the booking tool. Anything they typed on the page is only a fallback.\n"
        . 'Use this calendar to resolve days; never invent the date for a weekday: ' . implode('; ', $calendar) . ".\n\n"
        . "## Boutiques in this demonstration\n\nAll boutiques below are in France. These addresses and hours are the only ones you may give; they are the usual hours from Cartier's website and the boutique confirms public holidays. Opening hours do not mean a slot is free: the tool checks the visit time.\n" . implode("\n", $lines) . "\n";
}

function normalise_phone($raw): ?string {
    $raw = trim((string) $raw);
    $digits = preg_replace('/\D/', '', $raw);
    if (str_starts_with($raw, '+') || str_starts_with($raw, '00')) {
        if (str_starts_with($raw, '00')) $digits = substr($digits, 2);
        return preg_match('/^[1-9]\d{7,14}$/D', $digits) ? '+' . $digits : null;
    }
    // French national format: 0 + nine digits (06 12 34 56 78) becomes +33 and the last nine.
    if (strlen($digits) === 10 && preg_match('/^0[1-9]\d{8}$/D', $digits)) return '+33' . substr($digits, 1);
    return strlen($digits) === 11 && preg_match('/^33[1-9]\d{8}$/D', $digits) ? '+' . $digits : null;
}

function validate_slot($storeId, $date, $time, string $lang = 'fr', ?DateTimeImmutable $now = null): array {
    if (!is_string($storeId) || !is_string($date) || !is_string($time)) return ['ok' => false, 'reason' => 'Date, time and boutique must be text.'];
    $store = store_by_id($storeId);
    if (!$store) return ['ok' => false, 'reason' => 'Pick a boutique from the list.'];
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $date) || !preg_match('/^(?:[01]\d|2[0-3]):[0-5]\d$/D', $time)) return ['ok' => false, 'reason' => 'Date or time is incomplete.'];
    $tz = new DateTimeZone('Europe/Paris');
    $now = ($now ?? new DateTimeImmutable('now'))->setTimezone($tz);
    $today = new DateTime($now->format('Y-m-d'));
    $day = DateTime::createFromFormat('!Y-m-d', $date);
    if (!$day || $day->format('Y-m-d') !== $date) return ['ok' => false, 'reason' => 'Choose a valid calendar date.'];
    $offset = (int) $today->diff($day)->format('%r%a');
    if ($offset < 0 || $offset > BOOKING_DAYS) return ['ok' => false, 'reason' => 'Visits can be booked from today up to ' . BOOKING_DAYS . ' days ahead.'];
    if ($offset === 0 && new DateTimeImmutable("{$date}T{$time}:00", $tz) < $now->modify('+2 hours')) return ['ok' => false, 'reason' => 'Same-day visits need at least two hours notice.'];
    $weekday = (int) $day->format('w');
    $dayName = DAY_NAMES['en'][$weekday];
    $ranges = $store['hours'][$weekday];
    if (!$ranges) return ['ok' => false, 'reason' => "{$store['name']} is closed on {$dayName}. Its usual hours: " . hours_text($store, 'en') . '. Offer another day.'];
    $t = mins($time);
    $fits = array_filter($ranges, fn($r) => $t >= mins($r[0]) && $t <= mins($r[1]) - SLOT_STEP);
    if (!$fits || $t % SLOT_STEP) {
        return ['ok' => false, 'reason' => "{$store['name']} takes visits on the hour or half hour, from opening until 30 minutes before closing. On {$dayName} the usual hours are " . hours_text($store, 'en') . '. Offer a time within them.'];
    }
    $at = (int) $day->format('j') . ' ' . MONTH_NAMES[$lang][(int) $day->format('n')];
    $label = $lang === 'fr'
        ? DAY_NAMES['fr'][$weekday] . " {$at} à " . clock($time, 'fr') . ' (heure de Paris)'
        : "{$dayName} {$at} at " . date('g:i A', strtotime($time)) . ' (Paris time)';
    return ['ok' => true, 'store' => $store, 'startISO' => (new DateTimeImmutable("{$date}T{$time}:00", $tz))->format('c'), 'label' => $label];
}

function confirmation_message(string $name, array $store, string $label, string $lang): string {
    if ($lang === 'fr') {
        return "Bonjour {$name}, votre visite démo à la boutique Cartier est enregistrée.\n\nBoutique Cartier {$store['name']}, {$store['city']}\n{$store['address']}\n{$label}\n\nCeci est une démonstration Voxdonna, pas une réservation confirmée avec Cartier ni avec la boutique. Répondez ici pour échanger sur la visite avec l'assistant WhatsApp.";
    }
    return "Hello {$name}, your demo visit to the Cartier boutique has been saved.\n\nCartier boutique {$store['name']}, {$store['city']}\n{$store['address']}\n{$label}\n\nThis is a Voxdonna demonstration, not a reservation confirmed with Cartier or the boutique. Reply here to discuss the visit with the WhatsApp assistant.";
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

function confirm_booking(array $body, string $eventId, callable $dm, string $lang = 'fr', ?string $directory = null): array {
    if (!is_string($body['name'] ?? null) || !is_string($body['phone'] ?? null)) return [400, ['error' => 'A name and a WhatsApp number are needed.']];
    $name = mb_substr(trim($body['name']), 0, 60);
    $phone = normalise_phone($body['phone']);
    if ($name === '' || $phone === null) return [400, ['error' => 'A name and a valid WhatsApp number are needed, with country code if outside France.']];
    $slot = validate_slot($body['storeId'] ?? null, $body['date'] ?? null, $body['time'] ?? null, $lang);
    if (!$slot['ok']) return [400, ['error' => $slot['reason']]];
    // ponytail: one PHP host; use shared durable storage before adding another host.
    $directory ??= dirname(__DIR__, 3) . '/.cartier-bookings';
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) return [503, ['error' => 'Booking storage is unavailable.']];
    $path = $directory . '/' . hash('sha256', $eventId . '|' . $phone . '|' . $body['storeId'] . '|' . $slot['startISO']);
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
            // ponytail: contact field names are the ones the shared DM Champ account already accepts for the Tanishq demo.
            $fields = ['firstName' => $name, 'channel' => 'whatsapp_web', 'custom_fields' => ['tanishq_store' => 'Cartier ' . $slot['store']['name'], 'tanishq_visit' => $slot['label']]];
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
            if (!dm_ok($cs, $updated)) return [502, ['error' => 'Could not save the visit details. Please retry shortly.']];
            // Persist before each external write: a lost response must never trigger a duplicate.
            save_booking($path, ['phase' => 'booking_unknown']);
            [$as, $appt] = $dm('POST', '/appointments', ['contact_id' => $contactId, 'event_id' => $eventId, 'start_time' => $slot['startISO']]);
            $appointmentId = dm_ok($as, $appt) ? dm_id($appt, 'appointment') : null;
            if (!$appointmentId) {
                if ($as >= 400 && $as < 500) {
                    save_booking($path, []);
                    return [502, ['error' => $as === 409 ? 'That slot has just been taken. Please pick another time.' : 'The booking was rejected. Please retry shortly.']];
                }
                return [502, ['error' => 'The booking result is unconfirmed. Ask the demo operator to check it before trying again.', 'retryable' => false]];
            }
            $result = ['appointmentId' => $appointmentId, 'contactId' => $contactId, 'store' => "{$slot['store']['name']}, {$slot['store']['city']}", 'when' => $slot['label'], 'sentTo' => $phone, 'whatsappStatus' => 'unknown'];
        }
        $result['whatsappStatus'] = 'unknown';
        save_booking($path, ['result' => $result]);
        [$ws, $sent] = $dm('POST', '/whatsapp-web/send', ['phoneNumber' => $phone, 'message' => confirmation_message($name, $slot['store'], $slot['label'], $lang)]);
        $sentData = dm_data($sent);
        if (dm_ok($ws, $sent) && ($sent['success'] ?? $sentData['success'] ?? false) === true && ($sentData['queued'] ?? true) !== false) $result['whatsappStatus'] = 'queued';
        elseif (($ws >= 400 && $ws < 500) || ($ws >= 200 && $ws < 300 && (($sent['success'] ?? null) === false || ($sentData['success'] ?? null) === false))) $result['whatsappStatus'] = 'failed';
        save_booking($path, ['result' => $result]);
        return [200, $result];
    } catch (Throwable $error) {
        error_log('Cartier booking failed: ' . get_class($error));
        return [503, ['error' => 'Booking could not finish. Retry the same visit to check its saved status.']];
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}

if (PHP_SAPI === 'cli' && defined('CARTIER_TEST')) return;

// ---------------------------------------------------------------------------
$env = load_env(dirname(__DIR__, 2) . '/.env');
$route = $_GET['route'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$booking_ready = !empty($env['DMCHAMP_TANISHQ_API_KEY']) && !empty($env['DMCHAMP_EVENT_ID']);

if ($route === 'config') {
    out(200, [
        'frenchConfigured' => !empty($env['ELEVENLABS_API_KEY']),
        'englishConfigured' => !empty($env['ELEVENLABS_API_KEY']),
        'bookingConfigured' => $booking_ready,
        'stores' => array_map(fn($s) => ['id' => $s['id'], 'city' => $s['city'], 'name' => $s['name']], stores()),
    ]);
}

// --- The voice agent books and sends the WhatsApp itself, through its webhook tool.
// The tool has no page and no browser origin, so this route authenticates with a token derived from a secret the server already holds.
if ($route === 'agent/book') {
    if ($method !== 'POST') out(405, ['error' => 'POST required.']);
    if (!$booking_ready) out(200, ['ok' => false, 'error' => 'Booking is not configured on the server.']);
    $expected = hash_hmac('sha256', 'cartier-agent-tool', $env['DMCHAMP_TANISHQ_API_KEY']);
    $given = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
    if (!is_string($given) || !hash_equals($expected, $given)) out(403, ['ok' => false, 'error' => 'Not authorised.']);
    $lang = ($_GET['lang'] ?? 'fr') === 'en' ? 'en' : 'fr';
    $raw = file_get_contents('php://input', false, null, 0, 4097);
    $payload = json_decode($raw, true);
    if (!is_array($payload)) out(200, ['ok' => false, 'error' => 'Send a JSON object.']);
    $callerId = normalise_phone($_SERVER['HTTP_X_CALLER_ID'] ?? '');
    if (($payload['phone'] ?? '') === '' && $callerId !== null) $payload['phone'] = $callerId;
    foreach (['name', 'phone', 'store', 'date', 'time'] as $field) {
        if (!isset($payload[$field]) || !is_string($payload[$field])) out(200, ['ok' => false, 'error' => "I still need the {$field}. Ask for it, then call this again."]);
    }
    $phone = normalise_phone($payload['phone']);
    // A language model that must fill a phone field invents a tidy one. Never book those.
    $digits = $phone === null ? '' : preg_replace('/\D/', '', $phone);
    $tail = substr($digits, -10);
    $placeholder = $tail !== '' && (
        in_array($tail, ['9876543210', '1234567890', '0123456789', '9999999999', '1111111111', '0000000000', '3612345678', '3601020304', '3600000000', '3123456789'], true)
        || preg_match('/^(\d)\1{9}$/D', $tail)
    );
    if ($placeholder && $tail !== substr((string) $callerId, -10)) {
        out(200, ['ok' => false, 'error' => 'That looks like a made-up number, not one the caller gave you. Ask them to say their WhatsApp number, repeat it back, and call this again with what they actually said.']);
    }
    if ($phone === null) out(200, ['ok' => false, 'error' => 'That is not a valid WhatsApp number. Ask them to say it again, digit by digit, then call this again.']);
    if (limited('agentbook:' . $phone, 10, 3600) || limited('agentbook:global:' . date('Y-m-d'), 200, 86400)) {
        out(200, ['ok' => false, 'error' => 'This number has booked several visits in the last hour, so I cannot add another one right now.']);
    }
    $store = store_by_label($payload['store']);
    if ($store === null && !preg_match('/[A-Za-z]/', $payload['store'])) {
        out(200, ['ok' => false, 'error' => 'Send the boutique name in English letters, for example Rue de la Paix or Nice, and call this again.']);
    }
    if ($store === null) out(200, ['ok' => false, 'error' => 'That boutique is not in this demo. Ask which area, then name one boutique from the list.']);
    $date = resolve_date($payload['date']);
    if ($date === null) out(200, ['ok' => false, 'error' => 'Send the day as a weekday in English, like Saturday, then call this again.']);
    $key = $env['DMCHAMP_TANISHQ_API_KEY'];
    $dm = fn(string $m, string $path, ?array $b = null) => http($m, 'https://api.dmchamp.com/v1' . $path . (str_contains($path, '?') ? '&' : '?') . 'apiKey=' . rawurlencode($key), [], $b);
    [$status, $result] = confirm_booking([
        'name' => $payload['name'], 'phone' => $phone,
        'storeId' => $store['id'], 'date' => $date, 'time' => $payload['time'],
    ], $env['DMCHAMP_EVENT_ID'], $dm, $lang);
    if ($status === 200) {
        out(200, ['ok' => true, 'store' => $result['store'], 'when' => $result['when'],
                  'whatsapp' => $result['whatsappStatus'] === 'failed' ? 'not_sent' : 'sent', 'sentTo' => $result['sentTo']]);
    }
    // A non-2xx reply reaches the agent as a bare "Error code: N" with no reason, so anything the
    // caller can fix on the call comes back 200 with ok:false and a sentence she can read out.
    out(200, ['ok' => false, 'error' => $result['error'] ?? 'The booking could not be saved.']);
}

if ($method !== 'POST') out(405, ['error' => 'POST required.']);
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (!in_array($origin, ALLOWED_ORIGINS, true) || ($_SERVER['HTTP_X_DEMO_REQUEST'] ?? '') !== '1') out(403, ['error' => 'Open the demo page before starting a conversation.']);
$raw = file_get_contents('php://input', false, null, 0, 16385);
if (strlen($raw) > 16384) out(413, ['error' => 'Request is too large.']);
$body = json_decode($raw);
if (!is_object($body)) out(400, ['error' => 'Send a JSON object.']);
$body = (array) $body;
if (isset($body['name']) && !is_string($body['name'])) out(400, ['error' => 'name must be text.']);

if ($route === 'session') {
    $language = $_GET['language'] ?? '';
    if (!in_array($language, ['fr', 'en'], true)) out(400, ['error' => 'Choose French or English.']);
    if (limited("session:$ip", 6, 600)) out(429, ['error' => 'Too many starts. Please wait a few minutes.']);
    if (limited('session:global:' . date('Y-m-d'), DAILY_SESSION_CAP, 86400)) out(503, ['error' => 'The demo is busy today. Please try again tomorrow.']);
    $name = mb_substr(trim((string) ($body['name'] ?? '')), 0, 60);
    $key = $env['ELEVENLABS_API_KEY'] ?? '';
    if ($key === '') out(503, ['error' => 'Voice credentials are not configured.']);
    $agent = $env['ELEVENLABS_CARTIER_' . strtoupper($language) . '_AGENT_ID'] ?? AGENTS[$language];
    [$status, $data] = http('GET', 'https://api.elevenlabs.io/v1/convai/conversation/get-signed-url?agent_id=' . rawurlencode($agent), ["xi-api-key: {$key}"]);
    $url = $data['signed_url'] ?? '';
    if ($status >= 300 || !str_starts_with($url, 'wss://api.elevenlabs.io/')) out(502, ['error' => "Voice provider rejected the session ({$status}). Please retry shortly."]);
    out(200, ['url' => $url, 'provider' => 'elevenlabs', 'sampleRate' => 16000, 'maxSeconds' => 300, 'agentId' => $agent,
        'dynamicVariables' => ['channel' => 'web', 'session_facts' => session_facts($name, $language)]]);
}

out(404, ['error' => 'Not found.']);
