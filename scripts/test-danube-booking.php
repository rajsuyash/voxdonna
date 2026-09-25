<?php
// Run: php scripts/test-danube-booking.php. Provider calls are stubbed; nothing is sent.
define('DANUBE_TEST', true);
require __DIR__ . '/../demo/danube-book.php';

function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$tz = new DateTimeZone(DANUBE_TZ);
$now = new DateTimeImmutable('2026-09-25 09:00:00', $tz); // Friday

// --- phone normalisation: international + UAE + India, per the brief's owner test number ---
foreach ([
    ['+33766158499', '+33766158499'],   // owner test number, France
    ['+33 7 66 15 84 99', '+33766158499'],
    ['00971501234567', '+971501234567'],
    ['0501234567', '+971501234567'],   // bare UAE mobile
    ['9876543211', '+919876543211'],   // Indian mobile fallback
    ['+91 98765 43211', '+919876543211'],
] as [$in, $want]) {
    check(normalise_phone_intl($in) === $want, "Normalise {$in} -> {$want}.");
}
foreach (['1234567', '', '+3', 'not a number', '5551234567', '+9719876500001'] as $bad) {
    check(normalise_phone_intl($bad) === null, "Reject ambiguous/invalid {$bad}.");
}
// A dialogue model sometimes wraps a bare Indian 10-digit number in a "+971" it invented —
// the wrong length after the country code must be rejected, not accepted as a plausible number.

// --- placeholder numbers ---
foreach (['+919876543210', '+919999999999', '+33111111111', '+971500000000'] as $ph) {
    check(looks_placeholder($ph), "Flag placeholder {$ph}.");
}
check(!looks_placeholder('+33766158499'), 'Owner test number is not a placeholder.');
check(!looks_placeholder('+971501234567'), 'A real-looking UAE number is not a placeholder.');

// --- weekday resolution ---
check(resolve_danube_date('Saturday', $tz, $now) === '2026-09-26', 'Resolve Saturday to the next occurrence.');
check(resolve_danube_date('Friday', $tz, $now) === '2026-09-25', 'Same weekday as today resolves to today.');
check(resolve_danube_date('next Friday', $tz, $now) === '2026-10-02', '"next" pushes to the following week.');
check(resolve_danube_date('tomorrow', $tz, $now) === '2026-09-26', 'Relative words resolve correctly.');
check(resolve_danube_date('whenever', $tz, $now) === null, 'Reject an unresolvable day.');

// --- time parsing ---
foreach ([['11:00', '11:00'], ['11 AM', '11:00'], ['11am', '11:00'], ['2:30 pm', '14:30'], ['14:00', '14:00'], ['12 PM', '12:00'], ['12 AM', '00:00']] as [$in, $want]) {
    check(parse_danube_time($in) === $want, "Parse time {$in} -> {$want}.");
}
foreach (['25:00', 'teatime', '13 AM', ''] as $bad) check(parse_danube_time($bad) === null, "Reject bad time {$bad}.");

// --- slot validation: hours, notice, booking window ---
check(validate_danube_slot('2026-09-26', '11:00', $tz, $now)['ok'], 'A normal daytime slot with notice is valid.');
check(!validate_danube_slot('2026-09-25', '09:30', $tz, $now)['ok'], 'Reject a slot before opening.');
foreach (['09:30', '19:00', '19:30', '11:15'] as $badTime) {
    check(!validate_danube_slot('2026-09-26', $badTime, $tz, $now)['ok'], "Reject out-of-hours/off-grid time {$badTime}.");
}
check(!validate_danube_slot('2026-09-25', '10:00', $tz, $now)['ok'], 'Reject a same-day slot inside the two-hour notice window.');
check(validate_danube_slot('2026-09-25', '11:30', $tz, $now)['ok'], 'A same-day slot past the notice window is valid.');
check(!validate_danube_slot('2026-09-24', '11:00', $tz, $now)['ok'], 'Reject a slot in the past.');
check(!validate_danube_slot('2026-11-01', '11:00', $tz, $now)['ok'], 'Reject a slot beyond the booking window.');
check(!validate_danube_slot('2026-09-31', '11:00', $tz, $now)['ok'], 'Reject an invalid calendar date.');
check(!validate_danube_slot([], '11:00', $tz, $now)['ok'], 'Reject a non-string date.');

$slot = validate_danube_slot('2026-09-26', '11:00', $tz, $now);
check($slot['label'] === 'Saturday 26 September, 11:00 AM Dubai time', 'Label reads out the weekday, date and Dubai time.');
check(str_ends_with($slot['startISO'], '+04:00'), 'ISO start time carries the Dubai UTC offset.');

// --- provider-level behaviour: confirm_danube_booking with a stubbed DM Champ ---
$directory = sys_get_temp_dir() . '/danube-check-' . bin2hex(random_bytes(8));
$body = ['name' => 'Demo Test', 'phone' => '+33766158499', 'appointment_type' => 'video_consultation', 'date' => '2026-09-26', 'time' => '11:00', 'project' => 'Oceanz'];
$calls = [];
$sendReply = [200, ['success' => false]];
$appointmentReply = [201, ['success' => true, 'data' => ['appointment_id' => 'appointment-1']]];
$lookupReply = [200, ['success' => true, 'contact' => ['id' => 'contact-1']]];
$updateReply = [200, ['success' => true]];
$dm = function (string $method, string $path, ?array $payload = null) use (&$calls, &$sendReply, &$appointmentReply, &$lookupReply, &$updateReply): array {
    $calls[] = [$method, $path, $payload];
    if ($method === 'GET') return $lookupReply;
    if ($method === 'PUT') return $updateReply;
    if ($path === '/contacts') return [201, ['success' => true, 'data' => ['contactId' => 'contact-new']]];
    if ($path === '/appointments') return $appointmentReply;
    if ($path === '/whatsapp-web/send') return $sendReply;
    throw new RuntimeException('Unexpected provider request.');
};
$count = function (string $path) use (&$calls): int { return count(array_filter($calls, fn($call) => $call[1] === $path)); };

try {
    // Happy path with a WhatsApp failure first: booking still succeeds, WhatsApp reported not sent.
    [$status, $result] = confirm_danube_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'failed', 'Booking succeeds even when the WhatsApp send fails.');
    check($result['when'] === 'Saturday 26 September, 11:00 AM Dubai time', 'Booking result carries the human-readable slot.');

    // Retry only re-sends WhatsApp, never re-books.
    $sendReply = [202, ['success' => true, 'queued' => true]];
    [$status, $result] = confirm_danube_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'queued', 'Retry recovers a failed WhatsApp send.');
    check($count('/appointments') === 1 && $count('/whatsapp-web/send') === 2, 'Retry never books the appointment twice.');

    // Full repeat is idempotent and makes no provider calls once WhatsApp already succeeded.
    $before = count($calls);
    check(confirm_danube_booking($body, 'event', $dm, $directory)[1]['repeated'], 'A repeat of a successful booking is reported as repeated.');
    check(count($calls) === $before, 'A successful repeat makes no provider calls.');

    // 409 slot conflict.
    $body2 = $body; $body2['time'] = '12:00';
    $appointmentReply = [409, ['success' => false]];
    [$status, $result] = confirm_danube_booking($body2, 'event', $dm, $directory);
    check($status === 502 && str_contains($result['error'], 'taken'), '409 from the provider is reported as a taken slot.');

    // Ambiguous appointment result is never success, and is not retried into a duplicate.
    $body3 = $body; $body3['time'] = '13:00';
    $appointmentReply = [0, null];
    [$status, $result] = confirm_danube_booking($body3, 'event', $dm, $directory);
    check($status === 502 && $result['retryable'] === false, 'A timed-out appointment call is never reported as success.');
    $before = count($calls);
    confirm_danube_booking($body3, 'event', $dm, $directory);
    check(count($calls) === $before, 'An unconfirmed booking is never submitted twice.');

    // Malformed / missing input never reaches the provider.
    $before = count($calls);
    check(confirm_danube_booking(['name' => [], 'phone' => []], 'event', $dm, $directory)[0] === 400 && count($calls) === $before, 'Malformed input causes no provider calls.');
    check(confirm_danube_booking(['name' => 'X', 'phone' => '+33766158499', 'appointment_type' => 'not_a_type', 'date' => '2026-09-26', 'time' => '11:00'], 'event', $dm, $directory)[0] === 400, 'Reject an unknown appointment type.');

    foreach (glob($directory . '/*') as $file) {
        if (!str_ends_with($file, '.lock')) check(is_array(json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR)), 'Written records remain valid JSON.');
    }
    echo "PASS: phone normalisation, placeholder detection, weekday/time parsing, slot validation, provider failures, retries, 409 handling and persisted JSON.\n";
} finally {
    foreach (glob($directory . '/*') as $file) unlink($file);
    if (is_dir($directory)) rmdir($directory);
}
