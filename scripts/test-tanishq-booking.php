<?php
// Run: php scripts/test-tanishq-booking.php. Provider calls are stubbed; nothing is sent.
define('TANISHQ_TEST', true);
require __DIR__ . '/../demo/tanishq-personal-shopper/api.php';

function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$now = new DateTimeImmutable('2026-09-11 12:00:00', new DateTimeZone('Asia/Kolkata'));
check(validate_slot('mum-powai', '2026-09-11', '14:00', $now)['ok'], 'Exactly two hours notice is valid.');
foreach ([['2026-09-31', '14:00'], ['2026-09-12', '13:60'], ['2026-09-12', '14:90'], ['2026-09-12', '14:15'], ['2026-09-11', '13:30'], ['2026-10-10', '14:00'], [[], '14:00']] as [$date, $time]) {
    check(!validate_slot('mum-powai', $date, $time, $now)['ok'], 'Reject invalid date, time or window.');
}
check(!validate_slot([], '2026-09-12', '14:00', $now)['ok'], 'Reject non-string store.');
foreach ([['98765 43210', '+919876543210'], ['919876543210', '+919876543210'], ['+91 98765-43210', '+919876543210'], ['+31 6 1234 5678', '+31612345678'], ['0031612345678', '+31612345678'], ['+1 415 555 0100', '+14155550100']] as [$in, $want]) {
    check(normalise_phone($in) === $want, "Normalise {$in}.");
}
foreach (['+3', '12345', '1234567890', '+91 12345 67890', '+0 123456789', ''] as $bad) check(normalise_phone($bad) === null, "Reject {$bad}.");
check(dm_id(['success' => true, 'data' => ['contactId' => 'contact-1']], 'contact') === 'contact-1', 'Read nested contact ID.');
foreach ([[0, null], [200, null], [200, ['success' => false]], [200, ['data' => ['success' => false]]], [200, ['error_code' => 409]], [500, ['id' => 'bad']]] as [$status, $data]) {
    check(!dm_ok($status, $data), 'HTTP status and response body both determine success.');
}

$directory = sys_get_temp_dir() . '/tanishq-check-' . bin2hex(random_bytes(8));
$body = ['name' => 'Demo Test', 'phone' => '+919000000000', 'storeId' => 'mum-powai', 'date' => (new DateTimeImmutable('+1 day'))->format('Y-m-d'), 'time' => '14:00'];
$calls = [];
$sendReply = [200, ['success' => false]];
$appointmentReply = [201, ['success' => true, 'data' => ['appointment_id' => 'appointment-1']]];
$lookupReply = [200, ['success' => true, 'contact' => ['id' => 'contact-1']]];
$updateReply = [200, ['success' => true]];
$nestedCheck = false;
$dm = function (string $method, string $path, ?array $payload = null) use (&$dm, &$calls, &$sendReply, &$appointmentReply, &$lookupReply, &$updateReply, &$nestedCheck, &$body, $directory): array {
    $calls[] = [$method, $path, $payload];
    if ($method === 'GET') return $lookupReply;
    if ($method === 'PUT') return $updateReply;
    if ($path === '/contacts') return [201, ['success' => true, 'data' => ['contactId' => 'contact-new']]];
    if ($path === '/appointments') {
        if ($nestedCheck) {
            $nestedCheck = false;
            check(confirm_booking($body, 'event', $dm, $directory)[0] === 409, 'Concurrent submission must not create another appointment.');
        }
        return $appointmentReply;
    }
    if ($path === '/whatsapp-web/send') return $sendReply;
    throw new RuntimeException('Unexpected provider request.');
};
$count = function (string $path) use (&$calls): int { return count(array_filter($calls, fn($call) => $call[1] === $path)); };

try {
    $nestedCheck = true;
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'failed', 'Keep saved appointment when WhatsApp rejects a send.');
    $sendReply = [202, ['success' => true, 'queued' => true]];
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'queued', 'Retry only the failed message.');
    check($count('/appointments') === 1 && $count('/whatsapp-web/send') === 2, 'Retry never books the appointment twice.');
    $before = count($calls);
    foreach (glob($directory . '/*') as $file) touch($file, time() - 900);
    check(confirm_booking($body, 'event', $dm, $directory)[1]['repeated'], 'Deduplication survives the former ten-minute expiry.');
    check(count($calls) === $before, 'Successful repeat makes no provider calls.');

    $body['storeId'] = 'mum-bandra';
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 200 && $count('/appointments') === 2, 'Store is part of the booking identity.');

    $body['time'] = '15:00';
    $appointmentReply = [0, null];
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 502 && $result['retryable'] === false, 'An ambiguous appointment result is never success.');
    $before = count($calls);
    confirm_booking($body, 'event', $dm, $directory);
    check(count($calls) === $before, 'A timed-out appointment is not submitted twice.');

    $body['time'] = '15:30';
    $appointmentReply = [200, ['success' => false]];
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 502, 'A 200 error is not an appointment.');
    $body['time'] = '16:00';
    $appointmentReply = [201, ['success' => true]];
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 502, 'Never invent a missing appointment ID.');

    $body['time'] = '16:30';
    $appointmentReply = [409, ['success' => false]];
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 502, 'Report a real slot conflict.');
    $appointmentReply = [201, ['id' => 'appointment-2']];
    $sendReply = [0, null];
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'unknown', 'Message timeout preserves the appointment and reports uncertainty.');
    $before = count($calls);
    confirm_booking($body, 'event', $dm, $directory);
    check(count($calls) === $before, 'Do not resend a message whose acceptance is unknown.');

    $body['time'] = '17:00';
    $lookupReply = [503, null];
    $before = $count('/contacts');
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 502 && $count('/contacts') === $before, 'A failed lookup does not trigger contact creation.');
    $lookupReply = [404, ['success' => false]];
    $updateReply = [200, ['success' => false]];
    $before = $count('/appointments');
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 502 && $count('/appointments') === $before, 'Failed contact update stops before booking.');
    $updateReply = [200, ['success' => true]];
    $sendReply = [202, ['success' => true, 'queued' => true]];
    check(confirm_booking($body, 'event', $dm, $directory)[0] === 200, 'New contacts support nested response IDs.');

    $before = count($calls);
    check(confirm_booking(['name' => [], 'phone' => []], 'event', $dm, $directory)[0] === 400 && count($calls) === $before, 'Malformed input causes no provider calls.');
    foreach (glob($directory . '/*') as $file) {
        if (!str_ends_with($file, '.lock')) check(is_array(json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR)), 'Written records remain valid JSON.');
    }
    echo "PASS: slot validation, provider failures, nested IDs, retry safety, concurrent submission and persisted JSON.\n";
} finally {
    foreach (glob($directory . '/*') as $file) unlink($file);
    if (is_dir($directory)) rmdir($directory);
}
