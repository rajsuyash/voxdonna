<?php
// Run: php scripts/test-luke-diamond-booking.php. Provider calls are stubbed; nothing is sent.
define('LUKE_DIAMOND_TEST', true);
require __DIR__ . '/../demo/luke-diamond-personal-shopper/api.php';

function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$storeId = stores()['stores'][0]['id'];
for ($i = 3; $i <= 14; $i++) {
    $date = (new DateTimeImmutable("+{$i} days"))->format('Y-m-d');
    if (validate_slot($storeId, $date, '14:00')['ok']) break;
}
check(validate_slot($storeId, $date, '14:00')['ok'], 'Found a bookable test slot.');

$directory = sys_get_temp_dir() . '/luke-diamond-check-' . bin2hex(random_bytes(8));
$body = ['name' => 'Demo Test', 'phone' => '+919000000000', 'storeId' => $storeId, 'date' => $date, 'time' => '14:00'];
$calls = [];
$sendReply = [200, ['success' => false]];
$dm = function (string $method, string $path, ?array $payload = null) use (&$calls, &$sendReply): array {
    $calls[] = [$method, $path, $payload];
    if ($method === 'GET') return [200, ['success' => true, 'contact' => ['id' => 'contact-1']]];
    if ($method === 'PUT') return [200, ['success' => true]];
    if ($path === '/appointments') return [201, ['success' => true, 'data' => ['appointment_id' => 'appointment-1']]];
    if ($path === '/whatsapp-templates/send') return $sendReply;
    throw new RuntimeException('Unexpected provider request.');
};
$count = function (string $path) use (&$calls): int { return count(array_filter($calls, fn($call) => $call[1] === $path)); };

try {
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'failed', 'Keep saved appointment when WhatsApp rejects a send.');
    $sendReply = [202, ['success' => true, 'queued' => true]];
    [$status, $result] = confirm_booking($body, 'event', $dm, $directory);
    check($status === 200 && $result['whatsappStatus'] === 'queued', 'Retry only the failed message.');
    check($count('/appointments') === 1 && $count('/whatsapp-templates/send') === 2, 'Retry never books the appointment twice.');
    $sent = array_values(array_filter($calls, fn($call) => $call[1] === '/whatsapp-templates/send'))[0][2];
    check($sent['contactId'] === 'contact-1' && $sent['whatsappTemplateId'] === 'R9Aj0QlGkIOajaIPfACp' && array_keys($sent['variables']) === ['first_name', 'store', 'address', 'visit_time'], 'Template send carries contact, English template and four variables.');
    echo "PASS: template send and retry safety.\n";
} finally {
    foreach (glob($directory . '/*') as $file) unlink($file);
    if (is_dir($directory)) rmdir($directory);
}
