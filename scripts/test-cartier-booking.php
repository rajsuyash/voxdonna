<?php
// Run: php scripts/test-cartier-booking.php. Provider calls are stubbed; nothing is sent.
define('CARTIER_TEST', true);
require __DIR__ . '/../demo/cartier-boutique-receptionist/api.php';

function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$storeId = stores()[0]['id'];
for ($i = 3; $i <= 14; $i++) {
    $date = (new DateTimeImmutable("+{$i} days"))->format('Y-m-d');
    foreach (['fr', 'en'] as $lang) if (!validate_slot($storeId, $date, '14:00', $lang)['ok']) continue 2;
    break;
}
check(validate_slot($storeId, $date, '14:00')['ok'], 'Found a bookable test slot.');

$directory = sys_get_temp_dir() . '/cartier-check-' . bin2hex(random_bytes(8));
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
    foreach (['fr' => ['+33612345678', 'MikbXQUGD2TazI5lAN8Z'], 'en' => ['+33698765432', 'R9Aj0QlGkIOajaIPfACp']] as $lang => [$phone, $templateId]) {
        $calls = [];
        $body = ['name' => 'Demo Test', 'phone' => $phone, 'storeId' => $storeId, 'date' => $date, 'time' => '14:00'];
        $sendReply = [200, ['success' => false]];
        [$status, $result] = confirm_booking($body, 'event', $dm, $lang, $directory);
        check($status === 200 && $result['whatsappStatus'] === 'failed', "[{$lang}] Keep saved appointment when WhatsApp rejects a send.");
        $sendReply = [202, ['success' => true, 'queued' => true]];
        [$status, $result] = confirm_booking($body, 'event', $dm, $lang, $directory);
        check($status === 200 && $result['whatsappStatus'] === 'queued', "[{$lang}] Retry only the failed message.");
        check($count('/appointments') === 1 && $count('/whatsapp-templates/send') === 2, "[{$lang}] Retry never books the appointment twice.");
        $sent = array_values(array_filter($calls, fn($call) => $call[1] === '/whatsapp-templates/send'))[0][2];
        check($sent['contactId'] === 'contact-1' && $sent['whatsappTemplateId'] === $templateId && array_keys($sent['variables']) === ['first_name', 'store', 'address', 'visit_time'], "[{$lang}] Template send carries contact, template and four variables.");
    }
    echo "PASS: French and English template sends and retry safety.\n";
} finally {
    foreach (glob($directory . '/*') as $file) unlink($file);
    if (is_dir($directory)) rmdir($directory);
}
