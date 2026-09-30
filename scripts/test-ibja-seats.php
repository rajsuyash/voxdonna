<?php
declare(strict_types=1);
define('IBJA_SEATS_TEST', true);
require __DIR__ . '/../ibja-seats.php';

function check(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}

$pages = [];
foreach (IBJA_PAGES as $id => $amount) {
    $pages[$id] = ['id' => $id, 'amount' => $amount, 'currency' => 'INR', 'times_paid' => 0];
}
$public = '// <<<JSON_DATA_START>>> var data = ' . json_encode(['is_test_mode' => false, 'payment_link' => $pages[array_key_first($pages)]]) . '; // <<<JSON_DATA_END>>>';
check(ibja_payment_page($public) === $pages[array_key_first($pages)], 'Parse actual public payment-page format');
try { ibja_payment_page('broken page'); throw new LogicException('Missing source accepted'); }
catch (RuntimeException $error) {}
try { ibja_payment_page(str_replace('false', 'true', $public)); throw new LogicException('Test-mode count accepted'); }
catch (RuntimeException $error) {}
check(ibja_seats($pages)['remaining'] === 10, 'Zero payments leaves ten seats');
$ids = array_keys($pages);
$pages[$ids[0]]['times_paid'] = 3;
check(ibja_seats($pages)['remaining'] === 7, 'Only bundle purchases consume the bundle allocation');
$pages[$ids[0]]['times_paid'] = 12;
check(ibja_seats($pages)['remaining'] === 0, 'Oversubscription never produces negative seats');
foreach ([null, -1, '2'] as $bad) {
    $pages[$ids[0]]['times_paid'] = $bad;
    try { ibja_seats($pages); throw new LogicException('Invalid payment count accepted'); }
    catch (RuntimeException $error) {}
}
$pages[$ids[0]]['times_paid'] = 0;
foreach (['id' => 'unrelated-page', 'currency' => 'USD', 'amount' => 29900000] as $field => $bad) {
    $invalid = $pages;
    $invalid[$ids[0]][$field] = $bad;
    try { ibja_seats($invalid); throw new LogicException('Invalid bundle payment page accepted'); }
    catch (RuntimeException $error) {}
}
$pages['pl_TiB7MYUlVNvPX8'] = ['times_paid' => 20];
check(ibja_seats($pages)['remaining'] === 10, 'Individual purchases do not consume bundle seats');
echo "IBJA bundle paid-seat checks passed\n";
