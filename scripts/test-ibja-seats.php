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
$pages[$ids[0]]['times_paid'] = 2;
$pages[$ids[1]]['times_paid'] = 1;
check(ibja_seats($pages)['remaining'] === 7, 'All three setup links share one allocation');
$pages[$ids[2]]['times_paid'] = 9;
check(ibja_seats($pages)['remaining'] === 0, 'Oversubscription never produces negative seats');
foreach ([null, -1, '2'] as $bad) {
    $pages[$ids[0]]['times_paid'] = $bad;
    try { ibja_seats($pages); throw new LogicException('Invalid payment count accepted'); }
    catch (RuntimeException $error) {}
}
$pages[$ids[0]]['times_paid'] = 0;
$pages[$ids[0]]['id'] = 'unrelated-page';
try { ibja_seats($pages); throw new LogicException('Unrelated page accepted'); }
catch (RuntimeException $error) {}
echo "IBJA paid-seat checks passed\n";
