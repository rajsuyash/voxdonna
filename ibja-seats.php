<?php
declare(strict_types=1);

const IBJA_PAGES = [
    'pl_TiCNslH3rbMjq0' => 44900000,
];

function ibja_seats(array $pages): array {
    $claimed = 0;
    foreach (IBJA_PAGES as $id => $amount) {
        $page = $pages[$id] ?? [];
        if (($page['id'] ?? null) !== $id || ($page['currency'] ?? null) !== 'INR'
            || ($page['amount'] ?? null) !== $amount || !is_int($page['times_paid'] ?? null)
            || $page['times_paid'] < 0) {
            throw new RuntimeException('Invalid webinar payment page');
        }
        $claimed += $page['times_paid'];
    }
    return ['capacity' => 10, 'claimed' => $claimed, 'remaining' => max(0, 10 - $claimed)];
}

function ibja_payment_page(string $html): array {
    if (!preg_match('~// <<<JSON_DATA_START>>>\s*var data = (.*?)\s*;\s*// <<<JSON_DATA_END>>>~s', $html, $match)) {
        throw new RuntimeException('Payment page data unavailable');
    }
    $data = json_decode($match[1], true, 512, JSON_THROW_ON_ERROR);
    if (($data['is_test_mode'] ?? null) !== false || !is_array($data['payment_link'] ?? null)) {
        throw new RuntimeException('Live payment page unavailable');
    }
    return $data['payment_link'];
}

if (defined('IBJA_SEATS_TEST')) return;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    echo '{"error":"Method not allowed"}';
    exit;
}

$cache = null;
try {
    $cache = fopen(dirname(__DIR__) . '/ibja-bundle-seat-cache.json', 'c+');
    if (!$cache || !flock($cache, LOCK_EX)) throw new RuntimeException('Cache unavailable');
    $cached = json_decode(stream_get_contents($cache), true);
    $age = is_array($cached) ? time() - (strtotime($cached['updatedAt'] ?? '') ?: 0) : PHP_INT_MAX;
    if ($age < 0 || $age >= 25) {
        $pages = [];
        foreach (IBJA_PAGES as $id => $amount) {
            $curl = curl_init('https://pages.razorpay.com/' . $id . '/view');
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 4,
                CURLOPT_HTTPHEADER => ['Cache-Control: no-cache'],
            ]);
            $body = curl_exec($curl);
            $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            unset($curl);
            if ($body === false || $code !== 200) throw new RuntimeException('Provider unavailable');
            $pages[$id] = ibja_payment_page($body);
        }
        $cached = ibja_seats($pages) + ['updatedAt' => gmdate('Y-m-d\TH:i:s\Z')];
        $json = json_encode($cached, JSON_THROW_ON_ERROR);
        json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        rewind($cache);
        if (!ftruncate($cache, 0) || fwrite($cache, $json) !== strlen($json) || !fflush($cache)) {
            throw new RuntimeException('Cache write failed');
        }
        rewind($cache);
        if (json_decode(stream_get_contents($cache), true, 512, JSON_THROW_ON_ERROR) !== $cached) {
            throw new RuntimeException('Cache verification failed');
        }
    }
    echo json_encode($cached, JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    error_log('IBJA seat feed unavailable: ' . $error->getMessage());
    http_response_code(503);
    echo '{"error":"Live availability unavailable"}';
} finally {
    if (is_resource($cache)) {
        flock($cache, LOCK_UN);
        fclose($cache);
    }
}
