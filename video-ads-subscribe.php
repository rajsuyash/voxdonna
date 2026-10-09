<?php
declare(strict_types=1);

/**
 * VoxDonna Video Ads Manager — create a Razorpay subscription for a jeweller
 * signing up at /jewellers/video-ads.html.
 *
 * Request:  POST /video-ads-subscribe.php
 *           { business_name, contact_name, email, phone, city, social? }
 * Response: { ok, subscription_id, key_id, short_url }
 */

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/video-ads-lib.php';

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        va_fail(405, 'method_not_allowed');
        exit;
    }

    $env = va_load_env();
    va_require_env($env, ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'VIDEO_ADS_PLAN_ID']);

    $raw  = file_get_contents('php://input');
    $body = $raw !== false ? json_decode($raw, true) : null;
    if (!is_array($body)) {
        va_fail(400, 'malformed_json');
        exit;
    }

    [$errors, $clean] = va_validate_signup($body);
    if ($errors) {
        va_fail(400, 'invalid_input', ['details' => $errors]);
        exit;
    }

    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $pdo = va_db(va_data_dir());

    if (!va_rate_limit_ok($pdo, 'subscribe', $ip, 5, 600)) {
        va_fail(429, 'rate_limited');
        exit;
    }

    [$code, $resp] = va_razorpay_request('POST', '/subscriptions', $env, [
        'plan_id'          => $env['VIDEO_ADS_PLAN_ID'],
        'total_count'      => VIDEO_ADS_TOTAL_COUNT,
        'customer_notify'  => 1,
        'quantity'         => 1,
        'notes'            => [
            'business_name' => $clean['business_name'],
            'contact_name'  => $clean['contact_name'],
            'email'         => $clean['email'],
            'phone'         => $clean['phone'],
            'city'          => $clean['city'],
            'service'       => 'video-ads-manager',
        ],
    ]);

    if ($code < 200 || $code >= 300 || !is_array($resp) || empty($resp['id'])) {
        error_log('video-ads-subscribe: razorpay create failed code=' . $code . ' body=' . json_encode($resp));
        va_fail(502, 'provider_error');
        exit;
    }

    $now = gmdate('Y-m-d H:i:s');
    try {
        $pdo->prepare(
            'INSERT INTO subscribers
                (created_at, updated_at, business_name, contact_name, email, phone, city, social, subscription_id, status, ip)
             VALUES (:created, :updated, :bn, :cn, :em, :ph, :ci, :so, :sid, :status, :ip)'
        )->execute([
            ':created' => $now, ':updated' => $now,
            ':bn' => $clean['business_name'], ':cn' => $clean['contact_name'], ':em' => $clean['email'],
            ':ph' => $clean['phone'], ':ci' => $clean['city'], ':so' => $clean['social'],
            ':sid' => $resp['id'], ':status' => 'created', ':ip' => $ip,
        ]);
    } catch (Throwable $e) {
        error_log('video-ads-subscribe: store insert failed: ' . $e->getMessage());
        va_fail(500, 'store_failed');
        exit;
    }

    echo json_encode([
        'ok'              => true,
        'subscription_id' => $resp['id'],
        'key_id'          => $env['RAZORPAY_KEY_ID'],
        'short_url'       => $resp['short_url'] ?? null,
    ]);
} catch (Throwable $e) {
    error_log('video-ads-subscribe: unhandled error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'internal_error']);
}
