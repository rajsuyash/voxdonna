<?php
declare(strict_types=1);

/**
 * VoxDonna Video Ads Manager — confirm a Razorpay checkout handler payload,
 * verify it against Razorpay itself, mark the subscriber paid, and send the
 * thank-you email exactly once.
 *
 * Request:  POST /video-ads-confirm.php
 *           { razorpay_payment_id, razorpay_subscription_id, razorpay_signature }
 * Response: { ok, status, email }
 */

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/video-ads-lib.php';

const VIDEO_ADS_ACTIVE_STATUSES = ['authenticated', 'active'];

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        va_fail(405, 'method_not_allowed');
        exit;
    }

    $env = va_load_env();
    va_require_env($env, ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'VIDEO_ADS_PLAN_ID', 'RESEND_API_KEY']);

    $raw  = file_get_contents('php://input');
    $body = $raw !== false ? json_decode($raw, true) : null;
    if (!is_array($body)) {
        va_fail(400, 'malformed_json');
        exit;
    }

    $paymentId = trim((string)($body['razorpay_payment_id'] ?? ''));
    $subId     = trim((string)($body['razorpay_subscription_id'] ?? ''));
    $signature = trim((string)($body['razorpay_signature'] ?? ''));
    if ($paymentId === '' || $subId === '' || $signature === '') {
        va_fail(400, 'invalid_input');
        exit;
    }

    if (!va_verify_signature($paymentId, $subId, $env['RAZORPAY_KEY_SECRET'], $signature)) {
        va_fail(400, 'signature_mismatch');
        exit;
    }

    $pdo  = va_db(va_data_dir());
    $stmt = $pdo->prepare('SELECT * FROM subscribers WHERE subscription_id = :sid');
    $stmt->execute([':sid' => $subId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        va_fail(404, 'not_found');
        exit;
    }

    // Already confirmed by an earlier call with this same payment: re-run the
    // email claim (idempotent — a second attempt is always a no-op) and
    // return ok without hitting Razorpay again.
    if ($row['status'] !== 'created' && $row['payment_id'] === $paymentId) {
        $sendResult = va_claim_and_send_thank_you($pdo, $row, function (array $r) use ($env) {
            [$subject, $html, $text] = va_thank_you_email($r);
            return va_send_resend_email($env, $r['email'], $subject, $html, $text);
        });
        echo json_encode(['ok' => true, 'status' => $row['status'], 'email' => $sendResult]);
        exit;
    }

    [$code, $resp] = va_razorpay_request('GET', '/subscriptions/' . rawurlencode($subId), $env);
    if ($code < 200 || $code >= 300 || !is_array($resp)) {
        error_log('video-ads-confirm: razorpay fetch failed code=' . $code . ' sub=' . $subId);
        va_fail(502, 'provider_error');
        exit;
    }

    $status = (string)($resp['status'] ?? '');
    $planOk = ($resp['plan_id'] ?? null) === $env['VIDEO_ADS_PLAN_ID'];
    if (!in_array($status, VIDEO_ADS_ACTIVE_STATUSES, true) || !$planOk) {
        error_log('video-ads-confirm: subscription not active sub=' . $subId . ' status=' . $status . ' plan_ok=' . ($planOk ? '1' : '0'));
        va_fail(402, 'not_active');
        exit;
    }

    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare('UPDATE subscribers SET status = :status, payment_id = :pid, paid_at = :paid, updated_at = :upd WHERE id = :id')
        ->execute([':status' => $status, ':pid' => $paymentId, ':paid' => $now, ':upd' => $now, ':id' => $row['id']]);

    $row['status']     = $status;
    $row['payment_id'] = $paymentId;

    $sendResult = va_claim_and_send_thank_you($pdo, $row, function (array $r) use ($env) {
        [$subject, $html, $text] = va_thank_you_email($r);
        return va_send_resend_email($env, $r['email'], $subject, $html, $text);
    });

    echo json_encode(['ok' => true, 'status' => $status, 'email' => $sendResult]);
} catch (Throwable $e) {
    error_log('video-ads-confirm: unhandled error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'internal_error']);
}
