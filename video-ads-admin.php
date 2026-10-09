<?php
declare(strict_types=1);

/**
 * VoxDonna Video Ads Manager — admin listing. No webhook on this Hostinger
 * shared-hosting setup, so ?refresh=1 is how renewals/cancellations get
 * noticed: it re-fetches every non-terminal subscription's status from
 * Razorpay before returning the list.
 *
 * Request: GET /video-ads-admin.php              -> { ok, subscribers }
 *          GET /video-ads-admin.php?format=csv   -> CSV download
 *          GET /video-ads-admin.php?refresh=1     -> also refreshes statuses first
 * Auth:    header X-Admin-Token: <token>  or  ?token=<token>
 */

header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/video-ads-lib.php';

const VIDEO_ADS_TERMINAL_STATUSES = ['cancelled', 'completed', 'expired'];

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
        va_fail(405, 'method_not_allowed');
        exit;
    }

    $env = va_load_env();
    va_require_env($env, ['VIDEO_ADS_ADMIN_TOKEN']);

    $given = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ($_GET['token'] ?? '');
    if (!is_string($given) || !hash_equals($env['VIDEO_ADS_ADMIN_TOKEN'], $given)) {
        va_fail(401, 'unauthorized');
        exit;
    }

    $pdo = va_db(va_data_dir());

    if (($_GET['refresh'] ?? '') === '1') {
        va_require_env($env, ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET']);
        $placeholders = implode(',', array_fill(0, count(VIDEO_ADS_TERMINAL_STATUSES), '?'));
        $stmt = $pdo->prepare("SELECT id, subscription_id FROM subscribers WHERE status NOT IN ($placeholders)");
        $stmt->execute(VIDEO_ADS_TERMINAL_STATUSES);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
            [$code, $resp] = va_razorpay_request('GET', '/subscriptions/' . rawurlencode($r['subscription_id']), $env);
            if ($code >= 200 && $code < 300 && is_array($resp) && !empty($resp['status'])) {
                $pdo->prepare('UPDATE subscribers SET status = :s, updated_at = :u WHERE id = :id')
                    ->execute([':s' => $resp['status'], ':u' => gmdate('Y-m-d H:i:s'), ':id' => $r['id']]);
            } else {
                error_log('video-ads-admin: refresh failed for subscription ' . $r['subscription_id'] . ' code=' . $code);
            }
        }
    }

    $all = $pdo->query('SELECT * FROM subscribers ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);

    if (($_GET['format'] ?? '') === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="video-ads-subscribers.csv"');
        $out = fopen('php://output', 'w');
        if ($all) {
            fputcsv($out, array_keys($all[0]));
        }
        foreach ($all as $r) {
            fputcsv($out, $r);
        }
        fclose($out);
        exit;
    }

    echo json_encode(['ok' => true, 'subscribers' => $all]);
} catch (Throwable $e) {
    error_log('video-ads-admin: unhandled error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'internal_error']);
}
