<?php
declare(strict_types=1);
require __DIR__ . '/../video-ads-lib.php';

function check(bool $ok, string $message): void {
    if (!$ok) {
        throw new RuntimeException($message);
    }
}

// --- validation: required fields -------------------------------------------------
[$errors] = va_validate_signup([]);
check(count($errors) === 5, 'All five required fields flagged on empty payload, got: ' . implode(', ', $errors));

$goodPayload = [
    'business_name' => 'Anand Jewellers',
    'contact_name'  => 'Priya',
    'email'         => 'priya@anandjewellers.in',
    'phone'         => '9876543210',
    'city'          => 'Chennai',
];
[$errors, $clean] = va_validate_signup($goodPayload);
check($errors === [], 'Valid payload produced errors: ' . implode(', ', $errors));
check($clean['phone'] === '+919876543210', 'Bare 10-digit mobile normalised to +91, got: ' . $clean['phone']);

// --- phone normalisation -----------------------------------------------------------
check(va_normalize_indian_mobile('9876543210') === '+919876543210', 'Bare mobile');
check(va_normalize_indian_mobile('919876543210') === '+919876543210', '91-prefixed mobile');
check(va_normalize_indian_mobile('+919876543210') === '+919876543210', '+91-prefixed mobile');
check(va_normalize_indian_mobile('+91 98765 43210') === '+919876543210', 'Spaced +91 mobile');
check(va_normalize_indian_mobile('12345') === null, 'Too short rejected');
check(va_normalize_indian_mobile('5876543210') === null, 'Landline-shaped (starts 5) rejected');
check(va_normalize_indian_mobile('+12025550123') === null, 'US number rejected rather than guessed as Indian');

// --- email validation ----------------------------------------------------------------
[$bad] = va_validate_signup(array_merge($goodPayload, ['email' => 'not-an-email']));
check(in_array('valid email required', $bad, true), 'Bad email flagged');
[$ok2] = va_validate_signup(array_merge($goodPayload, ['email' => 'a@b.co']));
check($ok2 === [], 'Good email accepted');

// --- Razorpay signature verification ------------------------------------------------
$secret = 'test_secret_xyz';
$paymentId = 'pay_ABC123';
$subId = 'sub_DEF456';
$goodSig = hash_hmac('sha256', $paymentId . '|' . $subId, $secret);
check(va_verify_signature($paymentId, $subId, $secret, $goodSig), 'Known-good HMAC verifies');
check(!va_verify_signature($paymentId, $subId, $secret, $goodSig . 'x'), 'Tampered signature rejected');
check(!va_verify_signature($paymentId, 'sub_OTHER', $secret, $goodSig), 'Signature for a different subscription id rejected');

// --- HTML escaping in the thank-you email -------------------------------------------
$row = [
    'contact_name'  => '<script>alert(1)</script>',
    'business_name' => 'O\'Reilly & Sons "Gold"',
];
[$subject, $html, $text] = va_thank_you_email($row);
check(strpos($html, '<script>alert(1)</script>') === false, 'Raw script tag must not appear unescaped in HTML');
check(strpos($html, '&lt;script&gt;') !== false, 'Contact name HTML-escaped');
check(strpos($html, '&amp;') !== false, 'Ampersand HTML-escaped');
check(strpos($text, '<script>alert(1)</script>') !== false, 'Text part keeps the literal value (plain text, not rendered as markup)');
check(is_string($subject) && $subject !== '', 'Subject present');

// --- idempotent thank-you send, against a real temp SQLite db ----------------------
$tmpPath = sys_get_temp_dir() . '/video-ads-test-' . bin2hex(random_bytes(6)) . '.sqlite';
$pdo = new PDO('sqlite:' . $tmpPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
va_init_schema($pdo);
$pdo->exec("INSERT INTO subscribers (created_at, updated_at, business_name, contact_name, email, phone, city, subscription_id, status)
            VALUES ('now','now','Biz','Contact','c@example.com','+919876543210','City','sub_idem_1','active')");
$subscriberId = (int)$pdo->lastInsertId();
$subscriberRow = $pdo->query('SELECT * FROM subscribers WHERE id = ' . $subscriberId)->fetch(PDO::FETCH_ASSOC);

$sendCount = 0;
$fakeSender = function (array $r) use (&$sendCount): bool {
    $sendCount++;
    return true;
};

$first  = va_claim_and_send_thank_you($pdo, $subscriberRow, $fakeSender);
$second = va_claim_and_send_thank_you($pdo, $subscriberRow, $fakeSender);
check($first === 'sent', 'First confirm sends, got: ' . $first);
check($second === 'skipped', 'Second confirm is a no-op, got: ' . $second);
check($sendCount === 1, 'Exactly one email sent across two confirms, got: ' . $sendCount);

$sentAt = $pdo->query('SELECT thank_you_sent_at FROM subscribers WHERE id = ' . $subscriberId)->fetchColumn();
check($sentAt !== null && $sentAt !== '', 'thank_you_sent_at recorded after a successful send');

// A send that fails must clear the claim so a later retry can try again.
$pdo->exec("INSERT INTO subscribers (created_at, updated_at, business_name, contact_name, email, phone, city, subscription_id, status)
            VALUES ('now','now','Biz2','Contact2','c2@example.com','+919876543211','City','sub_idem_2','active')");
$failId = (int)$pdo->lastInsertId();
$failRow = $pdo->query('SELECT * FROM subscribers WHERE id = ' . $failId)->fetch(PDO::FETCH_ASSOC);
$failingSender = function (array $r): bool {
    return false;
};
$result = va_claim_and_send_thank_you($pdo, $failRow, $failingSender);
check($result === 'failed', 'Failed send reported as failed, got: ' . $result);
$claimedAt = $pdo->query('SELECT thank_you_claimed_at FROM subscribers WHERE id = ' . $failId)->fetchColumn();
check($claimedAt === null, 'Claim cleared after a failed send, so retry can claim again');

unlink($tmpPath);

echo "Video Ads Manager checks passed\n";
