<?php
// Roster for a single org. Passcode-gated; returns trainee PII, so it is POST
// only, rate limited, and never logs or echoes the submitted passcode.

declare(strict_types=1);
require __DIR__ . '/_store.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail('POST only', 405);
}

rate_limit('admin');

$body = read_body();

$secretFile = data_dir() . '/admin_secret.txt';
if (!is_readable($secretFile)) {
    fail('admin access is not configured on this server', 503);
}
$secret = trim((string) file_get_contents($secretFile));
if ($secret === '') {
    fail('admin access is not configured on this server', 503);
}

$supplied = $body['passcode'] ?? '';
if (!is_string($supplied) || !hash_equals($secret, $supplied)) {
    // Deliberately slow the guess loop beyond the shared rate limit.
    usleep(400000);
    fail('incorrect passcode', 401);
}

$orgs = [];
foreach (glob(__DIR__ . '/../orgs/*.json') ?: [] as $path) {
    $slug = basename($path, '.json');
    if (valid_org($slug) !== null) {
        $orgs[] = ['slug' => $slug, 'company' => org_company($slug)];
    }
}

$wanted = $body['org'] ?? '';
$org    = valid_org(is_string($wanted) ? $wanted : '');

if ($org === null) {
    json_out(['ok' => true, 'orgs' => $orgs, 'trainees' => []]);
}

$store    = read_json(data_dir() . '/' . $org . '.json');
$trainees = isset($store['trainees']) && is_array($store['trainees']) ? $store['trainees'] : [];

$rows = [];
foreach ($trainees as $id => $t) {
    if (!is_array($t)) {
        continue;
    }
    $exam = isset($t['exam']) && is_array($t['exam']) ? $t['exam'] : null;
    $rows[] = [
        'id'       => (string) $id,
        'name'     => (string) ($t['name'] ?? ''),
        'email'    => (string) ($t['email'] ?? ''),
        'modules'  => is_array($t['done'] ?? null) ? count($t['done']) : 0,
        'sections' => is_array($t['sections'] ?? null) ? $t['sections'] : [],
        'score'    => $exam ? (int) ($exam['score'] ?? 0) : null,
        'total'    => $exam ? (int) ($exam['total'] ?? 0) : null,
        'passed'   => $exam ? !empty($exam['passed']) : false,
        'certId'   => $exam ? ($exam['certId'] ?? null) : null,
        'first'    => (string) ($t['first'] ?? ''),
        'last'     => (string) ($t['last'] ?? ''),
    ];
}

usort($rows, static function (array $a, array $b): int {
    return strcmp($b['last'], $a['last']);
});

json_out([
    'ok'       => true,
    'orgs'     => $orgs,
    'org'      => $org,
    'company'  => org_company($org),
    'trainees' => $rows,
]);
