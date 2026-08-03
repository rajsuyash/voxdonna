<?php
// Public certificate lookup. Returns the holder's name, company, and score for a
// known certificate id — deliberately never the email address.

declare(strict_types=1);
require __DIR__ . '/_store.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    fail('GET only', 405);
}

rate_limit('verify');

$id = $_GET['id'] ?? '';
if (!is_string($id) || !preg_match('/^[A-Za-z0-9-]{8,64}$/', $id)) {
    fail('bad certificate id');
}

$certs = read_json(data_dir() . '/certs.json');
$cert  = $certs[$id] ?? null;

if (!is_array($cert)) {
    json_out(['ok' => false, 'error' => 'not found'], 404);
}

json_out([
    'ok'      => true,
    'name'    => (string) ($cert['name'] ?? ''),
    'company' => (string) ($cert['company'] ?? ''),
    'score'   => (int) ($cert['score'] ?? 0),
    'total'   => (int) ($cert['total'] ?? 0),
    'date'    => (string) ($cert['date'] ?? ''),
]);
