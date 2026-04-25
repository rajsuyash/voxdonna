<?php
// GitHub webhook receiver — pulls latest main on push.
// Reads HMAC secret from ../deploy_secret.txt (outside web root, not in git).

$secretFile = __DIR__ . '/../deploy_secret.txt';
$logFile    = __DIR__ . '/../deploy.log';

header('Content-Type: text/plain');

if (!is_readable($secretFile)) {
    http_response_code(500);
    echo "Server not configured: secret file missing\n";
    exit;
}
$secret = trim(file_get_contents($secretFile));
if ($secret === '') {
    http_response_code(500);
    echo "Server not configured: empty secret\n";
    exit;
}

$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$expected  = 'sha256=' . hash_hmac('sha256', $payload, $secret);

if (!hash_equals($expected, $signature)) {
    http_response_code(403);
    echo "Forbidden: bad signature\n";
    exit;
}

$event = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
if ($event === 'ping') {
    echo "pong\n";
    exit;
}
if ($event !== 'push') {
    http_response_code(202);
    echo "Ignored event: $event\n";
    exit;
}

$repoDir = __DIR__;
$cmd = 'cd ' . escapeshellarg($repoDir)
     . ' && git fetch origin main 2>&1'
     . ' && git reset --hard origin/main 2>&1';

$output = [];
$rc = 0;
exec($cmd, $output, $rc);

$head = trim(shell_exec('cd ' . escapeshellarg($repoDir) . ' && git rev-parse --short HEAD 2>&1'));
$ts   = gmdate('Y-m-d H:i:s');
$line = "[$ts] rc=$rc head=$head\n" . implode("\n", $output) . "\n---\n";
@file_put_contents($logFile, $line, FILE_APPEND);

if ($rc !== 0) {
    http_response_code(500);
    echo "Deploy failed (rc=$rc):\n" . implode("\n", $output) . "\n";
    exit;
}

echo "Deployed $head\n";
