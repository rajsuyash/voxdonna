<?php
// GitHub webhook receiver — pulls latest main on push.
// Uses proc_open since exec/shell_exec are disabled on Hostinger shared.
// Reads HMAC secret from ../deploy_secret.txt (outside web root, not in git).

$secretFile = __DIR__ . '/../deploy_secret.txt';
$logFile    = __DIR__ . '/../deploy.log';

header('Content-Type: text/plain');

if (!is_readable($secretFile)) {
    http_response_code(500);
    echo "secret file missing\n";
    exit;
}
$secret = trim(file_get_contents($secretFile));
if ($secret === '') {
    http_response_code(500);
    echo "empty secret\n";
    exit;
}

$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$expected  = 'sha256=' . hash_hmac('sha256', $payload, $secret);

if (!hash_equals($expected, $signature)) {
    http_response_code(403);
    echo "bad signature\n";
    exit;
}

$event = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
if ($event === 'ping') {
    echo "pong\n";
    exit;
}
if ($event !== 'push') {
    http_response_code(202);
    echo "ignored event: $event\n";
    exit;
}

function run_cmd(array $argv, string $cwd): array {
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($argv, $desc, $pipes, $cwd);
    if (!is_resource($proc)) {
        return [127, '', 'proc_open failed'];
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    return [$rc, $stdout, $stderr];
}

$repoDir = __DIR__;
$git     = '/usr/bin/git';
$out     = "";

[$rc1, $o1, $e1] = run_cmd([$git, 'fetch', 'origin', 'main'], $repoDir);
$out .= "fetch rc=$rc1\n$o1$e1\n";

if ($rc1 === 0) {
    [$rc2, $o2, $e2] = run_cmd([$git, 'reset', '--hard', 'origin/main'], $repoDir);
    $out .= "reset rc=$rc2\n$o2$e2\n";
    $rc = $rc2;
} else {
    $rc = $rc1;
}

[$_, $headOut] = run_cmd([$git, 'rev-parse', '--short', 'HEAD'], $repoDir);
$head = trim($headOut);

$ts   = gmdate('Y-m-d H:i:s');
$line = "[$ts] rc=$rc head=$head\n$out---\n";
@file_put_contents($logFile, $line, FILE_APPEND);

if ($rc !== 0) {
    http_response_code(500);
    echo "deploy failed rc=$rc\n$out";
    exit;
}

echo "deployed $head\n";
