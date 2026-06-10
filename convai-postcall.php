<?php
/**
 * ElevenLabs ConvAI post-call webhook receiver.
 * Receives transcription webhooks (type: post_call_transcription), verifies the
 * HMAC signature, extracts data_collection results + call summary, appends to a
 * leads log, and emails the lead to the configured inbox.
 *
 * Setup: in ElevenLabs dashboard → Conversational AI → Settings → Post-call
 * webhooks → add https://voxdonna.com/convai-postcall.php and copy the signing
 * secret into .env as ELEVENLABS_WEBHOOK_SECRET.
 */

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
}

function load_env($path) {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1]);
    }
    return $env;
}

$env = load_env(__DIR__ . '/.env');
$secret = $env['ELEVENLABS_WEBHOOK_SECRET'] ?? '';
$lead_email = $env['LEAD_EMAIL'] ?? 'hello@voxdonna.com';

$payload = file_get_contents('php://input');

// HMAC verification (ElevenLabs-Signature: t=<ts>,v0=<hex hmac sha256 of "<ts>.<payload>">)
if (!empty($secret)) {
    $sig_header = $_SERVER['HTTP_ELEVENLABS_SIGNATURE'] ?? '';
    $ts = ''; $v0 = '';
    foreach (explode(',', $sig_header) as $part) {
        $kv = explode('=', trim($part), 2);
        if (count($kv) === 2) {
            if ($kv[0] === 't') $ts = $kv[1];
            if ($kv[0] === 'v0') $v0 = $kv[1];
        }
    }
    $expected = hash_hmac('sha256', $ts . '.' . $payload, $secret);
    if (empty($v0) || !hash_equals($expected, $v0)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'bad_signature']);
        exit;
    }
    // reject stale (>30 min) timestamps
    if (empty($ts) || abs(time() - (int)$ts) > 1800) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'stale_timestamp']);
        exit;
    }
}

$data = json_decode($payload, true);
if (!$data || ($data['type'] ?? '') !== 'post_call_transcription') {
    echo json_encode(['ok' => true, 'skipped' => 'not_transcription']);
    exit;
}

$d = $data['data'] ?? [];
$agent_id = $d['agent_id'] ?? 'unknown';
$conv_id = $d['conversation_id'] ?? 'unknown';
$analysis = $d['analysis'] ?? [];
$collected = $analysis['data_collection_results'] ?? [];
$summary = $analysis['transcript_summary'] ?? '';
$success = $analysis['call_successful'] ?? 'unknown';
$evaluation = $analysis['evaluation_criteria_results'] ?? [];

// Flatten collected fields ({field: {value: ...}} or plain)
$fields = [];
foreach ($collected as $k => $v) {
    $fields[$k] = is_array($v) ? ($v['value'] ?? json_encode($v)) : $v;
}

// Append to leads log (JSON lines, outside web root not possible on shared host — use dotfile)
$log_line = json_encode([
    'ts' => date('c'),
    'agent_id' => $agent_id,
    'conversation_id' => $conv_id,
    'call_successful' => $success,
    'fields' => $fields,
    'summary' => $summary,
    'evaluation' => array_map(fn($e) => is_array($e) ? ($e['result'] ?? '') : $e, $evaluation),
], JSON_UNESCAPED_UNICODE);
@file_put_contents(__DIR__ . '/.convai-leads.jsonl', $log_line . "\n", FILE_APPEND | LOCK_EX);

// Email the lead
$subject = 'Voxdonna lead: ' . ($fields['company_name'] ?? $fields['product_required'] ?? $conv_id);
$body = "New voice-agent lead\n====================\n";
$body .= "Agent: $agent_id\nConversation: $conv_id\nCall successful: $success\n\n";
foreach ($fields as $k => $v) {
    $body .= str_pad(ucwords(str_replace('_', ' ', $k)) . ':', 26) . $v . "\n";
}
if ($summary) $body .= "\nSummary:\n$summary\n";
$headers = "From: leads@voxdonna.com\r\nReply-To: hello@voxdonna.com";
@mail($lead_email, $subject, $body, $headers);

echo json_encode(['ok' => true, 'logged' => true, 'fields' => count($fields)]);
