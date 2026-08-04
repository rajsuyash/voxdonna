<?php
// Records trainee enrolment, module progress, section scores, and exam results.
// The browser's localStorage is the source of truth; this is the reporting mirror.

declare(strict_types=1);
require __DIR__ . '/_store.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail('POST only', 405);
}

rate_limit('progress');

$body = read_body();

$org = valid_org($body['org'] ?? null);
if ($org === null) {
    fail('unknown org');
}

$action = $body['action'] ?? '';
if (!in_array($action, ['enroll', 'progress', 'section', 'exam', 'review'], true)) {
    fail('unknown action');
}

// ---- trainee identity ----

$trainee = $body['trainee'] ?? null;
if (!is_array($trainee)) {
    fail('missing trainee');
}

$id = $trainee['id'] ?? '';
if (!is_string($id) || !preg_match('/^[A-Za-z0-9-]{8,64}$/', $id)) {
    fail('bad trainee id');
}

$name = clean_text($trainee['name'] ?? '', 80);
if (mb_strlen($name) < 2) {
    fail('bad name');
}

$email = clean_text($trainee['email'] ?? '', 120);
if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fail('bad email');
}

// ---- progress payload ----

$done = [];
if (isset($body['done']) && is_array($body['done'])) {
    foreach (array_slice($body['done'], 0, MAX_DONE_ENTRIES) as $moduleId) {
        if (is_string($moduleId) && preg_match('/^[a-z0-9-]{1,30}$/', $moduleId)) {
            $done[$moduleId] = true;
        }
    }
}
$done = array_keys($done);

$sections = [];
if (isset($body['sections']) && is_array($body['sections'])) {
    foreach ($body['sections'] as $key => $score) {
        $n = (int) $key;
        if ($n >= 1 && $n <= 10 && is_numeric($score)) {
            $sections[(string) $n] = max(0, min(10, (int) $score));
        }
    }
}

$review = [];
if (isset($body['review']) && is_array($body['review'])) {
    foreach ($body['review'] as $key => $entry) {
        // 1-100 are exam questions; 1001+ are per-lesson recall checks.
        $n = (int) $key;
        if ($n < 1 || $n > MAX_QUESTION_NUMBER || !is_array($entry)) {
            continue;
        }
        $due  = isset($entry['due']) && is_numeric($entry['due']) ? (float) $entry['due'] : 0;
        $step = isset($entry['step']) && is_numeric($entry['step']) ? (int) $entry['step'] : 0;
        if ($due <= 0) {
            continue;
        }
        $review[(string) $n] = ['due' => $due, 'step' => max(0, min(10, $step))];
        if (count($review) >= MAX_REVIEW_ENTRIES) {
            break;
        }
    }
}

$exam = null;
if (isset($body['exam']) && is_array($body['exam'])) {
    $raw    = $body['exam'];
    $total  = isset($raw['total']) && is_numeric($raw['total']) ? (int) $raw['total'] : 0;
    $score  = isset($raw['score']) && is_numeric($raw['score']) ? (int) $raw['score'] : 0;
    $certId = $raw['certId'] ?? null;

    if ($total > 0 && $total <= 100 && $score >= 0 && $score <= $total) {
        $exam = [
            'score'  => $score,
            'total'  => $total,
            'passed' => !empty($raw['passed']),
            'date'   => clean_text($raw['date'] ?? '', 40),
            'certId' => (is_string($certId) && preg_match('/^[A-Za-z0-9-]{8,64}$/', $certId))
                ? $certId : null,
        ];
    }
}

// ---- write ----

$now      = gmdate('c');
$overflow = false;

mutate_json(data_dir() . '/' . $org . '.json', function (array $store) use (
    $org, $id, $name, $email, $done, $sections, $review, $exam, $now, &$overflow
) {
    $store['org']      = $org;
    $store['updated']  = $now;
    $trainees          = isset($store['trainees']) && is_array($store['trainees'])
        ? $store['trainees'] : [];

    if (!isset($trainees[$id]) && count($trainees) >= MAX_TRAINEES_PER_ORG) {
        $overflow = true;
        return $store;
    }

    $record = $trainees[$id] ?? ['first' => $now];
    $record['name']     = $name;
    $record['email']    = $email;
    $record['done']     = $done;
    $record['sections'] = $sections;
    $record['review']   = $review;
    $record['last']     = $now;

    // Never let a weaker attempt overwrite a passing one.
    $prior = $record['exam'] ?? null;
    if ($exam !== null) {
        $priorPassed = !empty($prior['passed']);
        $priorScore  = isset($prior['score']) ? (int) $prior['score'] : -1;
        if (!$priorPassed || ($exam['passed'] && $exam['score'] > $priorScore)) {
            if ($priorPassed && empty($exam['certId']) && !empty($prior['certId'])) {
                $exam['certId'] = $prior['certId'];
            }
            $record['exam'] = $exam;
        }
    }

    $trainees[$id]     = $record;
    $store['trainees'] = $trainees;
    return $store;
});

if ($overflow) {
    fail('enrolment limit reached for this organisation', 507);
}

// A passing exam registers the certificate so verify.php can resolve it.
if ($exam !== null && $exam['passed'] && $exam['certId'] !== null) {
    $company = org_company($org);
    mutate_json(data_dir() . '/certs.json', function (array $certs) use (
        $exam, $org, $company, $name, $now
    ) {
        $existing = $certs[$exam['certId']] ?? null;
        if ($existing !== null && (int) ($existing['score'] ?? 0) >= $exam['score']) {
            return $certs;
        }
        $certs[$exam['certId']] = [
            'org'     => $org,
            'company' => $company,
            'name'    => $name,
            'score'   => $exam['score'],
            'total'   => $exam['total'],
            'date'    => $exam['date'] !== '' ? $exam['date'] : $now,
        ];
        return $certs;
    });
}

json_out(['ok' => true, 'action' => $action]);
