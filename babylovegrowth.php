<?php
declare(strict_types=1);

function blg_text($value, int $max): string {
    if (!is_string($value) || trim($value) === '' || strlen($value) > $max) {
        throw new InvalidArgumentException('Missing or oversized text field');
    }
    return trim(preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $value));
}

function blg_url(string $url, bool $image = false): bool {
    if (preg_match('/[\x00-\x20\x7f\\\\]/', $url)) return false;
    if (!$image && preg_match('~^(?:/(?!/)|#)~', $url)) return true;
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (!$image && in_array($scheme, ['mailto', 'tel'], true)) return true;
    return in_array($scheme, $image ? ['https'] : ['https', 'http'], true)
        && filter_var($url, FILTER_VALIDATE_URL) !== false;
}

function blg_html(string $html): string {
    $doc = new DOMDocument();
    $previous = libxml_use_internal_errors(true);
    $doc->loadHTML('<?xml encoding="utf-8" ?><html><body>' . $html . '</body></html>', LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($previous);
    $allowed = ['p','h2','h3','h4','h5','h6','ul','ol','li','strong','em','b','i','u','s',
        'blockquote','pre','code','br','hr','table','thead','tbody','tfoot','tr','th','td',
        'a','img','figure','figcaption','div','span','sup','sub'];
    $drop = ['script','style','iframe','object','embed','form','input','button','textarea',
        'svg','math','template','link','meta','base','noscript'];
    $clean = function (DOMNode $node) use (&$clean, $allowed, $drop): string {
        if ($node instanceof DOMText) return htmlspecialchars($node->textContent, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        if (!($node instanceof DOMElement)) return '';
        $tag = strtolower($node->tagName);
        if (in_array($tag, $drop, true)) return '';
        // The site template supplies the article title.
        if ($tag === 'h1') return '';
        $children = '';
        foreach ($node->childNodes as $child) $children .= $clean($child);
        if (!in_array($tag, $allowed, true)) return $children;
        $attrs = '';
        foreach ($node->attributes as $attr) {
            $name = strtolower($attr->name);
            $value = $attr->value;
            $anchor = $name === 'id' && preg_match('/^[A-Za-z][A-Za-z0-9_-]{0,199}$/D', $value);
            $ok = in_array($name, ['title','alt'], true)
                || $anchor
                || ($tag === 'a' && $name === 'href' && blg_url($value))
                || ($tag === 'img' && $name === 'src' && blg_url($value, true))
                || (in_array($tag, ['td','th'], true) && in_array($name, ['colspan','rowspan'], true) && preg_match('/^[1-9][0-9]?$/', $value));
            // Keep article links working without colliding with the site's element IDs.
            if ($anchor) $value = 'blg-' . $value;
            if ($name === 'href' && preg_match('/^#[A-Za-z][A-Za-z0-9_-]{0,199}$/D', $value)) $value = '#blg-' . substr($value, 1);
            if ($ok) $attrs .= ' ' . $name . '="' . htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
        }
        if ($tag === 'img') {
            if (!str_contains($attrs, ' src=')) return '';
            $attrs .= ' loading="lazy" decoding="async" style="max-width:100%;height:auto"';
        }
        return '<' . $tag . $attrs . '>' . (in_array($tag, ['img','br','hr'], true) ? '' : $children . '</' . $tag . '>');
    };
    $result = '';
    foreach ($doc->getElementsByTagName('body')->item(0)->childNodes as $child) $result .= $clean($child);
    return $result;
}

function blg_article(array $input): array {
    $slug = blg_text($input['slug'] ?? null, 160);
    if (!preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug)) throw new InvalidArgumentException('Invalid slug');
    $id = $input['id'] ?? null;
    if ((!is_int($id) && !is_string($id)) || !preg_match('/^[a-zA-Z0-9_-]{1,100}$/D', (string) $id)) throw new InvalidArgumentException('Invalid article ID');
    $lang = $input['lang'] ?? $input['languageCode'] ?? 'en';
    if (!in_array($lang, ['en','fr','it'], true)) throw new InvalidArgumentException('Supported languages: en, fr, it');
    $rawHtml = $input['content_html'] ?? null;
    if (!is_string($rawHtml) || strlen($rawHtml) > 1500000) throw new InvalidArgumentException('Missing or oversized content_html');
    $body = blg_html($rawHtml);
    if (trim(strip_tags($body)) === '') throw new InvalidArgumentException('Article body is empty after sanitizing');
    $image = $input['heroImageUrl'] ?? '';
    if (!is_string($image) || ($image !== '' && !blg_url($image, true))) throw new InvalidArgumentException('Invalid hero image URL');
    if (($input['featureImageEnabled'] ?? true) && $image !== ''
        && !str_contains($body, ' src="' . htmlspecialchars($image, ENT_QUOTES, 'UTF-8') . '"')) {
        $body = blg_html('<figure><img src="' . htmlspecialchars($image, ENT_QUOTES, 'UTF-8') . '" alt="'
            . htmlspecialchars(is_string($input['heroImageAlt'] ?? null) ? $input['heroImageAlt'] : '', ENT_QUOTES, 'UTF-8') . '"></figure>') . $body;
    }
    return ['id' => (string) $id, 'slug' => $slug, 'lang' => $lang,
        'title' => blg_text($input['title'] ?? null, 500),
        'description' => blg_text($input['metaDescription'] ?? null, 2000),
        'html' => $body, 'image' => $image];
}

function blg_reply(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) return;
header('Content-Type: application/json');
header('Cache-Control: no-store');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    blg_reply(405, ['success' => false, 'error' => 'POST required']);
}
try {
    $configFile = dirname(__DIR__) . '/babylovegrowth/config.json';
    if (!is_readable($configFile)) blg_reply(503, ['success' => false, 'error' => 'Publisher not configured']);
    $config = json_decode(file_get_contents($configFile), true, 32, JSON_THROW_ON_ERROR);
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    $token = str_starts_with($token, 'Bearer ') ? substr($token, 7) : ($_SERVER['HTTP_X_API_KEY'] ?? '');
    if (strlen($config['secret'] ?? '') < 32 || !hash_equals($config['secret'], $token)) blg_reply(401, ['success' => false, 'error' => 'Unauthorized']);
    $raw = file_get_contents('php://input', false, null, 0, 2000001);
    if (strlen($raw) > 2000000) blg_reply(413, ['success' => false, 'error' => 'Payload too large']);
    $input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($input) || array_is_list($input)) throw new InvalidArgumentException('Expected article object');
    $article = blg_article($input);
    $lock = fopen(dirname($configFile) . '/publish.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) blg_reply(503, ['success' => false, 'error' => 'Publisher busy; retry shortly']);
    $proc = proc_open([$config['node'], __DIR__ . '/scripts/babylovegrowth-publish.js', $config['repo'], $config['sshKey']],
        [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['file', dirname($configFile) . '/publisher.log', 'a']], $pipes);
    if (!is_resource($proc)) throw new RuntimeException('Could not start publisher');
    $encoded = json_encode($article, JSON_THROW_ON_ERROR);
    $offset = 0;
    while ($offset < strlen($encoded)) {
        $written = fwrite($pipes[0], substr($encoded, $offset));
        if (!$written) throw new RuntimeException('Could not deliver article to publisher');
        $offset += $written;
    }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $rc = proc_close($proc);
    flock($lock, LOCK_UN);
    fclose($lock);
    if ($rc !== 0) blg_reply(503, ['success' => false, 'error' => 'Publishing failed; retry or check publisher log']);
    $result = json_decode($output, true, 32, JSON_THROW_ON_ERROR);
    blg_reply(200, $result);
} catch (InvalidArgumentException | JsonException $e) {
    blg_reply(400, ['success' => false, 'error' => 'Invalid article payload: ' . $e->getMessage()]);
} catch (Throwable $e) {
    error_log('BabyLoveGrowth: ' . $e->getMessage());
    blg_reply(503, ['success' => false, 'error' => 'Publisher unavailable']);
}
