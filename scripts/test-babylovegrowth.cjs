const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {execFileSync, spawn} = require('node:child_process');
const {writeArticle} = require('./babylovegrowth-publish.js');
const root = path.resolve(__dirname, '..');
const php = process.env.PHP_BINARY || 'php';
const payload = {id: 91827, slug: 'publisher-verification', languageCode: 'en', title: 'Publisher verification',
  metaDescription: 'Verifies the connection.', content_html: '<h1>Publisher verification</h1><p>A safe article.</p>',
  heroImageUrl: 'https://voxdonna.com/og-image.png', heroImageAlt: 'VoxDonna'};
function normalize(input) {
  return JSON.parse(execFileSync(php, ['-r', 'require $argv[1];echo json_encode(blg_article(json_decode($argv[2],true)),JSON_THROW_ON_ERROR);', path.join(root, 'babylovegrowth.php'), JSON.stringify(input)], {encoding:'utf8', stdio:['ignore','pipe','pipe']}));
}
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blg-test-'));
  fs.mkdirSync(path.join(dir, 'scripts'));
  for (const lang of ['en','fr','it']) fs.mkdirSync(path.join(dir, 'blog', lang), {recursive:true});
  for (const name of ['blog.html','blog-post.html','.htaccess','sitemap.xml','scripts/build-blog-static.js']) fs.copyFileSync(path.join(root, name), path.join(dir, name));
  return dir;
}
test('normalizes payload, removes executable markup and preserves safe rich content', () => {
  const article = normalize({...payload, content_html: `<h1>Title</h1><p onclick="evil()">Hi &amp; bye <a href="jav&#x61;script:evil()">bad</a><a href="https://example.com">good</a></p>
  <script>evil()</script><svg onload="evil()"><script>evil()</script></svg><iframe src="https://example.com"></iframe>
  <img src="x" onerror="evil()"><table><tr><td colspan="2">Cell</td></tr></table><pre>one\ntwo</pre>`});
  assert.doesNotMatch(article.html, /onclick|onerror|javascript:|<script|<svg|<iframe|<h1/);
  assert.match(article.html, /href="https:\/\/example.com"/);
  assert.match(article.html, /<td colspan="2">Cell<\/td>/);
  assert.match(article.html, /<pre>one\ntwo<\/pre>/);
});
test('rejects traversal, unsupported language, empty body, invalid image and missing fields', () => {
  for (const change of [{slug:'../index'}, {id:[]}, {lang:'de'}, {content_html:'<script>only evil</script>'}, {heroImageUrl:'javascript:evil()'}, {title:null}, {slug:'foo\nbar'}]) assert.throws(() => normalize({...payload,...change}));
});
test('safe rendering, repeated deliveries, updates, ownership and XML integrity', () => {
  const dir = fixture();
  try {
    const article = normalize({...payload, title:'Price $& "quote" </script><script>evil()</script>', content_html:'<p>Keep $& and $` literal.</p>'});
    const result = writeArticle(dir, article);
    const firstIndex = fs.readFileSync(path.join(dir,'blog.html'),'utf8');
    const firstMap = fs.readFileSync(path.join(dir,'sitemap.xml'),'utf8');
    writeArticle(dir, article);
    assert.equal(fs.readFileSync(path.join(dir,'blog.html'),'utf8'), firstIndex);
    assert.equal(fs.readFileSync(path.join(dir,'sitemap.xml'),'utf8'), firstMap);
    execFileSync(process.execPath, ['scripts/build-blog-static.js', result.relative], {cwd:dir});
    const output = fs.readFileSync(path.join(dir,result.relative.replace('.md','.html')),'utf8');
    assert.match(output, new RegExp(`<!-- babylovegrowth:${result.hash} -->`));
    assert.equal((output.match(/<h1>/g)||[]).length, 1);
    assert.ok(output.includes(article.html));
    assert.match(output, /Price &#36;&amp;/);
    assert.doesNotMatch(output, /<script>evil\(\)<\/script>/);
    for (const m of output.matchAll(/<script type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)) JSON.parse(m[1]);
    execFileSync(php,['-r','$d=new DOMDocument();if(!$d->load($argv[1],LIBXML_NONET))exit(1);',path.join(dir,'sitemap.xml')]);
    writeArticle(dir,{...article,title:'Updated title'});
    assert.match(fs.readFileSync(path.join(dir,'blog.html'),'utf8'), /Updated title/);
    assert.throws(()=>writeArticle(dir,{...article,id:'different'}), /existing article/);
    assert.throws(()=>writeArticle(dir,{...article,slug:'changed-slug'}), /redirect/);
    fs.writeFileSync(path.join(dir,'blog/en/existing.md'), '---\ntitle: Existing\n---\nOriginal');
    assert.throws(()=>writeArticle(dir,{...article,slug:'existing'}), /existing article/);
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('HTTP method, bearer authentication and payload validation fail closed', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(),'blg-http-'));
  const webroot = path.join(base,'public_html'); fs.mkdirSync(webroot);
  fs.mkdirSync(path.join(base,'babylovegrowth'));
  fs.copyFileSync(path.join(root,'babylovegrowth.php'),path.join(webroot,'babylovegrowth.php'));
  const secret = 'a'.repeat(64);
  fs.writeFileSync(path.join(base,'babylovegrowth/config.json'),JSON.stringify({secret}));
  const port = 40000+Math.floor(Math.random()*10000);
  const server = spawn(php,['-S',`127.0.0.1:${port}`,'-t',webroot],{stdio:'ignore'});
  try {
    const url = `http://127.0.0.1:${port}/babylovegrowth.php`;
    let ready = false;
    for(let i=0;i<30;i++){try{await fetch(url);ready=true;break;}catch{await new Promise(r=>setTimeout(r,50));}}
    assert.ok(ready);
    assert.equal((await fetch(url)).status,405);
    assert.equal((await fetch(url,{method:'POST',body:'{}'})).status,401);
    for (const headers of [{'Authorization':`Bearer ${secret}`},{'X-API-Key':secret}]) {
      const response=await fetch(url,{method:'POST',headers,body:'{"slug":"../escape"}'});
      assert.equal(response.status,400); assert.equal((await response.json()).success,false);
    }
  } finally {server.kill();fs.rmSync(base,{recursive:true,force:true});}
});
