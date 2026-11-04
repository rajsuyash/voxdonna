# VoxDonna virtual try-on demo

Page: /demo/virtual-try-on.html. A standalone client demo, not linked into the shared site navigation.

## Implementation

- Static HTML with Inter, copper and warm-black VoxDonna styling.
- Browser SDK: @decartai/sdk 0.2.14, loaded on Start from esm.sh.
- Model: lucy-vton-latest (currently lucy-vton-3.6), standard speed.
- Four text presets, editable prompts and JPEG/PNG/WebP garment upload. Preset illustrations are not product reference images. Uploads stay in browser memory and are sent to Decart when a session starts or Apply is pressed.
- Camera only, no microphone or recording. Original camera preview beside the generated video. Stop, page leave, hidden tab and a two-minute timer release streams. Late connection results are discarded.
- PHP token endpoint reads DECART_API_KEY from the process environment or ../vton.env outside the production webroot. The PHP development server reads the repository's gitignored .env instead.
- Tokens expire after 60 seconds and are minted per dial. Model/origin scope and a provider-enforced 120-second session limit are requested. The browser also stops after two minutes, including connection time.
- Locked rate-limit storage in the PHP temporary directory: six mint attempts per IP per ten minutes, 100 total per hour. Failed mint attempts count. No camera data or permanent key enters this storage.
- Public, no-login demo: these limits reduce abuse, but token mint limits are not a monetary spending cap. Origin headers can be spoofed outside browsers and a token can be reused before expiry. Decart account credit/concurrency controls remain the spending boundary.

## Run and verify

Requires PHP 8.1+ with cURL, Node and Playwright with Chrome. No project-wide type checker, linter or build system is configured.

    php -S 127.0.0.1:3499
    node scripts/test-virtual-try-on.mjs

The test script uses the installed Codex Playwright runtime. The default suite mocks Decart, exercises real browser camera tracks with synthetic input, and tests PHP token rules with isolated provider stubs. No credits are used.

    LIVE_VTON=1 node scripts/test-virtual-try-on.mjs

This optional real-provider check consumes credits and stops immediately after receiving output frames. Uses a synthetic camera, never a person's camera. The real-provider check received 1280 × 720 output on 2026-11-04. It does not establish garment realism, logo fidelity, fit accuracy, or Safari/iOS compatibility.

Before shipping: php -l virtual-try-on-token.php; node --check assets/virtual-try-on.js; node --check scripts/test-virtual-try-on.mjs; git diff --check. Check the local and live byte parity after deployment.

## Source references

- https://docs.platform.decart.ai/llms.txt
- https://docs.platform.decart.ai/getting-started/client-tokens.md
- https://docs.platform.decart.ai/api-reference/create-client-token.md
- https://docs.platform.decart.ai/sdks/javascript-realtime.md
- https://docs.platform.decart.ai/models/realtime/vton-3.5-prompting.md
- https://github.com/DecartAI/tryon-examples/tree/main/examples/ecommerce

The e-commerce example informed the camera → token → model → outfit-change lifecycle. This implementation is native to VoxDonna's static/PHP stack. No Next.js app, payment flow, product inventory, background-removal service, or batch-video processing was added.

SDK detail verified against 0.2.14: model.fps is already a MediaTrackConstraints value ({ideal:30,max:30}); pass it directly to getUserMedia rather than nesting it in another ideal object.
