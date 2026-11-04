# VoxDonna virtual try-on demo

Verified implementation record: 2026-11-04.

Live demo: https://voxdonna.com/demo/virtual-try-on.html. The “Try it on now” CTA at /virtual-try-on.html opens this demo. Shared navigation was not changed. Consent links to the VoxDonna-hosted /demo/virtual-try-on-privacy.html.

## Implementation

- Static HTML with Inter, copper and warm-black VoxDonna styling.
- Browser SDK: @decartai/sdk 0.2.14, loaded on Start from esm.sh.
- Model: lucy-vton-latest (documented as lucy-vton-3.6 on 2026-11-04; the latest alias can change), standard speed.
- Six AI-generated garment image samples: men's shirt/T-shirt/coat and women's blouse/T-shirt/coat. The browser crops the selected cell of assets/virtual-try-on-samples.png into a 512px JPEG and sends it with its matching prompt. Four additional text-only styles remain available. Uploaded garment images and prompt edits still work.
- Sample sheet generated using the built-in image-generation tool: six isolated, front-facing catalogue garments on plain backgrounds, a 3×2 grid with no people or logos. Prompt: navy men's button-down shirt, forest-green men's T-shirt, camel men's coat, ivory women's satin blouse, dusty-rose women's T-shirt, charcoal women's double-breasted coat.
- Experimental jewellery samples use assets/virtual-try-on-jewellery.png, generated with the built-in image-generation tool as another 3×2 catalogue sheet. Prompt: yellow gold hoop earrings, pearl drop earrings, gold disc pendant necklace, emerald-green oval pendant necklace, plain gold curb chain and plain silver rope chain, isolated on pale backgrounds without people or logos.
- Jewellery uses single-action Add prompts with body placement, retaining the original outfit. Client guidance asks for visible ears/neckline and discloses variable placement/detail fidelity. Decart's prompting guide explicitly supports pendant necklaces; its example repository notes jewellery can challenge the standard realtime model. No extra image pre-generation service was added. Synthetic-camera acceptance tests prove reference transmission, not on-person fidelity.
- Uploaded images stay in browser memory and are sent to Decart when a session starts or Apply is pressed.
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

This optional real-provider check consumes credits, waits for output frames, applies a coat and each of the six jewellery references, then stops. Uses a synthetic camera, never a person's camera. The real-provider check received 1280 × 720 output on 2026-11-04. It does not establish garment realism, logo fidelity, fit accuracy, or Safari/iOS compatibility.

Before shipping: php -l virtual-try-on-token.php; node --check assets/virtual-try-on.js; node --check scripts/test-virtual-try-on.mjs; git diff --check. Check local/live HTML and JavaScript parity after deployment. Hostinger may re-encode PNGs: if bytes differ, compare decoded dimensions and pixels before concluding the image is stale.

## Source references

- https://docs.platform.decart.ai/llms.txt
- https://docs.platform.decart.ai/getting-started/client-tokens.md
- https://docs.platform.decart.ai/api-reference/create-client-token.md
- https://docs.platform.decart.ai/sdks/javascript-realtime.md
- https://docs.platform.decart.ai/models/realtime/vton-3.5-prompting.md
- https://github.com/DecartAI/tryon-examples/tree/main/examples/ecommerce

The e-commerce example informed the camera → token → model → outfit-change lifecycle. This implementation is native to VoxDonna's static/PHP stack. No Next.js app, payment flow, product inventory, background-removal service, or batch-video processing was added.

SDK detail verified against 0.2.14: model.fps is already a MediaTrackConstraints value ({ideal:30,max:30}); pass it directly to getUserMedia rather than nesting it in another ideal object.


## Decart integration lessons

These distinguish observed behavior in this integration from documented options that were not exercised here.

| Topic | Finding and implementation consequence | Evidence |
| --- | --- | --- |
| Documentation discovery | Start with llms.txt, then the realtime SDK, client-token and prompting pages. Examples are useful lifecycle references; match their framework to the host application. | Official sources above; native HTML/PHP implementation |
| Camera constraints | SDK 0.2.14 returns model.fps as an object. Pass it directly; wrapping it in another ideal fails before connecting. | Reproduced locally, fixed before f1bd9df |
| Initial vs updated state | initialState uses prompt: {text, enhance:false}; realtime set() uses prompt text, image and enhance:false. set() replaces state, so send every field to retain. | assets/virtual-try-on.js; upload retention and text-only switching tests |
| Tokens | Mint through apiKeyProvider immediately before dialing. A 60-second token lifetime does not terminate an active stream. Enforce session duration separately, server-side and in the UI. | Client-token docs; virtual-try-on-token.php; local timer regression |
| Secrets | Keep the permanent key on the server, outside the production webroot; return only short-lived tokens. Never put the permanent key in browser code or documentation. | Token endpoint and deployed private config |
| Reference images | Use isolated items on plain backgrounds, at least 512px square, with descriptive prompts. Clothing uses Substitute; accessories use Add plus body placement. | Prompting guide; all 12 distinct reference crops verified |
| Fast mode | Documented connect-time speed: "fast" costs 2x standard realtime. Standard means omitting the option, not sending "standard". Changing speed requires reconnecting. | User-supplied Decart guide; fast mode not implemented or tested |
| Jewellery | Request acceptance and output frames do not prove earrings or chains are positioned faithfully. Keep experimental labeling until human-camera tests validate each category. | Official tryon-examples README; synthetic-camera test scope |
| Cleanup | Stop local and remote tracks on Stop, pagehide, hidden tab and timeout. Reject late connect results after cancellation. | Regression tests and assets/virtual-try-on.js |
| PHP responses | PHP 8.5 curl_close deprecation can contaminate JSON when errors are displayed. unset releases the handle without that warning. | Local PHP 8.5.11 failure; production PHP 8.3.36 |
| Image test oracle | Pale catalogue images can share average colors. Hash complete decoded pixels to verify distinct crops. | scripts/test-virtual-try-on.mjs |
| Spend controls | Token rate limits and browser Origin checks are not a spending cap or authentication. Provider credit/concurrency controls remain necessary. | Public endpoint design review |

Batch video processing is documented by Decart but was not implemented or tested here. Do not present realtime verification as evidence for the batch API.

## Privacy and provider terms

The consent UI is branded VoxDonna and opens an original, locally hosted privacy notice. Clients do not need to visit the provider website. The notice still identifies Decart as the video processor and distinguishes VoxDonna's lack of session recording from provider-side retention.

On 2026-11-04, the published API Terms (updated July 26, 2026), section 2.3, permitted input/output use for service improvement and model training. No account-specific no-training exception was verified. The published privacy policy (updated August 20, 2026) did not establish a fixed deletion period for this demo. Do not claim zero retention, India-only processing or no model training without a verified applicable agreement. The general VoxDonna privacy policy now explicitly excludes this demo from its other-product India-only/no-training statements.

Sources checked:
- https://docs.platform.decart.ai/resources/api-terms
- https://docs.platform.decart.ai/resources/privacy-policy
- https://github.com/DecartAI/tryon-examples#extreme-precision-for-non-trivial-items

The app stores hashed IPs and request timestamps for rate limiting. Entries older than an hour are pruned on a subsequent successful rate-limit-file write; this is not scheduled deletion. No legal review of the notice was performed.

## Delivery record

| Commit | Delivered |
| --- | --- |
| f1bd9df | Secure realtime demo and scoped token endpoint |
| 9289634 | Six clothing image samples |
| 05abb63 | Six experimental jewellery images and reference tests |
| 047f91d | Landing CTA opens new demo; obsolete Tint widget removed |
| 5036067 | VoxDonna consent branding |
| 97dbb57 | VoxDonna-hosted try-on privacy notice and general-policy scope correction |

GitHub main triggers the Hostinger webhook. These releases were made from an isolated worktree at /private/tmp/voxdonna-vton-release to preserve unrelated divergence and files in the original checkout. Do not reset the original checkout to reproduce the release. The temporary worktree and ad hoc browser scripts are conveniences, not durable dependencies.

## Verification boundaries

- Local/live automated regressions passed for image selection, full-state updates, token restrictions, camera denial, session timeout and cancelled connections.
- Real Decart sessions with a synthetic camera returned 1280×720 output and accepted all six jewellery changes. This verifies integration, not realistic fit or jewellery placement.
- Chrome at 390px and 1440px verified both the live landing CTA and the consent link opening the VoxDonna policy, with no provider links on that notice. These routing checks were ad hoc browser checks, not additions to the maintained test suite.
- Human-camera fidelity, Safari/iOS, batch processing, fast mode and an account-specific retention/training agreement remain unverified.
- No application logic changed during the final documentation pass. No new paid generation or model-quality test was run for documentation.


## UX audit fixes (2026-11-04)

The camera panel now stays in view on desktop and becomes a compact sticky preview while a mobile session is active. Apply sits beside Stop, rather than below the full wardrobe. Before starting, a Back to camera link returns users from the wardrobe to consent and Start. Active-session presentation follows the existing busy state, including connection and cleanup; stream behavior is unchanged.

Narrow screens use two sample columns and 14px labels (13px elsewhere). Secondary standalone controls have at least 44px hit areas, the header wraps under text enlargement, and textarea text is 16px. Surface, muted and error values use the brand palette. No new animations or dependencies were added.

Regression coverage now includes 200% computed-text scaling at 320/390/1440px and preview/Apply/sample reachability at 320×640, 390×844, 768×900, 844×390 and 1440×900 during mocked live sessions. Hit tests catch controls obscured by the sticky panel. Stop restores the inactive layout. Real phone keyboards, Safari/iOS and human-camera model fidelity still need separate validation.
