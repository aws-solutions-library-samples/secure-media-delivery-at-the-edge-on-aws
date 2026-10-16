# CTA-5007-B Secure Media Delivery

COSE MAC0 / CWT token-based content protection for Amazon CloudFront, implementing the CTA-5007-B Common Access Token specification.

## Features

- **Spec-compliant tokens**: COSE MAC0 structure with HMAC-SHA256, validated by CloudFront Functions `cf.cwt.validateToken()`
- **Multi-language SDKs**: Node.js, Python, and Ruby — all produce byte-identical tokens
- **Path-based token delivery**: `/{TOKEN}/video/stream.m3u8` with automatic token stripping at the edge
- **Client-side token renewal**: Player swaps expired path tokens for fresh ones without interrupting playback
- **Session revocation**: Instant token blocking via CloudFront KeyValueStore
- **IP and country restrictions**: Enforced at the edge using `event.viewer.ip` and `CloudFront-Viewer-Country`
- **Interactive demo**: Aura-styled website with HLS.js + DASH.js players, token generation, renewal, and revocation
- **Real-time log analysis**: Kinesis Data Stream → Lambda → Bedrock Nova Lite for AI-powered session anomaly detection
- **Auto-revocation**: Suspicious sessions flagged by Bedrock are automatically revoked in CloudFront KeyValueStore
- **Revocation dashboard**: Aura-styled dashboard showing revoked sessions with editable Bedrock analysis prompts
- **KVS cleanup**: Scheduled Lambda purges expired revocation entries from KeyValueStore

## Quick Start

```bash
cd source
npm install
npx cdk bootstrap    # First time only
npx cdk deploy CTASecureMedia -c enableDemo=true
```

The demo website URL and API endpoint are printed in the stack outputs.

## Architecture

```
Browser (HLS.js / DASH.js)
  │
  ├─ GET /{TOKEN}/video/stream.m3u8
  │     ↓
  │  CloudFront (default behavior)
  │     → CTA Validator Function (cf.cwt.validateToken)
  │        → Validates COSE MAC0 signature
  │        → Checks exp, catu (URI), catnip (IP), country
  │        → Checks revocation in KeyValueStore
  │        → Strips token from path → forwards to origin
  │
  ├─ POST /token (or /token-python, /token-ruby)
  │     ↓
  │  API Gateway → Lambda (Node/Python/Ruby)
  │     → Reads signing key from Secrets Manager
  │     → Builds CWT claims, generates COSE MAC0 token via SDK
  │     → Returns { token, signedUrl, expiresAt }
  │
  ├─ POST /revoke
  │     ↓
  │  API Gateway → Lambda
  │     → Writes revoked:{sessionId} to KeyValueStore
  │     → Edge enforcement within ~15 seconds
  │
  └─ Real-Time Log Pipeline
        CloudFront Real-Time Logs → Kinesis Data Stream
           → Lambda (kinesis_analyzer)
              → Aggregates session metrics
              → Sends to Bedrock Nova Lite/Pro for analysis
              → Auto-revokes flagged sessions in KVS

Dashboard (/website/dashboard.html)
  ├─ GET /revoked → Lists revoked sessions from KVS
  ├─ GET /prompt → Reads Bedrock analysis prompt from SSM
  └─ PUT /prompt → Updates Bedrock analysis prompt in SSM
```

## Token Structure

Tokens follow the COSE MAC0 / CWT structure per RFC 8152 and RFC 8392:

```
Tag(61) CWT {
  Tag(17) COSE_Mac0 {
    [ protectedHeaders, unprotectedHeaders, payload, hmacTag ]
  }
}
```

### CWT Claims

| Claim | Key | Description |
|-------|-----|-------------|
| `iss` | 1 | Issuer identifier |
| `exp` | 4 | Expiration (Unix timestamp) |
| `nbf` | 5 | Not before (Unix timestamp) |
| `iat` | 6 | Issued at (Unix timestamp) |
| `cti` | 7 | Token ID (session ID for revocation) |
| `catu` | 401 | URI restrictions (path prefix matching) |
| `catnip` | 402 | IP restrictions (array of allowed IPs) |
| `catgeoiso3166` | 316 | Country restrictions (ISO 3166-1 codes) |

### A Note on IP Restrictions

IP binding (`catnip`) is the strongest anti-sharing signal — if a token is locked to one IP and appears from another, it's clearly being redistributed. However, it's also the most likely to cause **false positives for legitimate mobile viewers**.

A viewer watching on home WiFi who walks to the backyard and their phone switches to cellular will get a new public IP address. Their token is still valid (not expired, not revoked), but the IP no longer matches. The same viewer might also appear to change city if the cellular tower's IP geo-maps to a neighboring town.

**Recommendations:**

- **Short-lived events (live sports):** IP binding is usually safe — viewers stay put for the duration
- **Long-form content (movies, series):** Consider skipping IP restriction or using it in log-only mode for analytics without enforcement
- **Mobile-heavy audiences:** Use country or region restrictions instead of IP — they survive WiFi→cellular handoffs within the same geography
- **If you must bind IP:** Use a short TTL (e.g., `5m`) with frequent renewal. Each renewal captures the viewer's current IP, so a legitimate network switch gets a fresh token on the next renewal cycle

The auto-revocation system (Bedrock analysis) treats a single IP change within the same country as low-risk specifically to avoid flagging these legitimate transitions.

## SDKs

All three SDKs expose the same API and produce byte-identical COSE MAC0 tokens.

### Node.js

```javascript
const { CTAClient } = require('./sdk/javascript/cta-client');

const client = new CTAClient('CTASecureMedia');
await client.initSecretsManager();
await client.getSigningKeys();

const result = client.generateSignedUrl(
  'https://cdn.example.com/video/stream.m3u8',
  { paths: ['/video/'], ttl: '2h', sessionId: 'viewer-123' }
);
console.log(result.signedUrl);
```

Requires `cbor-x` for CBOR encoding.

### Python

```python
from cta_client import CTAClient

client = CTAClient('CTASecureMedia')
client.init_secrets_manager()
client.get_signing_keys()

result = client.generate_signed_url(
    'https://cdn.example.com/video/stream.m3u8',
    {'paths': ['/video/'], 'ttl': '2h', 'sessionId': 'viewer-123'}
)
print(result['signedUrl'])
```

Zero external dependencies — built-in CBOR encoder.

### Ruby

```ruby
require_relative 'cta_client'

client = CTA::Client.new('CTASecureMedia')
client.init_secrets_manager
client.get_signing_keys

result = client.generate_signed_url(
  'https://cdn.example.com/video/stream.m3u8',
  { 'paths' => ['/video/'], 'ttl' => '2h', 'sessionId' => 'viewer-123' }
)
puts result[:signed_url]
```

Zero external dependencies — uses `openssl` from stdlib.

## Token Generation API

All three Lambda endpoints accept the same request format:

```bash
curl -X POST https://<api-endpoint>/prod/token \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "paths": ["/video/"],
      "ttl": "2h",
      "placement": "path",
      "sessionId": "viewer-123",
      "ips": "203.0.113.50",
      "countries": ["us", "ca"]
    },
    "mediaUrl": "https://your-distribution.cloudfront.net/video/stream.m3u8"
  }'
```

**Endpoints:**
- `POST /token` — Node.js SDK
- `POST /token-python` — Python SDK
- `POST /token-ruby` — Ruby SDK
- `POST /revoke` — Token revocation

**Response:**
```json
{
  "token": "2D3YEYRDoQEF...",
  "signedUrl": "https://cdn/TOKEN/video/stream.m3u8",
  "expiresAt": 1776881062
}
```

## Token Renewal Flow

1. **Initial playback**: Player loads `/{TOKEN₁}/video/stream.m3u8`
2. **Renewal timer**: At 2/3 of TTL, player calls `POST /token` for a fresh token
3. **Token swap**: Player replaces the old path token with the new one in segment URLs
4. **Seamless playback**: No interruption — CloudFront validates the new token identically

## Session Revocation

```bash
curl -X POST https://<api-endpoint>/prod/revoke \
  -H "Content-Type: application/json" \
  -d '{"tokenId": "viewer-123", "reason": "manual"}'
```

The revocation propagates to CloudFront edge locations via KeyValueStore within ~15 seconds. Subsequent requests with the revoked session ID receive HTTP 401.

## CloudFront Distribution Layout

| Path | Behavior | Origin | Auth |
|------|----------|--------|------|
| `/website/*` | Static site + dashboard | S3 bucket | None |
| `/api/*` | API Gateway | REST API | None (CORS enabled) |
| `/*` (default) | Video content | HTTP origin | CTA Validator Function |

### Demo Pages

| Page | Token Delivery Mode |
|------|---------------------|
| `/website/index-path.html` | Path token — CMS-friendly signed URLs |
| `/website/index-header.html` | Header-only — `CTA-Common-Access-Token` header |
| `/website/index-hybrid.html` | Hybrid — path init, header renewal |
| `/website/dashboard.html` | Revocation dashboard + Bedrock prompt editor |

## Token Transport Compatibility

The CloudFront Function validator supports three token delivery methods. Each has different compatibility characteristics depending on your distribution shape and player environment.

| Transport | Multi-behavior distributions | Native `<video>` players | CORS overhead | Cache-key considerations |
|-----------|:---------------------------:|:------------------------:|:-------------:|--------------------------|
| **Path** `/{TOKEN}/...` | ❌ | ✅ | None | Token is stripped before origin; no cache pollution |
| **Header** `CTA-Common-Access-Token` | ✅ | ❌ | Preflight per cross-origin request | Include header in cache key or use `no-store` on origin |
| **Query** `?CAT=<token>` | ✅ | ✅ | None | Strip `CAT` from cache key or accept per-viewer caching |

### Path tokens require a single-behavior distribution

CloudFront matches requests to cache behaviors based on the **original URI before the viewer-request function runs**. A URL like `/{TOKEN}/broadcast/foo.m3u8` matches the default behavior (`/*`), not a `/broadcast/*` behavior — even though the function strips the token prefix.

Path transport works when all protected content is served by the default behavior (the demo's distribution shape). If your distribution has multiple content behaviors with distinct path patterns, use header or query transport instead.

### Header tokens require MSE-based players

Custom HTTP headers cannot be set on native `<video src="...">` elements. Header transport requires a JavaScript-based player with request interceptor support:
- **HLS.js** — `xhrSetup` callback
- **DASH.js** — `RequestModifier` extension
- **Shaka Player** — request/response filters

This excludes iOS Safari's native HLS player (non-MSE). If you need native player support, use query transport.

### Query tokens are universal but need cache-key planning

Query parameter transport (`?CAT=<token>`) works with all players and all distribution shapes. However:
- If your cache policy **includes** `CAT` in the query string allowlist, each viewer gets a unique cache entry (expensive, defeats edge caching)
- If your cache policy **excludes** `CAT`, the function must strip it before forwarding to origin (the validator already does this via `delete request.querystring["CAT"]`)

The recommended approach: exclude `CAT` from the cache key and let the validator strip it.

## Extending the Validator with Additional Claims

The CloudFront Function validator can be extended to enforce additional viewer attributes beyond IP, country, and URI path. CloudFront provides a rich set of geo and device headers that can be used as token claims.

### Available CloudFront Viewer Headers

| Header | Example Value | Use Case |
|--------|---------------|----------|
| `cloudfront-viewer-country` | `US` | Country restriction (already implemented) |
| `cloudfront-viewer-country-region` | `CA` (California) | State/province restriction |
| `cloudfront-viewer-city` | `Seattle` | City-level geo-fencing |
| `cloudfront-viewer-postal-code` | `98101` | Postal code restriction |
| `cloudfront-viewer-metro-code` | `819` | DMA/metro area blackouts |
| `cloudfront-viewer-latitude` | `47.6062` | Coordinate-based geo-fencing |
| `cloudfront-viewer-longitude` | `-122.3321` | Coordinate-based geo-fencing |
| `cloudfront-viewer-asn` | `16509` | ISP/network restriction |
| `cloudfront-viewer-tls` | `TLSv1.3` | Minimum TLS enforcement |
| `cloudfront-is-mobile-viewer` | `true` | Device type restriction |
| `cloudfront-is-tablet-viewer` | `true` | Device type restriction |
| `cloudfront-is-desktop-viewer` | `true` | Device type restriction |
| `cloudfront-is-smarttv-viewer` | `true` | Device type restriction |

These headers must be enabled in your cache policy or origin request policy for CloudFront to populate them.

### How to Add a New Check

Adding a new claim requires changes in three places:

**1. Token Generator** — add the claim to the CWT claims map:

```javascript
// Example: metro/DMA code restriction
if (policy.metroCodes) {
    claims.set(817, policy.metroCodes); // custom claim key
}
```

**2. CloudFront Function Validator** — add validation logic in `validateClaims()`:

```javascript
// Example: metro/DMA code check
if (payload["817"]) {
    var metro = request.headers["cloudfront-viewer-metro-code"];
    if (!metro || payload["817"].indexOf(metro.value) === -1) {
        throw new Error("metro_restricted");
    }
}
```

**3. CDK Stack** — include the header in the cache policy so CloudFront populates it:

```typescript
cachePolicy: new cloudfront.CachePolicy(this, "CTACachePolicy", {
    headerBehavior: cloudfront.CacheHeaderBehavior.allowList(
        "CloudFront-Viewer-Country",
        "CloudFront-Viewer-Metro-Code"  // add new headers here
    ),
}),
```

### Cache-Key Rule

**Any header used for an access decision must be included in the cache key.** If a header is used to allow or deny access but is not part of the cache key, a successful response can be cached and served to a viewer with a different value for that header — bypassing the restriction.

For example: if you enforce `cloudfront-viewer-metro-code` but don't include it in the cache key, a viewer in an allowed DMA gets their response cached, and a viewer in a blocked DMA receives the cached success.

### CloudFront Function Size Limit

CloudFront Functions have a **10 KB code size limit**. Each additional check adds code to the validator. Plan your claim set carefully — if you need many complex checks (regex matching, haversine distance calculations, large allowlists), you may approach this ceiling. Keep validation logic concise and avoid inlining large data structures in the function code; use KVS lookups for dynamic data instead.

## Key Rotation

Scheduled rotation is **disabled by default**. Do not manually start rotation until the updated validators and mints are deployed together and the deployment checks below pass.

The Step Functions workflow uses one stable execution ARN as its rotation ID:

1. **Prepare:** atomically publish the new raw signing key at `key:default`, the old key at `key:previous` as `{"signingKey":"…","expiresAt":null}`, and ownership state at `key:rotation`. The mint still reads the old Secrets Manager `AWSCURRENT` version. Both keys validate; normal token expiry, revocation, and policy checks still apply.
2. **Wait for propagation:** wait at least 300 seconds, measured from confirmation of the atomic KVS update. This is a configured propagation allowance, **not an acknowledgement from every edge location**. Verify the allowance for each deployment before allowing rotation; increase it if needed.
3. **Promote:** create an idempotent `AWSPENDING` secret version, then move `AWSCURRENT` with the old version as an ownership guard. Confirm the new version before starting the overlap clock.
4. **Finalize overlap:** set the previous-key expiry to promotion confirmation + configured overlap + 60-second mint-cache allowance + 60-second in-flight allowance. Overlap must be at least 7200 seconds (2 hours). At expiry, validators reject old-key signatures even if physical cleanup is delayed.
5. **Cleanup:** after the deadline, confirm the mint still uses the new version, remove the pending label, and atomically delete `key:previous` and remove signing material from active rotation state. A key-free completion tombstone prevents old execution retries from affecting later rotations.

Lambda mints refresh their signing key within **60 seconds** of a fetch starting, including fetch latency. A failed refresh refuses to mint with stale cached material. Supported TTLs are positive integer-valued JSON numbers (for example, `3600.0` or `1e3`) or integer `s/m/h` durations, up to **7200 seconds (2 hours)**; only an omitted TTL defaults to `2h`. Booleans, fractional or non-finite numbers, and durations above that maximum, including `1d`, are rejected.

The combined **propagation + overlap + 60-second mint-cache allowance + in-flight allowance** must not exceed **31,449,600 seconds (364 days)**. CDK and Terraform use the default 60-second in-flight allowance; the Lambda also includes any configured `ROTATION_IN_FLIGHT_SECONDS` override in this bound. This reserves one day within the Standard workflow's one-year execution limit for tasks and retries. Configuration is rejected before staging; the 2-hour maximum/default token TTL and minimum overlap remain unchanged.

### Failure recovery and deployment gate

- Deploy validators and mints before changing rotation behavior. Keep existing EventBridge rotation rules disabled during rollout; applying these changes sets the schedule disabled unless explicitly opted in. Do not invoke the old `{rotate:true}` Lambda interface.
- **Interim deployment block:** live rotation schedule disables are out-of-band changes against old `main`, not protection encoded in that revision. Do not apply CTA roots sourced from old `main` until the reviewed disabled-default branch is deployed; an old-main apply can re-enable rotation. Keep manual rotation blocked throughout this gate.
- Inventory legacy/custom issuer TTLs. Previously issued tokens longer than 2 hours must expire before the first rotation, or the configured overlap must cover their maximum remaining lifetime. Longer overlap remains configurable for these legacy tokens. All continuing issuers must comply with the supported TTL/cache bounds.
- Verify old- and new-key requests through the actual CloudFront distribution, warm mint refresh, original token expiry, revocation/policy checks, and previous-key expiry/deletion. Local cryptographic tests do not prove AWS edge propagation.
- Consumers attached to an unchanged validator ARN do not need a distribution code/configuration change. Deploy the owning CTA stack, publish the updated LIVE function, and verify through the existing consumer distribution before permitting rotation. If the function ARN changes, update the consumer association only after the replacement validator and mint are ready.
- Within the 14-day Step Functions redrive window, redrive an eligible failed execution with its **same execution ARN**. After that window, use the direct recovery procedure below. Do not start a second rotation or overwrite KVS/secret state. CAS ownership rejects competing executions. Initial deployment sync skips an active rotation rather than resetting it.
- Before confirmed promotion, the previous-key deadline stays `null`, so a partial failure cannot expire the key still used by the mint. Resume the execution to finish promotion/finalization. After finalization, an interrupted cleanup does not extend signature acceptance; resume cleanup to physically delete the retained key.
- Rotation inputs, outputs, and logs contain no signing material. Do not enable SDK wire logging or print KVS/secret contents during troubleshooting.

CDK configuration: `main.rotationEnabled` defaults to false; `main.rotationOverlapSeconds` defaults to 7200 (minimum 7200); `main.rotationPropagationSeconds` defaults to 300. The monthly cadence applies only after opt-in.

### Direct recovery after the redrive window

Keep all rotation schedules disabled throughout recovery. First use Step Functions `DescribeExecution` on the **original execution ARN** and confirm its status is terminal (`FAILED`, `TIMED_OUT`, or `ABORTED`), not `RUNNING`. Never restart the workflow with a new execution ARN or change the stored ownership ID.

Invoke the existing SyncKeysToKvs Lambda directly with `InvocationType: RequestResponse`. Each payload must be `{"action":"<action>","executionId":"<original execution ARN>"}`. For **every** invocation, inspect the Invoke response metadata: require `StatusCode: 200` and an absent `FunctionError` before using its returned JSON payload or continuing. HTTP success alone does not establish function success. On an error, stop and diagnose without printing secret/KVS values; retry only the same action and execution ID.

1. Invoke `prepare`; retain its key-free `propagationReadyTimestamp`.
2. Wait until that absolute UTC timestamp has passed. Do not substitute a new relative timer or shorten the wait because the execution is old.
3. Invoke `promote`, then invoke `finalize`; retain the latter's key-free `cleanupTimestamp`.
4. Wait until `cleanupTimestamp` has passed, then invoke `cleanup` and require the key-free result's `phase` to be `complete`.

Repeated actions are idempotent for this original execution ID: already-completed phases retain their recorded deadlines, and completion tombstones prevent a replay from starting another rotation. If recovery is interrupted, repeat this sequence with the same ARN. Lambda action results contain only execution ID, phase, and timestamps, never signing keys. Record only those fields and invocation status; do not enable SDK wire logging or dump Secrets Manager/KVS contents. No new workflow execution, manual KVS edit, or manual secret-stage mutation is part of this procedure. These instructions do not authorize live recovery or rotation before the deployment gate passes.

### Legacy previous-key migration

Only when `key:rotation` is absent, a nonempty ASCII-alphanumeric `key:previous` is recognized as the legacy raw-key format, covering both initial generated passwords and later hexadecimal rotation keys, including configured key lengths. Raw previous records were not consumed by the pre-change validator; migration does not grant them a new acceptance window. Initial deployment sync atomically initializes a missing/empty `key:default` from the current secret key and deletes the raw previous key, or keeps an already-matching default key and atomically deletes the raw previous key. If a nonempty default key differs from the mint's current signing key, initialization fails closed without changing either key. `prepare` likewise requires mint/edge agreement, then atomically replaces the legacy raw previous key with the structured previous record for the currently minted key while staging the new default. Apply the legacy-token lifetime deployment gate before this migration. An existing rotation state protects ownership and retained keys; a structured previous record or unknown/malformed previous value is never silently discarded. Conflicts fail closed and require investigation, not manual deletion of ownership or retained-key state.



## WAF Rate Limiting

A WAFv2 Web ACL is attached to the CloudFront distribution to prevent automated token minting abuse. The default rule rate-limits `POST /api/token*` requests per source IP.

### Default Configuration

| Setting | Value |
|---------|-------|
| Rule name | `TokenMintRateLimit` |
| Rate limit | 300 requests per 5-minute window (~60/min per IP) |
| Scope | Requests matching `STARTS_WITH /api/token` |
| Action | Block with HTTP 429 + JSON error body |
| Metrics | CloudWatch metrics enabled, sampled requests enabled |

The 300 req/5min threshold is well above legitimate player traffic (a viewer typically mints one token per TTL — e.g., once every 2 hours) but tight enough to block automated scraping.

### Blocked Response

When rate-limited, clients receive:

```json
HTTP/1.1 429 Too Many Requests
{
  "error": "rate_limited",
  "message": "Too many token mint requests from this IP; try again in a few minutes."
}
```

### Editing WAF Rules

The Web ACL ARN is available in the stack outputs (`WebAclArn`). To modify rules:

**Via AWS Console:**
1. Navigate to **WAF & Shield** → **Web ACLs** → Select `CTASecureMedia-token-rate-limit`
2. Edit the `TokenMintRateLimit` rule to adjust the rate limit, scope, or action
3. Add additional rules (geo-blocking, IP allowlists, managed rule groups, etc.)

**Via AWS CLI:**

```bash
# Get current Web ACL configuration
aws wafv2 get-web-acl \
  --name CTASecureMedia-token-rate-limit \
  --scope CLOUDFRONT \
  --region us-east-1 \
  --id <web-acl-id>

# Update the rate limit (example: change to 100 req/5min)
aws wafv2 update-web-acl \
  --name CTASecureMedia-token-rate-limit \
  --scope CLOUDFRONT \
  --region us-east-1 \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action Allow={} \
  --rules '[...]' \
  --visibility-config '...'
```

**Via CDK (permanent change):**

Edit `source/lib/cta-secure-media-stack.ts` and modify the `rateBasedStatement.limit` value in the `CTAWebAcl` construct, then redeploy.

### Adding Custom Rules

Common additions to the Web ACL:

- **Geo-blocking**: Block token requests from specific countries
- **IP allowlist**: Only allow token minting from known backend IPs (e.g., your CMS servers)
- **AWS Managed Rules**: Add `AWSManagedRulesCommonRuleSet` for general web protection
- **Bot Control**: Add `AWSManagedRulesBotControlRuleSet` to block automated clients

## Real-Time Log Analysis (Auto-Revocation Stack)

An optional second CDK stack adds AI-powered session analysis:

1. CloudFront real-time access logs stream to Kinesis Data Streams
2. A Lambda consumer aggregates session metrics (IPs, countries, user agents, request rates)
3. Bedrock Nova Lite/Pro analyzes the metrics and flags suspicious sessions
4. Flagged sessions are automatically revoked in CloudFront KeyValueStore

The analysis prompt is editable via the revocation dashboard or the Prompt API (`GET/PUT /prompt`).

Deploy with:

```bash
npx cdk deploy --all -c enableAutoRevocation=true -c enableDemo=true
```

## KVS Cleanup

A scheduled Lambda runs hourly to purge expired revocation entries from KeyValueStore (default TTL: 24 hours).

## Stacks

| Stack | Description |
|-------|-------------|
| `CTASecureMedia` | Main stack: CloudFront, KVS, API Gateway, Lambdas, Secrets Manager, Kinesis, Step Functions |
| `CTAAutoRevocation` | Optional: Bedrock-powered Kinesis consumer, SSM prompt parameter, Prompt API |

## CDK Stack Outputs

After deployment, the stacks export the following outputs:

### CTASecureMedia (main stack)

| Output | Description |
|--------|-------------|
| `APIEndpoint` | CTA API endpoint (via CloudFront) — `https://<dist>/api` |
| `DemoWebsiteUrl` | Demo page — Path token mode |
| `DemoWebsiteHeaderUrl` | Demo page — Header-only token mode |
| `DemoWebsiteHybridUrl` | Demo page — Hybrid (path init → header renewal) |
| `DashboardUrl` | Standalone revocation dashboard with Bedrock prompt editor |
| `KeyValueStoreId` | CloudFront KeyValueStore ID (revocation + signing keys) |
| `SecretArn` | Secrets Manager ARN for the HMAC signing key |
| `RotationWorkflow` | Step Functions workflow name for key rotation |
| `WebAclArn` | WAFv2 Web ACL ARN (rate-limits token minting) |
| `CTAStandard` | Implemented specification version (`CTA-5007-B`) |

### CTASecureMediaAutoRevocation (optional stack)

| Output | Description |
|--------|-------------|
| `PromptAPIEndpoint` | API endpoint for reading/editing the Bedrock analysis prompt |

## Cost Estimate

The solution uses serverless/pay-per-use services. Costs scale with viewer count and session duration. Below is a breakdown of per-service usage at steady-state streaming.

### Per-Viewer Cost Drivers (1,000 concurrent viewers, 2-hour sessions, HLS)

A typical HLS viewer generates ~720 segment requests/hour (2s segments) plus periodic manifest fetches. With 2-hour token TTL, each viewer mints one token at start and one renewal.

| Service | Usage per viewer/session | At 1,000 viewers | Pricing page |
|---------|------------------------|------------------|--------------|
| **CloudFront requests** | ~1,500 GET requests (segments + manifests) | 1.5M requests | [CloudFront pricing](https://aws.amazon.com/cloudfront/pricing/) |
| **CloudFront Function** | 1 invocation per request (validator) | 1.5M invocations | Included in CF pricing |
| **KVS reads** | 2 per request (signing key + revocation check) | 3M reads | [KVS pricing](https://aws.amazon.com/cloudfront/pricing/) |
| **API Gateway** | 2 requests (initial token + 1 renewal) | 2,000 requests | [API Gateway pricing](https://aws.amazon.com/api-gateway/pricing/) |
| **Lambda (token gen)** | 2 invocations × ~100ms | 2,000 invocations | [Lambda pricing](https://aws.amazon.com/lambda/pricing/) |
| **Secrets Manager** | Cache refresh at most once per 60 seconds per active warm mint environment | Depends on warm environment count | [Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/) |
| **Kinesis (real-time logs)** | 1 record per CF request | 1.5M PUT records | [Kinesis pricing](https://aws.amazon.com/kinesis/data-streams/pricing/) |
| **S3 (demo site)** | Static hosting only | Minimal | [S3 pricing](https://aws.amazon.com/s3/pricing/) |

### Fixed / Scheduled Costs

| Service | Frequency | Notes |
|---------|-----------|-------|
| **WAFv2 Web ACL** | Always-on | $5/month + $1/rule + $0.60/M requests evaluated |
| **Step Functions (key rotation)** | Monthly after opt-in; disabled by default | 6 workflow states before retries |
| **Lambda (KVS cleanup)** | Hourly | Single invocation, <1s duration |
| **Secrets Manager** | 1 secret | $0.40/month |
| **Bedrock (auto-revocation)** | Per Kinesis batch (if enabled) | Input/output tokens at Nova Lite rates |

### Cost Optimization Tips

- **CloudFront Functions** are significantly cheaper than Lambda@Edge ($0.10/M vs $0.60/M) — this architecture avoids L@E entirely
- **KVS reads** at the edge are included in CloudFront pricing at $0.05 per 10M reads
- **Token TTL** affects renewal API costs within the supported 2-hour maximum: a 2-hour TTL means ~1 API call per viewer per 2 hours; shorter TTLs require more frequent renewals.
- **Kinesis** can be disabled if real-time log analysis isn't needed (remove the real-time log config from the distribution)
- **Bedrock** is only invoked if the auto-revocation stack is deployed AND the Kinesis consumer detects suspicious patterns — most batches skip Bedrock entirely

### Pricing Calculator

Use the [AWS Pricing Calculator](https://calculator.aws/) to estimate costs for your specific viewer count and session patterns.

## Requirements

- Node.js 22+
- AWS CDK v2.79.1+
- AWS account with CloudFront Functions CWT support

## Community ports

If you'd rather deploy this stack with Terraform than CDK, a community-maintained port is available:

- **Terraform**: [playon/terraform-aws-cta-secure-media](https://github.com/playon/terraform-aws-cta-secure-media) — feature-parity port as a reusable Terraform module. Vendors the Lambda runtime code from this repo unchanged; exposes the validator function ARN, KVS ARN, and API endpoint as module outputs so consumers can attach the validator to their own distribution.
