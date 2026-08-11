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

Signing keys are stored in Secrets Manager and synced to CloudFront KeyValueStore. Rotation is handled by a Step Functions workflow:

1. Generates new 32-byte hex key
2. Stores in Secrets Manager
3. Syncs to KVS as `key:default`
4. Preserves previous key as `key:previous` for graceful transition

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
| **Secrets Manager** | 0 (key cached in Lambda) | Negligible | [Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/) |
| **Kinesis (real-time logs)** | 1 record per CF request | 1.5M PUT records | [Kinesis pricing](https://aws.amazon.com/kinesis/data-streams/pricing/) |
| **S3 (demo site)** | Static hosting only | Minimal | [S3 pricing](https://aws.amazon.com/s3/pricing/) |

### Fixed / Scheduled Costs

| Service | Frequency | Notes |
|---------|-----------|-------|
| **WAFv2 Web ACL** | Always-on | $5/month + $1/rule + $0.60/M requests evaluated |
| **Step Functions (key rotation)** | Monthly (default) | ~5 state transitions per rotation |
| **Lambda (KVS cleanup)** | Hourly | Single invocation, <1s duration |
| **Secrets Manager** | 1 secret | $0.40/month |
| **Bedrock (auto-revocation)** | Per Kinesis batch (if enabled) | Input/output tokens at Nova Lite rates |

### Cost Optimization Tips

- **CloudFront Functions** are significantly cheaper than Lambda@Edge ($0.10/M vs $0.60/M) — this architecture avoids L@E entirely
- **KVS reads** at the edge are included in CloudFront pricing at $0.05 per 10M reads
- **Token TTL** is the primary cost lever — longer TTLs mean fewer renewal API calls. A 2-hour TTL means ~1 API call per viewer per 2 hours; a 24-hour TTL reduces it to near-zero
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
