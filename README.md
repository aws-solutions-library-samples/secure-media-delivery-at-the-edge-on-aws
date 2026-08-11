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

## Requirements

- Node.js 22+
- AWS CDK v2.79.1+
- AWS account with CloudFront Functions CWT support

## Community ports

If you'd rather deploy this stack with Terraform than CDK, a community-maintained port is available:

- **Terraform**: [playon/terraform-aws-cta-secure-media](https://github.com/playon/terraform-aws-cta-secure-media) — feature-parity port as a reusable Terraform module. Vendors the Lambda runtime code from this repo unchanged; exposes the validator function ARN, KVS ARN, and API endpoint as module outputs so consumers can attach the validator to their own distribution.
