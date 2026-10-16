# Deployment Guide

## Prerequisites

- Node.js 22+
- AWS CDK v2.79.1+
- AWS CLI configured with appropriate credentials
- CloudFront Functions CWT support (JS runtime 2.0)

## Deploy

### 1. Install dependencies

```bash
cd cta-compliant-solution/source
npm install
```

### 2. Bootstrap CDK (first time only)

```bash
npx cdk bootstrap
```

### 3. Deploy the stack

Deploy the main stack only:

```bash
npx cdk deploy CTASecureMedia -c enableDemo=true
```

Deploy both stacks (main + auto-revocation with Bedrock analysis):

```bash
npx cdk deploy --all -c enableDemo=true -c enableAutoRevocation=true
```

To deploy without the demo website:

```bash
npx cdk deploy CTASecureMedia -c enableDemo=false
```

### 4. Note the outputs

The deployment prints:

| Output | Description |
|--------|-------------|
| `DemoWebsiteUrl` | Demo site URL (if enabled) |
| `APIEndpoint` | CloudFront-fronted API URL |
| `CTAAPIEndpoint` | Direct API Gateway URL |
| `SecretArn` | Secrets Manager signing key ARN |
| `KeyValueStoreId` | CloudFront KVS ID |
| `RotationWorkflow` | Step Functions key rotation workflow |
| `PromptAPIEndpoint` | Bedrock prompt management API (auto-revocation stack) |

The dashboard is accessible at `{DemoWebsiteUrl}/../dashboard.html` (same S3 bucket, `/website/` prefix).

## Key Sync

The deployment automatically syncs the signing key from Secrets Manager to CloudFront KeyValueStore via a custom resource. No manual key configuration is needed.

To manually rotate keys:

```bash
aws stepfunctions start-execution \
  --state-machine-arn <RotationWorkflow ARN> \
  --input '{"rotate": true}'
```

## Token Generation API

All endpoints accept the same request format:

```bash
# Node.js SDK
curl -X POST https://<api-endpoint>/prod/token \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "paths": ["/video/"],
      "ttl": "2h",
      "placement": "path",
      "sessionId": "viewer-123",
      "ips": "203.0.113.50"
    },
    "mediaUrl": "https://<distribution>.cloudfront.net/video/stream.m3u8"
  }'

# Python SDK
curl -X POST https://<api-endpoint>/prod/token-python ...

# Ruby SDK
curl -X POST https://<api-endpoint>/prod/token-ruby ...
```

### Policy fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `paths` | string[] | No | URI prefix restrictions (e.g. `["/video/"]`) |
| `ttl` | number or string | No | Token lifetime: positive integer seconds or integer `s`/`m`/`h` durations (e.g. `30`, `"30s"`, `"5m"`, `"2h"`), maximum 7200 seconds (2 hours); default: `"2h"` |
| `placement` | string | No | `"path"` (default) or `"query"` |
| `sessionId` | string | No | Session ID for revocation tracking |
| `ips` | string | No | Allowed viewer IP address |
| `countries` | string[] | No | Allowed country codes (ISO 3166-1 lowercase) |

## Token Revocation

```bash
curl -X POST https://<api-endpoint>/prod/revoke \
  -H "Content-Type: application/json" \
  -d '{"tokenId": "viewer-123", "reason": "manual"}'
```

Propagates to edge locations via KeyValueStore within ~15 seconds.

## Testing

### Verify token generation

```bash
RESULT=$(curl -s -X POST https://<api-endpoint>/prod/token \
  -H "Content-Type: application/json" \
  -d '{"policy":{"paths":["/video/"],"ttl":"1h","placement":"path"},"mediaUrl":"https://<dist>.cloudfront.net/video/test.m3u8"}')
echo $RESULT | jq .
```

### Verify token validation

```bash
SIGNED_URL=$(echo $RESULT | jq -r .signedUrl)
curl -s -w "\nHTTP %{http_code}\n" "$SIGNED_URL" | head -5
```

### Verify revocation

```bash
# Generate token with session ID
# ... then revoke:
curl -s -X POST https://<api-endpoint>/prod/revoke \
  -H "Content-Type: application/json" \
  -d '{"tokenId":"test-session","reason":"test"}'

# Wait ~15 seconds, then retry the signed URL — should return 401
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `missing_token` | No token in path or header | Ensure URL has `/{TOKEN}/...` format |
| `Token verification failed` | HMAC mismatch | Check signing key is synced to KVS |
| `expired` | Token past expiration | Generate a new token |
| `ip_restricted` | Viewer IP doesn't match token | Check IPv4 vs IPv6 — CloudFront may see IPv6 |
| `token_revoked` | Session ID in revocation list | Generate a new token with a different session ID |
| `uri_not_allowed` | Request path doesn't match `catu` claim | Check path prefix in policy matches the content path |

## Updating

After code changes:

```bash
cd source
npx tsc                    # Compile TypeScript
npx cdk deploy --all -c enableDemo=true -c enableAutoRevocation=true
aws cloudfront create-invalidation --distribution-id <ID> --paths "/*"
```

## Cleanup

```bash
npx cdk destroy --all
```
