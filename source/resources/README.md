# Demo Websites — CTA-5007-B Token Delivery Modes

This directory contains three demo websites that demonstrate different token delivery strategies for CTA-5007-B (Common Access Token) protected streaming content. All three use the same CloudFront Function validator and token generation API.

## Sites

| Directory | Mode | Initial Playback | Token Renewal |
|-----------|------|------------------|---------------|
| `demo-website/` | **Path** | Token in URL path | API → new path token swapped via `xhrSetup` |
| `demo-website-header/` | **Header-Only** | Token in `CTA-Common-Access-Token` header | API → new header value (no URL change) |
| `demo-website-hybrid/` | **Hybrid (Path → Header)** | Token in URL path (CMS-friendly) | API → switches to header delivery |

## Token Delivery Comparison

### Path Mode (`demo-website/`)

```
Initial:  GET /{TOKEN₁}/video/stream.m3u8
Renewal:  GET /{TOKEN₂}/video/stream.m3u8  (URL rewritten by player)
```

- **Pros**: CMS can generate a complete signed URL — player is "dumb"
- **Cons**: Renewal requires URL rewriting in the player's request interceptor
- **Best for**: Simple integrations where the CMS owns token generation

### Header-Only Mode (`demo-website-header/`)

```
Initial:  GET /video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₁>
Renewal:  GET /video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₂>
```

- **Pros**: Clean URLs, trivial renewal (just swap a variable), no URL mangling
- **Cons**: Player must configure request interceptor from the start; CMS cannot embed auth in a URL
- **Best for**: Web apps that manage their own token lifecycle

### Hybrid Mode (`demo-website-hybrid/`)

```
Initial:  GET /{TOKEN₁}/video/stream.m3u8                    (path — CMS provides signed URL)
Renewal:  GET /{TOKEN₁}/video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₂>  (header wins)
```

- **Pros**: CMS generates initial URL (no player changes needed for first load); renewal is clean header-swap
- **Cons**: Stale path token remains in URL (CloudFront Function strips it harmlessly)
- **Best for**: Production deployments where CMS generates initial playback URLs but the player handles renewal

## CloudFront Function Behavior

The CTA validator function (`cta_token_validator.js`) supports all three modes with a single code path:

1. **Check header** → `CTA-Common-Access-Token` (highest priority)
2. **Check query** → `?CAT=<token>`
3. **Check path** → first segment > 50 chars

After validation (regardless of which method was used), the function always strips any path token:

```javascript
// Always strip path token if present (supports hybrid mode)
var segments = request.uri.split('/');
if (segments[1] && segments[1].length > 50) {
    segments.splice(1, 1);
    request.uri = segments.join('/') || '/';
}
```

This ensures the origin always receives a clean path, whether the token was validated via header, query, or path.

## Token Renewal Flow

All three demos use the same renewal strategy:

1. **Schedule renewal** at 2/3 of the token's TTL
2. **Call `POST /token`** to get a fresh CWT token from the API
3. **Deliver the new token** on subsequent requests (method depends on the mode)

The `POST /token` API accepts a `placement` field:
- `"path"` → returns `{ token, signedUrl, expiresAt }`
- `"header"` → returns `{ token, url, headers: { "CTA-Common-Access-Token": token }, expiresAt }`
- `"query"` → returns `{ token, signedUrl (with ?CAT=), expiresAt }`

## Player Configuration

### HLS.js — Header injection

```javascript
const hls = new Hls({
    xhrSetup(xhr, url) {
        xhr.setRequestHeader('CTA-Common-Access-Token', currentToken);
    }
});
```

### DASH.js — Header injection

```javascript
dashPlayer.extend('RequestModifier', function () {
    return {
        modifyRequestURL: function (url) { return url; },
        modifyRequestHeader: function (request) {
            request.setRequestHeader('CTA-Common-Access-Token', currentToken);
            return request;
        }
    };
}, true);
```

### HLS.js — Path token swap (original demo)

```javascript
const hls = new Hls({
    xhrSetup(xhr, url) {
        const u = new URL(url);
        const parts = u.pathname.split('/');
        if (parts[1] && parts[1].length > 50) {
            parts[1] = currentToken; // Swap old token for new
        }
        xhr.open('GET', `${u.origin}${parts.join('/')}`, true);
    }
});
```

## Configuration

Each demo site loads a `config.js` file that should be generated at deploy time:

```javascript
window.CTA_CONFIG = {
    apiEndpoint: 'https://<distribution-id>.cloudfront.net/api',
    cdnDomain: 'https://<distribution-id>.cloudfront.net'
};
```

## CORS

The CloudFront Function handles CORS preflight for the `CTA-Common-Access-Token` header:

```javascript
if (request.method === 'OPTIONS') {
    return {
        statusCode: 204,
        headers: {
            'access-control-allow-origin': { value: '*' },
            'access-control-allow-methods': { value: 'GET, HEAD, OPTIONS' },
            'access-control-allow-headers': { value: 'CTA-Common-Access-Token' },
            'access-control-max-age': { value: '86400' }
        }
    };
}
```

This is required for header-only and hybrid modes because custom headers trigger a CORS preflight request from the browser.
