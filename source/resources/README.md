# Demo Websites — CTA-5007-B Token Delivery Modes

The `demo-website/` directory contains three demo pages that demonstrate different token delivery strategies for CTA-5007-B (Common Access Token) protected streaming content. All three use the same CloudFront Function validator and token generation API, deployed to S3 and served at `/website/*` via CloudFront.

## Pages

| File | Mode | URL |
|------|------|-----|
| `index-path.html` | **Path** | `https://<dist>/website/index-path.html` |
| `index-header.html` | **Header-Only** | `https://<dist>/website/index-header.html` |
| `index-hybrid.html` | **Hybrid (Path → Header)** | `https://<dist>/website/index-hybrid.html` |

## Token Delivery Comparison

### Path Mode (`index-path.html`)

```
Initial:  GET /{TOKEN₁}/video/stream.m3u8
Renewal:  GET /{TOKEN₂}/video/stream.m3u8  (URL rewritten by player)
```

- **Pros**: CMS can generate a complete signed URL — player is "dumb"
- **Cons**: Renewal requires URL rewriting in the player's request interceptor
- **Best for**: Simple integrations where the CMS owns token generation

### Header-Only Mode (`index-header.html`)

```
Initial:  GET /video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₁>
Renewal:  GET /video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₂>
```

- **Pros**: Clean URLs, trivial renewal (just swap a variable), no URL mangling
- **Cons**: Player must configure request interceptor from the start; CMS cannot embed auth in a URL
- **Best for**: Web apps that manage their own token lifecycle

### Hybrid Mode (`index-hybrid.html`)

```
Initial:  GET /{TOKEN₁}/video/stream.m3u8                    (path — CMS provides signed URL)
Renewal:  GET /{TOKEN₁}/video/stream.m3u8  +  CTA-Common-Access-Token: <TOKEN₂>  (header wins)
```

- **Pros**: CMS generates initial URL (no player changes for first load); renewal is a clean header-swap
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

### HLS.js — Path token swap (path demo)

```javascript
const hls = new Hls({
    xhrSetup(xhr, url) {
        const u = new URL(url);
        const parts = u.pathname.split('/');
        if (parts[1] && parts[1].length > 50) {
            parts[1] = currentToken;
        }
        xhr.open('GET', `${u.origin}${parts.join('/')}`, true);
    }
});
```

## Configuration

Each demo page loads `config.js`, generated at deploy time by CDK:

```javascript
window.CTA_CONFIG = {
    apiEndpoint: 'https://<distribution>/api',
    cdnDomain: 'https://<distribution>'
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
