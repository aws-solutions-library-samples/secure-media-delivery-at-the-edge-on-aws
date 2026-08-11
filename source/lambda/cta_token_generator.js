/**
 * CTA-5007-B Token Generator Lambda — Node.js
 *
 * This Lambda function generates CTA-5007-B compliant COSE MAC0 / CWT tokens
 * for securing video content delivered through Amazon CloudFront. It serves as
 * the reference implementation for the Node.js SDK.
 *
 * ## Architecture
 *
 *   API Gateway (POST /token)
 *       → This Lambda
 *           → Reads HMAC signing key from AWS Secrets Manager (cached after first call)
 *           → Delegates token generation to the CTA Node.js SDK (./sdk/cta-client.js)
 *           → Returns base64url-encoded CWT token + signed URL
 *
 * ## SDK Usage
 *
 * The SDK's `generateToken(claims, key)` function handles all cryptographic operations:
 *   1. CBOR-encodes the claims map using cbor-x (with mapsAsObjects:false for spec-compliant maps)
 *   2. Builds the COSE MAC_structure per RFC 8152 §6.3: ["MAC0", protectedHeaders, externalAad, payload]
 *   3. Computes HMAC-SHA256 over the MAC_structure using the signing key
 *   4. Assembles the COSE_Mac0 array: [protectedHeaders, unprotectedHeaders, payload, hmacTag]
 *   5. Wraps in CBOR tags: Tag(17) for COSE_Mac0, Tag(61) for CWT
 *
 * The resulting token is validated at the edge by CloudFront Functions' cf.cwt.validateToken().
 *
 * ## Claims
 *
 * Standard CWT claims (RFC 8392):
 *   - CWT.ISS (1): Issuer — identifies this token generator
 *   - CWT.EXP (4): Expiration time — Unix timestamp
 *   - CWT.NBF (5): Not before — Unix timestamp
 *   - CWT.IAT (6): Issued at — Unix timestamp
 *   - CWT.CTI (7): CWT ID — session identifier for revocation support
 *
 * CTA-5007-B claims (CloudFront-aligned claim numbers):
 *   - CAT.CATU (401): URI restrictions — nested map with path prefix matching
 *     Structure: { CATU.PATH(2): { MATCH.PREFIX(1): "/path/" } }
 *
 * ## Token Placement
 *
 * The signed URL embeds the token in the URL path by default:
 *   https://cdn.example.com/{TOKEN}/video/stream.m3u8
 *
 * CloudFront Function strips the token segment before forwarding to origin.
 * Query parameter placement (?CAT={TOKEN}) is also supported.
 *
 * ## Environment Variables
 *   - SECRET_NAME: AWS Secrets Manager secret ID containing the HMAC signing key
 *
 * ## Request Format (POST body)
 *   {
 *     "policy": {
 *       "paths": ["/video/"],     // URI prefix restrictions
 *       "ttl": "2h",              // Token lifetime (e.g. "30s", "5m", "2h", "1d")
 *       "placement": "path",      // "path" (default) or "query"
 *       "sessionId": "abc-123"    // Session ID for revocation tracking
 *     },
 *     "viewer": {},               // Reserved for future viewer attributes
 *     "mediaUrl": "https://cdn.example.com/video/stream.m3u8"
 *   }
 *
 * ## Response Format
 *   {
 *     "token": "2D3YEYRDoQEF...",           // Base64url-encoded CWT token
 *     "signedUrl": "https://cdn/TOKEN/...",  // Ready-to-use signed URL
 *     "expiresAt": 1776881062                // Unix timestamp of expiration
 *   }
 */

const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const { generateToken, CWT, CAT, CATU, MATCH, parseTTL } = require('./sdk/cta-client');

const secretsManager = new SecretsManagerClient({});
let cachedKey = null;

/**
 * Retrieve the HMAC signing key from Secrets Manager.
 * The key is cached in the Lambda execution environment after the first call
 * to avoid repeated API calls across invocations in the same container.
 */
async function getSigningKey() {
    if (cachedKey) return cachedKey;
    const resp = await secretsManager.send(new GetSecretValueCommand({ SecretId: process.env.SECRET_NAME }));
    cachedKey = JSON.parse(resp.SecretString).signingKey;
    return cachedKey;
}

exports.handler = async (event) => {
    const headers = { 'Access-Control-Allow-Origin': '*' };
    try {
        const { policy, mediaUrl } = JSON.parse(event.body);
        if (!policy || !mediaUrl) throw new Error('Missing required fields: policy, mediaUrl');
        if (!/^https?:\/\//.test(mediaUrl)) throw new Error('mediaUrl must be a valid HTTP(S) URL');
        const signingKey = await getSigningKey();
        const now = Math.floor(Date.now() / 1000);
        const exp = now + parseTTL(policy.ttl || '2h');

        // Build CWT claims map with integer keys per CWT/CAT specification.
        // The SDK expects a JavaScript Map (not a plain object) to ensure
        // cbor-x encodes integer keys as CBOR integers, not text strings.
        const claims = new Map();
        claims.set(CWT.ISS, 'cta-secure-media');
        claims.set(CWT.EXP, exp);
        claims.set(CWT.NBF, now);
        claims.set(CWT.IAT, now);
        if (policy.sessionId) claims.set(CWT.CTI, policy.sessionId);
        if (policy.paths?.[0]) {
            // URI restriction: catu(401) → path(2) → prefix_match(1)
            claims.set(CAT.CATU, new Map([[CATU.PATH, new Map([[MATCH.PREFIX, policy.paths[0]]])]]));
        }
        if (policy.ips) {
            // IP restriction: catnip(402) — array of allowed IPs
            const ipList = Array.isArray(policy.ips) ? policy.ips : [policy.ips];
            claims.set(CAT.CATNIP, ipList);
        }

        // Generate the COSE MAC0 / CWT token via the SDK.
        // Returns a Buffer containing the CBOR-encoded token.
        const tokenBuf = generateToken(claims, signingKey);
        const token = tokenBuf.toString('base64url');

        // Build the signed URL with the token embedded in the path or query string.
        let signedUrl = mediaUrl;
        if (policy.placement === 'header') {
            return { statusCode: 200, headers, body: JSON.stringify({ token, url: mediaUrl, headers: { 'CTA-Common-Access-Token': token }, expiresAt: exp }) };
        } else if (policy.placement === 'query') {
            const sep = mediaUrl.includes('?') ? '&' : '?';
            signedUrl = `${mediaUrl}${sep}CAT=${token}`;
        } else {
            const url = new URL(mediaUrl);
            signedUrl = `${url.protocol}//${url.host}/${token}${url.pathname}${url.search}`;
        }

        return { statusCode: 200, headers, body: JSON.stringify({ token, signedUrl, expiresAt: exp }) };
    } catch (error) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    }
};
