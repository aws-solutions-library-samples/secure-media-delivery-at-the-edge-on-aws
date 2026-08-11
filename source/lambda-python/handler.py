"""
CTA-5007-B Token Generator Lambda — Python

This Lambda function generates CTA-5007-B compliant COSE MAC0 / CWT tokens
for securing video content delivered through Amazon CloudFront. It serves as
the reference implementation for the Python SDK.

Architecture
------------
    API Gateway (POST /token-python)
        → This Lambda
            → Reads HMAC signing key from AWS Secrets Manager (cached after first call)
            → Delegates token generation to the CTA Python SDK (cta_client.py)
            → Returns base64url-encoded CWT token + signed URL

SDK Usage
---------
The SDK's ``generate_token(claims, key)`` function handles all cryptographic operations:

    1. CBOR-encodes the claims dict using a built-in minimal CBOR encoder (zero external
       dependencies). Integer keys are encoded as CBOR unsigned/negative integers, strings
       as CBOR text strings, and bytes as CBOR byte strings.
    2. Builds the COSE MAC_structure per RFC 8152 §6.3:
       ``["MAC0", protectedHeaders, externalAad, payload]``
    3. Computes HMAC-SHA256 over the MAC_structure using Python's ``hmac`` module
    4. Assembles the COSE_Mac0 array:
       ``[protectedHeaders, unprotectedHeaders, payload, hmacTag]``
    5. Wraps in CBOR tags: Tag(17) for COSE_Mac0, Tag(61) for CWT

The resulting token is validated at the edge by CloudFront Functions' cf.cwt.validateToken().
The Python SDK produces byte-identical tokens to the Node.js SDK.

Claims
------
Standard CWT claims (RFC 8392):
    - CWT.ISS (1): Issuer — identifies this token generator
    - CWT.EXP (4): Expiration time — Unix timestamp
    - CWT.NBF (5): Not before — Unix timestamp
    - CWT.IAT (6): Issued at — Unix timestamp
    - CWT.CTI (7): CWT ID — session identifier for revocation support

CTA-5007-B claims (CloudFront-aligned claim numbers):
    - CAT.CATU (401): URI restrictions — nested dict with path prefix matching
      Structure: ``{CATU.PATH(2): {MATCH.PREFIX(1): "/path/"}}``

Token Placement
---------------
The signed URL embeds the token in the URL path by default::

    https://cdn.example.com/{TOKEN}/video/stream.m3u8

CloudFront Function strips the token segment before forwarding to origin.
Query parameter placement (``?CAT={TOKEN}``) is also supported.

Environment Variables
---------------------
    SECRET_NAME : str
        AWS Secrets Manager secret ID containing the HMAC signing key

Request Format (POST body)
--------------------------
::

    {
        "policy": {
            "paths": ["/video/"],     // URI prefix restrictions
            "ttl": "2h",              // Token lifetime (e.g. "30s", "5m", "2h", "1d")
            "placement": "path",      // "path" (default) or "query"
            "sessionId": "abc-123"    // Session ID for revocation tracking
        },
        "viewer": {},                 // Reserved for future viewer attributes
        "mediaUrl": "https://cdn.example.com/video/stream.m3u8"
    }

Response Format
---------------
::

    {
        "token": "2D3YEYRDoQEF...",           // Base64url-encoded CWT token
        "signedUrl": "https://cdn/TOKEN/...",  // Ready-to-use signed URL
        "expiresAt": 1776881062,               // Unix timestamp of expiration
        "sdk": "python"                        // SDK identifier
    }
"""

import json
import os
import time
import base64
from urllib.parse import urlparse

import boto3

from cta_client import generate_token, parse_ttl, CWT, CAT, CATU, MATCH

# Secrets Manager client — initialized once per Lambda container.
sm = boto3.client('secretsmanager')

# Signing key cache — persists across invocations in the same container,
# avoiding repeated Secrets Manager API calls.
cached_key = None


def get_signing_key():
    """
    Retrieve the HMAC signing key from AWS Secrets Manager.

    The key is a 32-byte hex string stored in a JSON secret under the
    ``signingKey`` field. It is cached in the module-level ``cached_key``
    variable after the first retrieval.
    """
    global cached_key
    if cached_key:
        return cached_key
    resp = sm.get_secret_value(SecretId=os.environ['SECRET_NAME'])
    cached_key = json.loads(resp['SecretString'])['signingKey']
    return cached_key


def handler(event, context):
    """
    Lambda handler for CTA token generation.

    Parses the API Gateway proxy event, builds CWT claims from the policy,
    delegates to the Python SDK for COSE MAC0 token generation, and returns
    the token with a signed URL.
    """
    headers = {'Access-Control-Allow-Origin': '*'}
    try:
        body = json.loads(event['body'])
        policy = body.get('policy')
        media_url = body.get('mediaUrl')
        if not policy or not media_url:
            raise ValueError('Missing required fields: policy, mediaUrl')
        if not media_url.startswith(('http://', 'https://')):
            raise ValueError('mediaUrl must be a valid HTTP(S) URL')
        key = get_signing_key()
        now = int(time.time())
        exp = now + parse_ttl(policy.get('ttl', '2h'))

        # Build CWT claims dict with integer keys per CWT/CAT specification.
        # The Python SDK's CBOR encoder handles int keys natively — no special
        # Map type needed (unlike the Node.js SDK which requires JavaScript Maps).
        claims = {
            CWT.ISS: 'cta-secure-media',
            CWT.EXP: exp,
            CWT.NBF: now,
            CWT.IAT: now,
        }

        # Session ID for revocation tracking — stored as a CBOR text string
        # so the CloudFront Function validator can match it against the KVS
        # revocation list using string comparison.
        if policy.get('sessionId'):
            claims[CWT.CTI] = policy['sessionId']

        # URI restriction: catu(401) → path(2) → prefix_match(1)
        if policy.get('paths'):
            claims[CAT.CATU] = {CATU.PATH: {MATCH.PREFIX: policy['paths'][0]}}

        # IP restriction: catnip(402) — array of allowed IPs
        if policy.get('ips'):
            ips = policy['ips'] if isinstance(policy['ips'], list) else [policy['ips']]
            claims[CAT.CATNIP] = ips

        # Generate the COSE MAC0 / CWT token via the SDK.
        # Returns raw bytes containing the CBOR-encoded token.
        token_buf = generate_token(claims, key)
        token = base64.urlsafe_b64encode(token_buf).rstrip(b'=').decode()

        # Build the signed URL with the token embedded in the path or query string.
        if policy.get('placement') == 'header':
            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps({
                    'token': token,
                    'url': media_url,
                    'headers': {'CTA-Common-Access-Token': token},
                    'expiresAt': exp,
                    'sdk': 'python'
                })
            }
        elif policy.get('placement') == 'query':
            sep = '&' if '?' in media_url else '?'
            signed_url = f'{media_url}{sep}CAT={token}'
        else:
            p = urlparse(media_url)
            signed_url = f'{p.scheme}://{p.netloc}/{token}{p.path}'
            if p.query:
                signed_url += f'?{p.query}'

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'token': token,
                'signedUrl': signed_url,
                'expiresAt': exp,
                'sdk': 'python'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': str(e)})
        }
