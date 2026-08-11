"""
CTA-5007-B Python SDK
Generates COSE MAC0 / CWT tokens compatible with cf.cwt.validateToken()
"""

import hmac
import hashlib
import struct
import time
import base64
from urllib.parse import urlparse


# COSE / CWT constants (matching CloudFront docs)
COSE_ALG = 1
COSE_KID = 4
HMAC_256 = 5

class CWT:
    ISS = 1; SUB = 2; AUD = 3; EXP = 4; NBF = 5; IAT = 6; CTI = 7

class CAT:
    CATU = 401; CATNIP = 402; CATM = 403; CATR = 404

class CATU:
    HOST = 1; PATH = 2; EXT = 3

class MATCH:
    PREFIX = 1; SUFFIX = 2; EXACT = 3


# --- Minimal CBOR encoder (produces identical bytes to cbor-x) ---

def _cbor_uint_head(major: int, value: int) -> bytes:
    """Encode a CBOR unsigned integer with the given major type."""
    major_bits = major << 5
    if value < 24:
        return bytes([major_bits | value])
    if value < 0x100:
        return bytes([major_bits | 24, value])
    if value < 0x10000:
        return struct.pack('>BH', major_bits | 25, value)
    if value < 0x100000000:
        return struct.pack('>BI', major_bits | 26, value)
    return struct.pack('>BQ', major_bits | 27, value)


def cbor_encode(value) -> bytes:
    """Encode a Python value to CBOR bytes."""
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        if value >= 0:
            return _cbor_uint_head(0, value)
        return _cbor_uint_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_uint_head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode('utf-8')
        return _cbor_uint_head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        parts = _cbor_uint_head(4, len(value))
        for item in value:
            parts += cbor_encode(item)
        return parts
    if isinstance(value, dict):
        parts = _cbor_uint_head(5, len(value))
        for k, v in value.items():
            parts += cbor_encode(k) + cbor_encode(v)
        return parts
    if value is None:
        return b'\xf6'
    raise TypeError(f'Cannot CBOR encode: {type(value)}')


def cbor_tag(tag_num: int, content: bytes) -> bytes:
    """Wrap raw CBOR bytes in a CBOR tag (always uses 2-byte form for consistency with cbor-x)."""
    if tag_num < 24:
        return bytes([0xd8, tag_num]) + content
    return _cbor_uint_head(6, tag_num) + content


# --- COSE MAC0 / CWT token generation ---

def generate_token(claims: dict, key: str, kid: str = 'key:default', cwt_tag: bool = True) -> bytes:
    """
    Generate a COSE MAC0 / CWT token buffer.

    Args:
        claims: dict with integer keys (CWT/CAT claim numbers)
        key: signing key string (used as-is for HMAC)
        kid: key identifier
        cwt_tag: whether to wrap in CWT tag (61)

    Returns:
        CBOR-encoded token bytes
    """
    protected_bytes = cbor_encode({COSE_ALG: HMAC_256})
    unprotected_map = {COSE_KID: kid.encode('utf-8')}
    payload_bytes = cbor_encode(claims)

    # MAC_structure = ["MAC0", protected, external_aad, payload]
    mac_structure = cbor_encode(["MAC0", protected_bytes, b'', payload_bytes])
    tag = hmac.new(key.encode('utf-8'), mac_structure, hashlib.sha256).digest()

    # COSE_Mac0 array
    arr = cbor_encode([protected_bytes, unprotected_map, payload_bytes, tag])

    # Tag(17) = COSE_Mac0
    cose_mac0 = cbor_tag(17, arr)

    if not cwt_tag:
        return cose_mac0
    # Tag(61) = CWT
    return cbor_tag(61, cose_mac0)


def parse_ttl(ttl) -> int:
    if isinstance(ttl, int):
        return ttl
    import re
    m = re.match(r'^(\d+)([smhd])$', str(ttl))
    if not m:
        return 7200
    v = int(m.group(1))
    return {'s': v, 'm': v * 60, 'h': v * 3600, 'd': v * 86400}[m.group(2)]


class CTAClient:
    def __init__(self, stack_name: str, region: str = 'us-east-1'):
        self.stack_name = stack_name
        self.region = region
        self.signing_key = None
        self._sm = None

    def init_secrets_manager(self, **kwargs):
        import boto3
        self._sm = boto3.client('secretsmanager', region_name=self.region, **kwargs)

    def get_signing_keys(self) -> str:
        if not self._sm:
            raise RuntimeError('Call init_secrets_manager() first')
        import json
        resp = self._sm.get_secret_value(SecretId=f'{self.stack_name}_CTAKey')
        self.signing_key = json.loads(resp['SecretString'])['signingKey']
        return self.signing_key

    def generate_cwt_token(self, policy: dict, viewer: dict = None) -> dict:
        if not self.signing_key:
            raise RuntimeError('Call get_signing_keys() first')

        now = int(time.time())
        exp = now + parse_ttl(policy.get('ttl', '2h'))

        claims = {
            CWT.ISS: 'cta-secure-media',
            CWT.EXP: exp,
            CWT.NBF: now,
            CWT.IAT: now,
        }
        if policy.get('sessionId'):
            claims[CWT.CTI] = policy['sessionId']
        if policy.get('paths'):
            prefixes = policy['paths'][0] if len(policy['paths']) == 1 else policy['paths']
            claims[CAT.CATU] = {CATU.PATH: {MATCH.PREFIX: prefixes}}
        if policy.get('countries'):
            claims[316] = policy["countries"]

        token_buf = generate_token(claims, self.signing_key)
        token = base64.urlsafe_b64encode(token_buf).rstrip(b'=').decode('ascii')
        return {'token': token, 'expiresAt': exp}

    def generate_signed_url(self, media_url: str, policy: dict, viewer: dict = None) -> dict:
        result = self.generate_cwt_token(policy, viewer)
        token = result['token']

        placement = policy.get('placement', 'path')
        if placement == 'query':
            sep = '&' if '?' in media_url else '?'
            return {**result, 'signedUrl': f'{media_url}{sep}CAT={token}'}
        if placement == 'header':
            return {**result, 'url': media_url, 'headers': {'CTA-Common-Access-Token': token}}

        parsed = urlparse(media_url)
        signed = f'{parsed.scheme}://{parsed.netloc}/{token}{parsed.path}'
        if parsed.query:
            signed += f'?{parsed.query}'
        return {**result, 'signedUrl': signed}
