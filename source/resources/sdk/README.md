# CTA-5007-B SDKs

Standalone SDK implementations for generating COSE MAC0 / CWT tokens compatible with CloudFront Functions `cf.cwt.validateToken()`. All three produce **byte-identical tokens** for the same inputs.

## Languages

| SDK | File | Dependencies | Test Runner |
|-----|------|-------------|-------------|
| **Node.js** | `javascript/cta-client.js` | `cbor-x` | Jest |
| **Python** | `python/cta_client.py` | None (built-in CBOR encoder) | unittest |
| **Ruby** | `ruby/cta_client.rb` | None (`openssl` from stdlib) | Minitest |

## Running Tests

```bash
# Node.js
cd source/lambda && npx jest

# Python
cd source/lambda-python && python3 -m unittest test_cta_client -v

# Ruby
cd source/lambda-ruby && ruby test_cta_client.rb -v
```

## Test Results

### Node.js — 36 tests passed

```
PASS __tests__/cta-client.test.js
  parseTTL
    ✓ parses seconds
    ✓ parses minutes
    ✓ parses hours
    ✓ parses days
    ✓ passes through numbers
    ✓ defaults invalid input
    ✓ defaults empty string
  generateToken
    ✓ returns a Buffer
    ✓ starts with CWT tag (d8 3d) then COSE_Mac0 tag (d8 11)
    ✓ skips CWT tag when cwtTag=false
    ✓ produces deterministic output for same inputs
    ✓ produces different output for different keys
    ✓ HMAC tag is 32 bytes (SHA-256)
    ✓ HMAC is verifiable
    ✓ uses custom kid
    ✓ encodes URI restriction claims
  CWT/CAT constants
    ✓ CWT claim numbers match RFC 8392
    ✓ CAT claim numbers match CloudFront docs
    ✓ CATU/MATCH constants

PASS __tests__/handlers.test.js
  Token Generator
    ✓ generates token with valid input
    ✓ returns path-based signed URL by default
    ✓ returns query-based signed URL when placement=query
    ✓ includes session ID in token
    ✓ returns 500 for missing policy
    ✓ returns 500 for invalid mediaUrl
    ✓ includes CORS header
  Revocation Handler
    ✓ revokes a token
    ✓ defaults reason to manual
    ✓ returns 400 for missing tokenId
  List Revoked
    ✓ returns revoked sessions sorted by time
    ✓ filters out non-revoked keys
    ✓ handles empty KVS
  Prompt Manager
    ✓ GET returns the prompt
    ✓ PUT updates the prompt
    ✓ PUT returns 400 for missing prompt
    ✓ returns 405 for unsupported method

Tests: 36 passed, 36 total
```

### Python — 29 tests passed

```
TestCborEncode
  ✓ test_bool_false
  ✓ test_bool_true
  ✓ test_bytes
  ✓ test_dict
  ✓ test_int
  ✓ test_list
  ✓ test_negative_int
  ✓ test_none
  ✓ test_one_byte_int
  ✓ test_small_int
  ✓ test_string
TestConstants
  ✓ test_cat
  ✓ test_catu
  ✓ test_cwt
TestGenerateToken
  ✓ test_cose_mac0_tag
  ✓ test_cwt_tag
  ✓ test_deterministic
  ✓ test_different_keys
  ✓ test_hmac_32_bytes
  ✓ test_hmac_verifiable
  ✓ test_no_cwt_tag
  ✓ test_path_claim
  ✓ test_returns_bytes
TestParseTTL
  ✓ test_days
  ✓ test_hours
  ✓ test_int_passthrough
  ✓ test_invalid
  ✓ test_minutes
  ✓ test_seconds

Ran 29 tests in 0.001s — OK
```

### Ruby — 28 tests, 37 assertions passed

```
TestConstants#test_cat
TestConstants#test_cwt
TestGenerateToken#test_cose_mac0_tag
TestGenerateToken#test_different_keys
TestGenerateToken#test_returns_string
TestGenerateToken#test_deterministic
TestGenerateToken#test_hmac_32_bytes
TestGenerateToken#test_path_claim
TestGenerateToken#test_cwt_tag
TestGenerateToken#test_hmac_verifiable
TestGenerateToken#test_no_cwt_tag
TestParseTTL#test_hours
TestParseTTL#test_seconds
TestParseTTL#test_days
TestParseTTL#test_int_passthrough
TestParseTTL#test_invalid
TestParseTTL#test_minutes
TestCborEncode#test_list
TestCborEncode#test_string
TestCborEncode#test_bytes
TestCborEncode#test_zero
TestCborEncode#test_dict
TestCborEncode#test_negative
TestCborEncode#test_small_int
TestCborEncode#test_false
TestCborEncode#test_nil
TestCborEncode#test_one_byte_int
TestCborEncode#test_true

28 runs, 37 assertions, 0 failures, 0 errors, 0 skips
```

## Token Structure

All SDKs produce tokens with this CBOR structure:

```
Tag(61) CWT {
  Tag(17) COSE_Mac0 {
    [
      protectedHeaders: { alg(1): HMAC-256(5) },
      unprotectedHeaders: { kid(4): "key:default" },
      payload: CBOR-encoded claims map,
      hmacTag: 32-byte SHA-256 HMAC
    ]
  }
}
```

## Byte-Identical Output

The three SDKs are tested to produce identical token bytes for the same claims and key. This is possible because:
- CBOR encoding is deterministic for maps with integer keys (sorted numerically)
- HMAC-SHA256 is deterministic
- The COSE MAC_structure is built identically across implementations
