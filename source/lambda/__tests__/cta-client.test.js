const { generateToken, parseTTL, CWT, CAT, CATU, MATCH } = require('../sdk/cta-client');
const crypto = require('crypto');
const { Encoder } = require('cbor-x');

const enc = new Encoder({ mapsAsObjects: false, tagUint8Array: false });
const TEST_KEY = 'test-signing-key-for-unit-tests-1234';

describe('parseTTL', () => {
  test('parses seconds', () => expect(parseTTL('30s')).toBe(30));
  test('parses minutes', () => expect(parseTTL('5m')).toBe(300));
  test('parses hours', () => expect(parseTTL('2h')).toBe(7200));
  test('parses maximum minutes', () => expect(parseTTL('120m')).toBe(7200));
  test('passes through numbers', () => expect(parseTTL(3600)).toBe(3600));
  test.each(['bad', '', 0, -1, 1.5, NaN, Infinity, null, false, '0s', '2h1', '121m', '3h', '1d', '25h', '2d', 7201, 86400, 86401])('rejects invalid or unsupported TTL %p', ttl => {
    expect(() => parseTTL(ttl)).toThrow('TTL must be');
  });
  test('accepts the maximum numeric TTL', () => expect(parseTTL(7200)).toBe(7200));
});

describe('generateToken', () => {
  const claims = new Map([
    [CWT.ISS, 'test-issuer'],
    [CWT.EXP, 1700000000],
    [CWT.IAT, 1699999000],
  ]);

  test('returns a Buffer', () => {
    const token = generateToken(claims, TEST_KEY);
    expect(Buffer.isBuffer(token)).toBe(true);
  });

  test('starts with CWT tag (d8 3d) then COSE_Mac0 tag (d8 11)', () => {
    const token = generateToken(claims, TEST_KEY);
    expect(token[0]).toBe(0xd8);
    expect(token[1]).toBe(0x3d); // Tag(61) CWT
    expect(token[2]).toBe(0xd8);
    expect(token[3]).toBe(0x11); // Tag(17) COSE_Mac0
  });

  test('skips CWT tag when cwtTag=false', () => {
    const token = generateToken(claims, TEST_KEY, { cwtTag: false });
    expect(token[0]).toBe(0xd8);
    expect(token[1]).toBe(0x11); // Tag(17) directly
  });

  test('produces deterministic output for same inputs', () => {
    const t1 = generateToken(claims, TEST_KEY);
    const t2 = generateToken(claims, TEST_KEY);
    expect(t1.equals(t2)).toBe(true);
  });

  test('produces different output for different keys', () => {
    const t1 = generateToken(claims, TEST_KEY);
    const t2 = generateToken(claims, 'different-key');
    expect(t1.equals(t2)).toBe(false);
  });

  test('HMAC tag is 32 bytes (SHA-256)', () => {
    const token = generateToken(claims, TEST_KEY);
    // The last 32 bytes before the end of the CBOR array are the HMAC
    const hmacTag = token.slice(-32);
    expect(hmacTag.length).toBe(32);
  });

  test('HMAC is verifiable', () => {
    const token = generateToken(claims, TEST_KEY);
    // Reconstruct MAC_structure and verify
    const protectedBytes = Buffer.from(enc.encode(new Map([[1, 5]])));
    const payloadBytes = Buffer.from(enc.encode(claims));
    const macStructure = enc.encode(["MAC0", protectedBytes, Buffer.alloc(0), payloadBytes]);
    const expected = crypto.createHmac('sha256', TEST_KEY).update(macStructure).digest();
    const actual = token.slice(-32);
    expect(actual.equals(expected)).toBe(true);
  });

  test('uses custom kid', () => {
    const token = generateToken(claims, TEST_KEY, { kid: 'key:custom' });
    expect(token.includes(Buffer.from('key:custom'))).toBe(true);
  });

  test('encodes URI restriction claims', () => {
    const claimsWithPath = new Map([
      [CWT.ISS, 'test'],
      [CWT.EXP, 1700000000],
      [CAT.CATU, new Map([[CATU.PATH, new Map([[MATCH.PREFIX, '/video/']])]])],
    ]);
    const token = generateToken(claimsWithPath, TEST_KEY);
    expect(token.includes(Buffer.from('/video/'))).toBe(true);
  });
});

describe('CWT/CAT constants', () => {
  test('CWT claim numbers match RFC 8392', () => {
    expect(CWT.ISS).toBe(1);
    expect(CWT.EXP).toBe(4);
    expect(CWT.NBF).toBe(5);
    expect(CWT.IAT).toBe(6);
    expect(CWT.CTI).toBe(7);
  });

  test('CAT claim numbers match CloudFront docs', () => {
    expect(CAT.CATU).toBe(401);
    expect(CAT.CATNIP).toBe(402);
  });

  test('CATU/MATCH constants', () => {
    expect(CATU.PATH).toBe(2);
    expect(MATCH.PREFIX).toBe(1);
  });
});
