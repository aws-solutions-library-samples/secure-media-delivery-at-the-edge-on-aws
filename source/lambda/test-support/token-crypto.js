const crypto = require('crypto');
const { Encoder, Decoder } = require('cbor-x');
const encoder = new Encoder({ mapsAsObjects: false, tagUint8Array: false });
const decoder = new Decoder({ mapsAsObjects: false });

function claimsObject(value) {
  if (value instanceof Map) return Object.fromEntries(Array.from(value, ([key, item]) => [key, claimsObject(item)]));
  if (Array.isArray(value)) return value.map(claimsObject);
  return value;
}

// Verify the actual SDK-produced COSE_Mac0 bytes rather than a token stub.
function validateToken(token, { key }) {
  const bytes = Buffer.isBuffer(token) ? token : Buffer.from(token, 'base64url');
  if (!bytes.subarray(0, 4).equals(Buffer.from([0xd8, 0x3d, 0xd8, 0x11]))) throw new Error('bad_token');
  const [protectedBytes, , payloadBytes, tag] = decoder.decode(bytes.subarray(4));
  const mac = encoder.encode(['MAC0', protectedBytes, Buffer.alloc(0), payloadBytes]);
  const expected = crypto.createHmac('sha256', key).update(mac).digest();
  if (tag.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(tag), expected)) throw new Error('bad_signature');
  return { payload: claimsObject(decoder.decode(payloadBytes)) };
}

module.exports = { validateToken };
