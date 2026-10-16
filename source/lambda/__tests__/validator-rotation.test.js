const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { validateToken } = require('../test-support/token-crypto');
const { generateToken } = require('../sdk/cta-client');


function load(keys) {
  const source = fs.readFileSync(path.join(__dirname, '../cta_token_validator.js'), 'utf8')
    .replace(/^import cf from 'cloudfront';/m, '');
  const context = vm.createContext({
    cf: {
      kvs: () => ({ get: async key => {
        if (!(key in keys)) throw new Error('KeyNotFound');
        return keys[key];
      } }),
      cwt: { validateToken },
    }, Buffer, Date,
  });
  vm.runInContext(source, context);
  return context.handler;
}

function token(key, claims = {}) {
  return generateToken(new Map(Object.entries({ 4: 2000, ...claims }).map(([k, v]) => [Number(k), v])), key).toString('base64url');
}
function request(value, placement = 'header') {
  return { request: {
    method: 'GET', uri: placement === 'path' ? `/${value}/video/live.m3u8` : '/video/live.m3u8',
    headers: placement === 'header' ? { 'cta-common-access-token': { value } } : {},
    querystring: placement === 'query' ? { CAT: { value } } : {},
  }, viewer: { ip: '127.0.0.1' } };
}

beforeEach(() => jest.spyOn(Date, 'now').mockReturnValue(1000 * 1000));
afterEach(() => jest.restoreAllMocks());

test.each(['header', 'query', 'path'])('current and overlapping previous signatures authenticate via %s', async placement => {
  const handler = load({ 'key:default': 'new', 'key:previous': JSON.stringify({ signingKey: 'old', expiresAt: 1500 }) });
  for (const key of ['new', 'old']) {
    const result = await handler(request(token(key), placement));
    expect(result.uri).toBe('/video/live.m3u8');
    expect(result.querystring).toEqual({});
  }
});

test('staged rotation keeps old mint tokens valid until promotion is confirmed', async () => {
  const handler = load({ 'key:default': 'new', 'key:previous': JSON.stringify({ signingKey: 'old', expiresAt: null }) });
  expect((await handler(request(token('old')))).uri).toBe('/video/live.m3u8');
});

test('previous key rejects at its deadline even before physical cleanup', async () => {
  const keys = { 'key:default': 'new', 'key:previous': JSON.stringify({ signingKey: 'old', expiresAt: 1000 }) };
  const handler = load(keys);
  expect((await handler(request(token('old')))).statusCode).toBe(401);
  expect((await handler(request(token('new')))).uri).toBe('/video/live.m3u8');
  delete keys['key:previous'];
  expect((await handler(request(token('old')))).statusCode).toBe(401);
});

test('overlap does not bypass original expiry, revocation, or URI policy', async () => {
  const handler = load({ 'key:default': 'new', 'key:previous': JSON.stringify({ signingKey: 'old', expiresAt: 1500 }), 'revoked:session': 'true' });
  expect((await handler(request(token('old', { 4: 999 })))).body).toBe('expired');
  expect((await handler(request(token('old', { 7: 'session' })))).body).toBe('token_revoked');
  const restricted = generateToken(new Map([[4, 2000], [401, new Map([[2, new Map([[1, '/other/']])]])]]), 'old').toString('base64url');
  expect((await handler(request(restricted))).body).toBe('uri_not_allowed');
});

test.each(['unrelated', ''])('unknown signing key is rejected: %s', key => {
  const handler = load({ 'key:default': 'new', 'key:previous': JSON.stringify({ signingKey: 'old', expiresAt: 1500 }) });
  return expect(handler(request(token(key)))).resolves.toMatchObject({ statusCode: 401 });
});
