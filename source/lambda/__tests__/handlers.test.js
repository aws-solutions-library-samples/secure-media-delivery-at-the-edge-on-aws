// Mock AWS SDK clients before requiring handlers
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: jest.fn(() => ({ send: mockSend })),
  GetSecretValueCommand: jest.fn(p => ({ _type: 'GetSecret', ...p })),
}));
jest.mock('@aws-sdk/client-cloudfront-keyvaluestore', () => ({
  CloudFrontKeyValueStoreClient: jest.fn(() => ({ send: mockSend })),
  PutKeyCommand: jest.fn(p => ({ _type: 'PutKey', ...p })),
  ListKeysCommand: jest.fn(p => ({ _type: 'ListKeys', ...p })),
  DeleteKeyCommand: jest.fn(p => ({ _type: 'DeleteKey', ...p })),
  DescribeKeyValueStoreCommand: jest.fn(p => ({ _type: 'Describe', ...p })),
}));
jest.mock('@aws-sdk/signature-v4a', () => ({}));
jest.mock('@aws-sdk/client-ssm', () => ({
  SSMClient: jest.fn(() => ({ send: mockSend })),
  GetParameterCommand: jest.fn(p => ({ _type: 'GetParam', ...p })),
  PutParameterCommand: jest.fn(p => ({ _type: 'PutParam', ...p })),
}));

beforeEach(() => {
  mockSend.mockReset();
  process.env.SECRET_NAME = 'test-secret';
  process.env.KVS_ARN = 'arn:aws:cloudfront::123:key-value-store/test';
  process.env.TTL_HOURS = '24';
  process.env.PROMPT_PARAM = '/test/prompt';
});

// --- Token Generator ---
describe('cta_token_generator', () => {
  const { handler } = require('../cta_token_generator');

  beforeEach(() => {
    mockSend.mockResolvedValue({ SecretString: JSON.stringify({ signingKey: 'test-key-abc123' }) });
  });

  test('generates token with valid input', async () => {
    const event = { body: JSON.stringify({ policy: { paths: ['/video/'], ttl: '1h' }, mediaUrl: 'https://cdn.example.com/video/test.m3u8' }) };
    const res = await handler(event);
    const body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.token).toBeDefined();
    expect(body.signedUrl).toContain(body.token);
    expect(body.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test('returns path-based signed URL by default', async () => {
    const event = { body: JSON.stringify({ policy: { paths: ['/video/'] }, mediaUrl: 'https://cdn.example.com/video/test.m3u8' }) };
    const res = await handler(event);
    const body = JSON.parse(res.body);
    expect(body.signedUrl).toMatch(/^https:\/\/cdn\.example\.com\/[A-Za-z0-9_-]+\/video\/test\.m3u8$/);
  });

  test('returns query-based signed URL when placement=query', async () => {
    const event = { body: JSON.stringify({ policy: { placement: 'query' }, mediaUrl: 'https://cdn.example.com/video/test.m3u8' }) };
    const res = await handler(event);
    const body = JSON.parse(res.body);
    expect(body.signedUrl).toContain('?CAT=');
  });

  test('includes session ID in token', async () => {
    const event = { body: JSON.stringify({ policy: { sessionId: 'sess-123' }, mediaUrl: 'https://cdn.example.com/v.m3u8' }) };
    const res = await handler(event);
    expect(res.statusCode).toBe(200);
  });

  test('returns 500 for missing policy', async () => {
    const event = { body: JSON.stringify({ mediaUrl: 'https://cdn.example.com/v.m3u8' }) };
    const res = await handler(event);
    expect(res.statusCode).toBe(500);
    expect(JSON.parse(res.body).error).toContain('Missing required');
  });

  test('returns 500 for invalid mediaUrl', async () => {
    const event = { body: JSON.stringify({ policy: {}, mediaUrl: 'not-a-url' }) };
    const res = await handler(event);
    expect(res.statusCode).toBe(500);
    expect(JSON.parse(res.body).error).toContain('valid HTTP');
  });

  test('includes CORS header', async () => {
    const event = { body: JSON.stringify({ policy: {}, mediaUrl: 'https://cdn.example.com/v.m3u8' }) };
    const res = await handler(event);
    expect(res.headers['Access-Control-Allow-Origin']).toBe('*');
  });
});

describe('CTA mint rotation boundaries', () => {
  const { validateToken } = require('../test-support/token-crypto');
  let handler;
  const event = ttl => ({ body: JSON.stringify({ policy: ttl === undefined ? {} : { ttl }, mediaUrl: 'https://cdn.example.com/video/live.m3u8' }) });
  beforeEach(() => {
    jest.resetModules();
    handler = require('../cta_token_generator').handler;
    jest.spyOn(Date, 'now').mockReturnValue(1700000000000);
  });
  afterEach(() => jest.restoreAllMocks());

  test('warm container switches to the promoted key at the 60-second boundary', async () => {
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'old-key' }) });
    const old = JSON.parse((await handler(event('1h'))).body);
    expect(validateToken(old.token, { key: 'old-key' }).payload[4]).toBe(1700003600);
    Date.now.mockReturnValue(1700000059999);
    const cached = JSON.parse((await handler(event('1h'))).body);
    expect(validateToken(cached.token, { key: 'old-key' }).payload[4]).toBe(1700003659);
    expect(mockSend).toHaveBeenCalledTimes(1);
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'new-key' }) });
    Date.now.mockReturnValue(1700000060000);
    const fresh = JSON.parse((await handler(event('1h'))).body);
    expect(validateToken(fresh.token, { key: 'new-key' }).payload[4]).toBe(1700003660);
    expect(() => validateToken(fresh.token, { key: 'old-key' })).toThrow('bad_signature');
    expect(mockSend).toHaveBeenCalledTimes(2);
    expect(mockSend.mock.calls[0][0].SecretId).toBe('test-secret');
  });

  test('fetch latency counts toward cache age', async () => {
    mockSend.mockImplementationOnce(async () => {
      Date.now.mockReturnValue(1700000050000);
      return { SecretString: JSON.stringify({ signingKey: 'old-key' }) };
    });
    await handler(event());
    Date.now.mockReturnValue(1700000060000);
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'new-key' }) });
    const fresh = JSON.parse((await handler(event())).body);
    validateToken(fresh.token, { key: 'new-key' });
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  test('failed refresh refuses to mint using an expired cached key and retries', async () => {
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'old-key' }) });
    await handler(event());
    Date.now.mockReturnValue(1700000060000);
    mockSend.mockRejectedValueOnce(new Error('unavailable'));
    expect((await handler(event())).statusCode).toBe(500);
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'new-key' }) });
    const fresh = JSON.parse((await handler(event())).body);
    validateToken(fresh.token, { key: 'new-key' });
    expect(mockSend).toHaveBeenCalledTimes(3);
  });

  test.each([0, -1, 1.5, null, false, '', 'bad', '0s', '2h1', '121m', '3h', '1d', '25h', 7201, 86400, 86401])('rejects unsupported TTL %p before fetching a key', async ttl => {
    const result = await handler(event(ttl));
    expect(result.statusCode).toBe(500);
    expect(JSON.parse(result.body).error).toContain('TTL must be');
    expect(mockSend).not.toHaveBeenCalled();
  });
  test.each([['1h', 3600], ['2h', 7200], ['120m', 7200], [7200, 7200], [undefined, 7200]])('accepts supported TTL %p', async (ttl, seconds) => {
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'key' }) });
    const result = await handler(event(ttl));
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).expiresAt).toBe(1700000000 + seconds);
  });
  test.each([['3600.0', 3600], ['1e3', 1000]])('accepts JSON numeric TTL %s', async (literal, seconds) => {
    mockSend.mockResolvedValueOnce({ SecretString: JSON.stringify({ signingKey: 'key' }) });
    const result = await handler({ body: `{"policy":{"ttl":${literal}},"mediaUrl":"https://cdn.example.com/video/live.m3u8"}` });
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).expiresAt).toBe(1700000000 + seconds);
  });
});

// --- Token Revocation ---
describe('cta_revocation', () => {
  const { handler } = require('../cta_revocation');

  beforeEach(() => {
    mockSend.mockResolvedValue({ ETag: 'etag-123' });
  });

  test('revokes a token', async () => {
    const event = { body: JSON.stringify({ tokenId: 'session-abc', reason: 'abuse' }) };
    const res = await handler(event);
    const body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.success).toBe(true);
    expect(body.tokenId).toBe('session-abc');
    expect(body.reason).toBe('abuse');
  });

  test('defaults reason to manual', async () => {
    const event = { body: JSON.stringify({ tokenId: 'session-abc' }) };
    const res = await handler(event);
    expect(JSON.parse(res.body).reason).toBe('manual');
  });

  test('returns 400 for missing tokenId', async () => {
    const event = { body: JSON.stringify({}) };
    const res = await handler(event);
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toContain('Missing tokenId');
  });
});

// --- List Revoked ---
describe('list_revoked', () => {
  const { handler } = require('../list_revoked');

  test('returns revoked sessions sorted by time', async () => {
    mockSend.mockResolvedValue({
      Items: [
        { Key: 'revoked:sess-1', Value: JSON.stringify({ reason: 'manual', revokedAt: 1000 }) },
        { Key: 'revoked:sess-2', Value: JSON.stringify({ reason: 'auto', revokedAt: 2000 }) },
        { Key: 'key:default', Value: 'signing-key' },
      ]
    });
    const res = await handler();
    const body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.count).toBe(2);
    expect(body.revoked[0].sessionId).toBe('sess-2'); // most recent first
    expect(body.revoked[1].sessionId).toBe('sess-1');
  });

  test('filters out non-revoked keys', async () => {
    mockSend.mockResolvedValue({ Items: [{ Key: 'key:default', Value: 'abc' }] });
    const res = await handler();
    expect(JSON.parse(res.body).count).toBe(0);
  });

  test('handles empty KVS', async () => {
    mockSend.mockResolvedValue({ Items: [] });
    const res = await handler();
    expect(JSON.parse(res.body).count).toBe(0);
  });
});

// --- Prompt Manager ---
describe('prompt_manager', () => {
  const { handler } = require('../prompt_manager');

  test('GET returns the prompt', async () => {
    mockSend.mockResolvedValue({ Parameter: { Value: 'Analyze sessions...' } });
    const res = await handler({ httpMethod: 'GET' });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).prompt).toBe('Analyze sessions...');
  });

  test('PUT updates the prompt', async () => {
    mockSend.mockResolvedValue({});
    const res = await handler({ httpMethod: 'PUT', body: JSON.stringify({ prompt: 'New prompt' }) });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).success).toBe(true);
  });

  test('PUT returns 400 for missing prompt', async () => {
    const res = await handler({ httpMethod: 'PUT', body: JSON.stringify({}) });
    expect(res.statusCode).toBe(400);
  });

  test('returns 405 for unsupported method', async () => {
    const res = await handler({ httpMethod: 'DELETE' });
    expect(res.statusCode).toBe(405);
  });
});
