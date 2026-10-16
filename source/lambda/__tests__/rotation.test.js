const mockSmSend = jest.fn();
const mockKvsSend = jest.fn();
const { createRequire } = require('module');
const runtimeRequire = createRequire(require.resolve('../sync_keys'));

function mockRuntimeModule(name, factory) {
  let resolved;
  try {
    resolved = runtimeRequire.resolve(name);
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') throw error;
    jest.doMock(name, factory, { virtual: true });
    return;
  }
  // sync_keys has its own node_modules; mock the SDK instance it actually loads.
  jest.doMock(resolved, factory);
}

mockRuntimeModule('@aws-sdk/signature-v4-crt', () => ({}));
mockRuntimeModule('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: jest.fn(() => ({ send: mockSmSend })),
  GetSecretValueCommand: jest.fn(input => ({ type: 'GetSecret', ...input })),
  PutSecretValueCommand: jest.fn(input => ({ type: 'PutSecret', ...input })),
  DescribeSecretCommand: jest.fn(input => ({ type: 'DescribeSecret', ...input })),
  UpdateSecretVersionStageCommand: jest.fn(input => ({ type: 'UpdateStage', ...input })),
}));
mockRuntimeModule('@aws-sdk/client-cloudfront-keyvaluestore', () => ({
  CloudFrontKeyValueStoreClient: jest.fn(() => ({ send: mockKvsSend })),
  DescribeKeyValueStoreCommand: jest.fn(input => ({ type: 'DescribeKvs', ...input })),
  GetKeyCommand: jest.fn(input => ({ type: 'GetKey', ...input })),
  UpdateKeysCommand: jest.fn(input => ({ type: 'UpdateKeys', ...input })),
}));

const crypto = require('crypto');
const { handler } = require('../sync_keys');
const OLD_KEY = '1'.repeat(64);
const ORIGINAL_VERSION = '0'.repeat(32);
const EXECUTION = 'execution-1';
let clock;
let keys;
let versions;
let revision;
let beforeKvs;
let afterKvs;
let beforeSm;
let afterSm;
let mutations;

function error(name) {
  return Object.assign(new Error(name), { name });
}

function state() {
  return JSON.parse(keys.get('key:rotation'));
}

function previous() {
  return JSON.parse(keys.get('key:previous'));
}

function mintVersion() {
  return [...versions.entries()].find(([, value]) => value.stages.includes('AWSCURRENT'));
}

function assertMintAccepted() {
  const signingKey = mintVersion()[1].value.signingKey;
  const retained = keys.has('key:previous') ? previous() : undefined;
  expect(keys.get('key:default') === signingKey || (retained?.signingKey === signingKey
    && (retained.expiresAt === null || clock < retained.expiresAt * 1000))).toBe(true);
}

function action(actionName, executionId = EXECUTION) {
  return handler({ action: actionName, executionId });
}

async function stage() {
  const output = await action('prepare');
  clock = output.propagationReadyAt * 1000;
  return output;
}

async function finalized() {
  await stage();
  await action('promote');
  return action('finalize');
}

function failKvsWrite(predicate, afterCommit = false) {
  const hook = async command => {
    if (command.type === 'UpdateKeys' && predicate(command)) {
      if (afterCommit) afterKvs = undefined;
      else beforeKvs = undefined;
      throw error('InjectedFailure');
    }
  };
  if (afterCommit) afterKvs = hook;
  else beforeKvs = hook;
}

beforeEach(() => {
  jest.restoreAllMocks();
  mockSmSend.mockReset();
  mockKvsSend.mockReset();
  clock = 1700000000000;
  jest.spyOn(Date, 'now').mockImplementation(() => clock);
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  process.env.SECRET_NAME = 'test-secret';
  process.env.KVS_ARN = 'arn:aws:cloudfront::123456789012:key-value-store/test';
  delete process.env.ROTATION_OVERLAP_SECONDS;
  delete process.env.ROTATION_PROPAGATION_SECONDS;
  delete process.env.ROTATION_IN_FLIGHT_SECONDS;
  keys = new Map([['key:default', OLD_KEY]]);
  versions = new Map([[ORIGINAL_VERSION, {
    value: { algorithm: 'HMAC-SHA256', signingKey: OLD_KEY, preserved: 'metadata' },
    stages: ['AWSCURRENT'],
  }]]);
  revision = 0;
  beforeKvs = afterKvs = beforeSm = afterSm = undefined;
  mutations = [];

  mockKvsSend.mockImplementation(async command => {
    if (beforeKvs) await beforeKvs(command);
    let output;
    if (command.type === 'DescribeKvs') output = { ETag: String(revision) };
    else if (command.type === 'GetKey') {
      if (!keys.has(command.Key)) throw error('ResourceNotFoundException');
      output = { Value: keys.get(command.Key) };
    } else if (command.type === 'UpdateKeys') {
      if (command.IfMatch !== String(revision)) throw error('ConflictException');
      const next = new Map(keys);
      for (const { Key, Value } of command.Puts || []) {
        if (Buffer.byteLength(Value) > 1024) throw error('ValidationException');
        next.set(Key, Value);
      }
      for (const { Key } of command.Deletes || []) {
        if (!next.has(Key)) throw error('ResourceNotFoundException');
        next.delete(Key);
      }
      keys = next;
      revision++;
      mutations.push('UpdateKeys');
      assertMintAccepted();
      output = { ETag: String(revision) };
    } else throw error('UnexpectedKvsCommand');
    if (afterKvs) await afterKvs(command);
    return output;
  });

  mockSmSend.mockImplementation(async command => {
    if (beforeSm) await beforeSm(command);
    let output;
    if (command.type === 'GetSecret') {
      const versionId = command.VersionId || mintVersion()[0];
      if (!versions.has(versionId)) throw error('ResourceNotFoundException');
      output = { VersionId: versionId, SecretString: JSON.stringify(versions.get(versionId).value) };
    } else if (command.type === 'DescribeSecret') {
      output = { VersionIdsToStages: Object.fromEntries(
        [...versions].map(([id, version]) => [id, [...version.stages]]),
      ) };
    } else if (command.type === 'PutSecret') {
      const value = JSON.parse(command.SecretString);
      const existing = versions.get(command.ClientRequestToken);
      if (existing && JSON.stringify(existing.value) !== JSON.stringify(value)) {
        throw error('ResourceExistsException');
      }
      if (!existing) {
        for (const version of versions.values()) {
          version.stages = version.stages.filter(label => !command.VersionStages.includes(label));
        }
        versions.set(command.ClientRequestToken, { value, stages: [...command.VersionStages] });
      }
      expect(command.VersionStages).toEqual(['AWSPENDING']);
      mutations.push('PutSecret');
      assertMintAccepted();
      output = { VersionId: command.ClientRequestToken };
    } else if (command.type === 'UpdateStage') {
      const old = versions.get(command.RemoveFromVersionId);
      if (!old?.stages.includes(command.VersionStage)) throw error('InvalidRequestException');
      old.stages = old.stages.filter(label => label !== command.VersionStage);
      if (command.VersionStage === 'AWSCURRENT' && command.MoveToVersionId) {
        for (const version of versions.values()) {
          version.stages = version.stages.filter(label => label !== 'AWSPREVIOUS');
        }
        old.stages.push('AWSPREVIOUS');
      }
      if (command.MoveToVersionId) versions.get(command.MoveToVersionId).stages.push(command.VersionStage);
      mutations.push('UpdateStage');
      assertMintAccepted();
      output = {};
    } else throw error('UnexpectedSmCommand');
    if (afterSm) await afterSm(command);
    return output;
  });
});

afterEach(() => jest.restoreAllMocks());

test('stages both edge keys atomically, waits, promotes, expires and physically removes previous', async () => {
  const prepared = await action('prepare');
  const nextKey = keys.get('key:default');
  expect(nextKey).not.toBe(OLD_KEY);
  expect(previous()).toEqual({ signingKey: OLD_KEY, expiresAt: null });
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
  expect(prepared).toEqual({
    executionId: EXECUTION,
    phase: 'staged',
    propagationReadyAt: 1700000300,
    propagationReadyTimestamp: '2023-11-14T22:18:20.000Z',
  });
  await expect(action('promote')).rejects.toMatchObject({ name: 'RotationPropagationPending' });
  expect(mutations).toEqual(['UpdateKeys', 'UpdateKeys']);
  clock = prepared.propagationReadyAt * 1000;
  const promoted = await action('promote');
  expect(previous().expiresAt).toBeNull();
  expect(mintVersion()[1].value).toEqual({ algorithm: 'HMAC-SHA256', signingKey: nextKey, preserved: 'metadata' });
  expect(versions.get(ORIGINAL_VERSION).stages).toEqual(['AWSPREVIOUS']);
  expect(mintVersion()[1].stages).toEqual(expect.arrayContaining(['AWSCURRENT', 'AWSPENDING']));
  expect(promoted.cleanupAt).toBe(prepared.propagationReadyAt + 7200 + 60 + 60);
  expect(promoted.cleanupTimestamp).toBe(new Date(promoted.cleanupAt * 1000).toISOString());
  const finished = await action('finalize');
  expect(previous().expiresAt).toBe(finished.cleanupAt);
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'RotationOverlapPending' });
  clock = finished.cleanupAt * 1000;
  expect((await action('cleanup')).phase).toBe('complete');
  expect(keys.has('key:previous')).toBe(false);
  expect(state()).toEqual({ executionId: EXECUTION, phase: 'complete',
    propagationReadyAt: prepared.propagationReadyAt, cleanupAt: finished.cleanupAt });
  expect(versions.get(mintVersion()[0]).stages).not.toContain('AWSPENDING');
  expect(versions.get(ORIGINAL_VERSION).stages).toEqual(['AWSPREVIOUS']);
  expect(mutations.slice(0, 5)).toEqual(['UpdateKeys', 'UpdateKeys', 'UpdateKeys', 'PutSecret', 'UpdateStage']);
});

test('starts the entire propagation wait after a slow edge-stage response', async () => {
  afterKvs = command => {
    if (command.type === 'UpdateKeys' && command.Puts.some(put => put.Key === 'key:default')) {
      clock += 180000;
      afterKvs = undefined;
    }
  };
  const prepared = await action('prepare');
  expect(prepared.propagationReadyAt * 1000 - clock).toBe(300000);
});

test('fractional-second boundaries cannot shorten propagation or overlap waits', async () => {
  clock += 999;
  const prepared = await action('prepare');
  clock = prepared.propagationReadyAt * 1000 - 1;
  await expect(action('promote')).rejects.toMatchObject({ name: 'RotationPropagationPending' });
  clock++;
  await action('promote');
  const finished = await action('finalize');
  clock = finished.cleanupAt * 1000 - 1;
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'RotationOverlapPending' });
});

test('prepare retries reuse persisted keys and do not move the propagation deadline', async () => {
  const prepared = await action('prepare');
  const saved = JSON.stringify(state());
  clock += 60000;
  expect(await action('prepare')).toEqual(prepared);
  expect(JSON.stringify(state())).toBe(saved);
  expect(mockSmSend.mock.calls.filter(([command]) => command.type === 'PutSecret')).toHaveLength(0);
});

test('lost staging response resumes the durable keys without generating another key', async () => {
  const random = jest.spyOn(crypto, 'randomBytes');
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:default'), true);
  await expect(action('prepare')).rejects.toMatchObject({ name: 'InjectedFailure' });
  const retained = state();
  expect(retained.phase).toBe('preparing');
  expect(previous().expiresAt).toBeNull();
  clock += 60000;
  const retried = await action('prepare');
  expect(retried.propagationReadyAt).toBe(1700000360);
  expect(state().nextSigningKey).toBe(retained.nextSigningKey);
  expect(random).toHaveBeenCalledTimes(1);
});

test('failed staging metadata confirmation resumes without changing the staged key', async () => {
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:rotation'
    && JSON.parse(put.Value).phase === 'staged'));
  await expect(action('prepare')).rejects.toMatchObject({ name: 'InjectedFailure' });
  const stagedKey = keys.get('key:default');
  expect(state().phase).toBe('preparing');
  clock += 300000;
  expect((await action('prepare')).propagationReadyAt).toBe(1700000600);
  expect(keys.get('key:default')).toBe(stagedKey);
});

test('failure before atomic edge staging cannot promote or expose a partially retained key', async () => {
  failKvsWrite(() => true);
  await expect(action('prepare')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(keys.has('key:rotation')).toBe(false);
  expect(keys.has('key:previous')).toBe(false);
  expect(keys.get('key:default')).toBe(OLD_KEY);
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
});

test('different simultaneous rotations have exactly one owner', async () => {
  const outcomes = await Promise.allSettled([action('prepare', 'owner-a'), action('prepare', 'owner-b')]);
  expect(outcomes.filter(outcome => outcome.status === 'fulfilled')).toHaveLength(1);
  expect(outcomes.find(outcome => outcome.status === 'rejected').reason.name).toBe('RotationInProgress');
  expect(['owner-a', 'owner-b']).toContain(state().executionId);
  expect(previous().signingKey).toBe(OLD_KEY);
});

test('simultaneous retries of the same execution converge on the same persisted keys and deadline', async () => {
  const outputs = await Promise.all([action('prepare'), action('prepare')]);
  expect(outputs[0]).toEqual(outputs[1]);
  expect(previous().signingKey).toBe(OLD_KEY);
});

test('failure persisting promotion intent cannot change the mint secret', async () => {
  await stage();
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:rotation'
    && JSON.parse(put.Value).phase === 'promoting'));
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(state().phase).toBe('staged');
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
  expect(previous().expiresAt).toBeNull();
  expect(mockSmSend.mock.calls.filter(([command]) => command.type === 'PutSecret')).toHaveLength(0);
  expect((await action('promote')).phase).toBe('promoted');
});

test('a failed secret write keeps old mint key accepted indefinitely, and retry uses the same version', async () => {
  await stage();
  beforeSm = command => {
    if (command.type === 'PutSecret') {
      beforeSm = undefined;
      throw error('InjectedFailure');
    }
  };
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  const saved = state();
  expect(saved.phase).toBe('promoting');
  expect(saved.proposedCleanupAt).toBeDefined();
  expect(previous().expiresAt).toBeNull();
  clock += 172800000;
  assertMintAccepted();
  await action('promote');
  expect(state().nextSigningKey).toBe(saved.nextSigningKey);
  expect(state().nextVersionId).toBe(saved.nextVersionId);
  expect(state().cleanupAt).toBe(clock / 1000 + saved.overlapSeconds + 60 + saved.inFlightSeconds);
});

test('failure after writing pending secret does not switch mint and retries the same deterministic version', async () => {
  await stage();
  afterSm = command => {
    if (command.type === 'PutSecret') {
      afterSm = undefined;
      throw error('InjectedFailure');
    }
  };
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
  const versionId = state().nextVersionId;
  await action('promote');
  expect(mintVersion()[0]).toBe(versionId);
  expect(versions.size).toBe(2);
});

test('failure before moving AWSCURRENT keeps expiresAt null until retry confirms promotion', async () => {
  await stage();
  beforeSm = command => {
    if (command.type === 'UpdateStage' && command.VersionStage === 'AWSCURRENT') {
      beforeSm = undefined;
      throw error('InjectedFailure');
    }
  };
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
  expect(previous().expiresAt).toBeNull();
  await action('promote');
  expect(mintVersion()[0]).toBe(state().nextVersionId);
});

test('lost AWSCURRENT response is confirmed without switching back or generating another version', async () => {
  await stage();
  afterSm = command => {
    if (command.type === 'UpdateStage' && command.VersionStage === 'AWSCURRENT') {
      afterSm = undefined;
      throw error('InjectedFailure');
    }
  };
  expect((await action('promote')).phase).toBe('promoted');
  expect(versions.size).toBe(2);
  expect(previous().expiresAt).toBeNull();
});

test('failure persisting confirmed promotion leaves no edge expiry and uses later confirmation on retry', async () => {
  await stage();
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:rotation'
    && JSON.parse(put.Value).phase === 'promoted'));
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(state().phase).toBe('promoting');
  expect(mintVersion()[0]).toBe(state().nextVersionId);
  expect(previous().expiresAt).toBeNull();
  clock += 3600000;
  const promoted = await action('promote');
  expect(promoted.cleanupAt).toBe(clock / 1000 + state().overlapSeconds + 60 + state().inFlightSeconds);
  const secretWrites = mockSmSend.mock.calls.filter(([command]) => command.type === 'PutSecret');
  expect(secretWrites).toHaveLength(1);
});

test('lost confirmed-promotion response and later retries cannot extend the persisted deadline', async () => {
  await stage();
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:rotation'
    && JSON.parse(put.Value).phase === 'promoted'), true);
  await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
  const saved = state();
  clock += 60000;
  expect((await action('promote')).cleanupAt).toBe(saved.cleanupAt);
  expect(state()).toEqual(saved);
});

test('same-execution simultaneous promotions converge without changing the current secret', async () => {
  await stage();
  const outputs = await Promise.all([action('promote'), action('promote')]);
  expect(outputs[0]).toEqual(outputs[1]);
  expect(versions.size).toBe(2);
  expect(mintVersion()[0]).toBe(state().nextVersionId);
});

test('finalization failures/retries retain the confirmed immutable deadline', async () => {
  await stage();
  const promoted = await action('promote');
  failKvsWrite(command => command.Puts.some(put => put.Key === 'key:previous'));
  await expect(action('finalize')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(previous().expiresAt).toBeNull();
  clock += 60000;
  expect((await action('finalize')).cleanupAt).toBe(promoted.cleanupAt);
  expect(previous().expiresAt).toBe(promoted.cleanupAt);
  const saved = JSON.stringify(state());
  clock += 60000;
  await action('finalize');
  expect(JSON.stringify(state())).toBe(saved);
});

test('cleanup failure before atomic deletion retains ownership and the physical previous key', async () => {
  const finished = await finalized();
  clock = finished.cleanupAt * 1000;
  failKvsWrite(command => command.Deletes?.some(item => item.Key === 'key:previous'));
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(state().phase).toBe('finalized');
  expect(keys.has('key:previous')).toBe(true);
  expect((await action('cleanup')).phase).toBe('complete');
  expect(keys.has('key:previous')).toBe(false);
});

test('failure removing the pending label cannot release ownership or delete a retained key', async () => {
  const finished = await finalized();
  clock = finished.cleanupAt * 1000;
  beforeSm = command => {
    if (command.type === 'UpdateStage' && command.VersionStage === 'AWSPENDING') {
      beforeSm = undefined;
      throw error('InjectedFailure');
    }
  };
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(state().phase).toBe('finalized');
  expect(keys.has('key:previous')).toBe(true);
  expect((await action('cleanup')).phase).toBe('complete');
});

test('lost cleanup response is harmless, and old execution retries cannot touch a later rotation', async () => {
  const finished = await finalized();
  clock = finished.cleanupAt * 1000;
  failKvsWrite(command => command.Deletes?.some(item => item.Key === 'key:previous'), true);
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'InjectedFailure' });
  expect(keys.has('key:previous')).toBe(false);
  expect((await action('cleanup')).phase).toBe('complete');
  await action('prepare', 'execution-2');
  const newState = JSON.stringify(state());
  const newPrevious = keys.get('key:previous');
  for (const name of ['prepare', 'promote', 'finalize', 'cleanup']) {
    expect((await action(name)).phase).toBe('complete');
  }
  expect(JSON.stringify(state())).toBe(newState);
  expect(keys.get('key:previous')).toBe(newPrevious);
});

test('foreign execution actions cannot promote, finalize or delete another owner retained key', async () => {
  await stage();
  for (const name of ['promote', 'finalize', 'cleanup']) {
    await expect(action(name, 'foreign')).rejects.toMatchObject({ name: 'RotationOwnershipConflict' });
  }
  expect(previous().expiresAt).toBeNull();
});

test('a stale cleanup CAS cannot delete the next execution previous key', async () => {
  const finished = await finalized();
  clock = finished.cleanupAt * 1000;
  let release;
  let reached;
  const paused = new Promise(resolve => { reached = resolve; });
  const resume = new Promise(resolve => { release = resolve; });
  beforeKvs = async command => {
    if (command.type === 'UpdateKeys' && command.Deletes?.length) {
      beforeKvs = undefined;
      reached();
      await resume;
    }
  };
  const stale = action('cleanup');
  await paused;
  await action('cleanup');
  await action('prepare', 'execution-2');
  const saved = keys.get('key:previous');
  release();
  expect((await stale).phase).toBe('complete');
  expect(keys.get('key:previous')).toBe(saved);
  expect(state().executionId).toBe('execution-2');
});

test('a stale promotion cannot move AWSCURRENT back after a later rotation has promoted', async () => {
  await stage();
  let release;
  let reached;
  const paused = new Promise(resolve => { reached = resolve; });
  const resume = new Promise(resolve => { release = resolve; });
  beforeSm = async command => {
    if (command.type === 'UpdateStage' && command.VersionStage === 'AWSCURRENT') {
      beforeSm = undefined;
      reached();
      await resume;
    }
  };
  const stale = action('promote');
  // Attach a rejection handler immediately while the other execution proceeds.
  const staleOutcome = stale.then(value => ({ value }), reason => ({ reason }));
  await paused;
  await action('promote');
  const first = await action('finalize');
  clock = first.cleanupAt * 1000;
  await action('cleanup');
  const second = await action('prepare', 'execution-2');
  clock = second.propagationReadyAt * 1000;
  await action('promote', 'execution-2');
  const saved = mintVersion()[0];
  release();
  expect((await staleOutcome).reason.name).toBe('InvalidRequestException');
  expect(mintVersion()[0]).toBe(saved);
  expect(state().executionId).toBe('execution-2');
});

test.each(['preparing', 'staged', 'promoting', 'promoted', 'finalized'])('initial sync never overwrites an active %s rotation', async phase => {
  if (phase === 'preparing') {
    failKvsWrite(command => command.Puts.some(put => put.Key === 'key:rotation'
      && JSON.parse(put.Value).phase === 'staged'));
    await expect(action('prepare')).rejects.toMatchObject({ name: 'InjectedFailure' });
  } else {
    await stage();
    if (phase === 'promoting') {
      beforeSm = command => {
        if (command.type === 'PutSecret') throw error('InjectedFailure');
      };
      await expect(action('promote')).rejects.toMatchObject({ name: 'InjectedFailure' });
      beforeSm = undefined;
    } else if (phase === 'promoted' || phase === 'finalized') {
      await action('promote');
      if (phase === 'finalized') await action('finalize');
    }
  }
  const saved = [...keys];
  expect((await handler({ RequestType: 'Update', PhysicalResourceId: 'existing-sync' })).Status).toBe('SUCCESS');
  expect([...keys]).toEqual(saved);
});

test('initial sync creates the current edge key atomically and delete is a no-op', async () => {
  keys.clear();
  expect(await handler({ RequestType: 'Create' })).toEqual({ PhysicalResourceId: 'key-sync', Status: 'SUCCESS' });
  expect(keys.get('key:default')).toBe(OLD_KEY);
  const calls = mockKvsSend.mock.calls.length;
  await handler({ RequestType: 'Delete', PhysicalResourceId: 'existing-sync' });
  expect(mockKvsSend.mock.calls).toHaveLength(calls);
});

test.each(['a'.repeat(64), 'A'.repeat(64), 'G7'.repeat(32), 'G7'.repeat(16)])('initial sync deletes raw legacy previous %s without changing the agreeing current key', async legacyPrevious => {
  keys.set('key:previous', legacyPrevious);
  expect((await handler({ RequestType: 'Update' })).Status).toBe('SUCCESS');
  expect([...keys]).toEqual([['key:default', OLD_KEY]]);
  const writes = mockKvsSend.mock.calls.map(([command]) => command).filter(command => command.type === 'UpdateKeys');
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    IfMatch: '0',
    Puts: [{ Key: 'key:default', Value: OLD_KEY }],
    Deletes: [{ Key: 'key:previous' }],
  });
});

test.each(['a'.repeat(64), 'A'.repeat(64), 'G7'.repeat(32), 'G7'.repeat(16)])('prepare atomically replaces raw legacy previous %s while staging and owning both keys', async legacyPrevious => {
  keys.set('key:previous', legacyPrevious);
  const prepared = await action('prepare');
  expect(prepared.phase).toBe('staged');
  expect(previous()).toEqual({ signingKey: OLD_KEY, expiresAt: null });
  expect(state().executionId).toBe(EXECUTION);
  const firstWrite = mockKvsSend.mock.calls.map(([command]) => command).find(command => command.type === 'UpdateKeys');
  expect(firstWrite.IfMatch).toBe('0');
  expect(firstWrite.Puts.map(put => put.Key)).toEqual(['key:rotation', 'key:default', 'key:previous']);
  expect(firstWrite.Deletes).toBeUndefined();
  expect(mintVersion()[1].value.signingKey).toBe(OLD_KEY);
});

test.each(['initialize', 'prepare'])('%s legacy migration fails closed when nonempty edge and mint current keys differ', async operation => {
  keys.set('key:default', 'outdated-edge-key');
  keys.set('key:previous', 'G7'.repeat(32));
  const saved = [...keys];
  const pending = operation === 'initialize' ? handler({ RequestType: 'Update' }) : action('prepare');
  await expect(pending).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  expect([...keys]).toEqual(saved);
  expect(mutations).toEqual([]);
});

test.each([
  JSON.stringify({ signingKey: OLD_KEY, expiresAt: null }),
  JSON.stringify({ signingKey: OLD_KEY, expiresAt: 1700007200 }),
  JSON.stringify({ signingKey: OLD_KEY, expiresAt: 0 }),
  'unknown-previous', '', 'with_underscore', 'with whitespace', JSON.stringify(OLD_KEY), '{}',
  '["unrecognized"]', '{malformed',
])('never migrates structured or unrecognized previous value %s', async retained => {
  keys.set('key:previous', retained);
  const saved = [...keys];
  await expect(handler({ RequestType: 'Update' })).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  await expect(action('prepare')).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  expect([...keys]).toEqual(saved);
  expect(mutations).toEqual([]);
});

test.each(['staged', 'complete'])('raw previous never bypasses existing %s ownership', async phase => {
  keys.set('key:rotation', JSON.stringify({ executionId: 'original-owner', phase }));
  keys.set('key:previous', 'a'.repeat(64));
  const saved = [...keys];
  if (phase === 'staged') {
    expect((await handler({ RequestType: 'Update' })).Status).toBe('SUCCESS');
    await expect(action('prepare')).rejects.toMatchObject({ name: 'RotationInProgress' });
  } else {
    await expect(handler({ RequestType: 'Update' })).rejects.toMatchObject({ name: 'RotationKeyConflict' });
    await expect(action('prepare')).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  }
  expect([...keys]).toEqual(saved);
  expect(mutations).toEqual([]);
});

test.each(['initialize', 'prepare'])('%s legacy migration cannot overwrite a concurrently retained structured key', async operation => {
  keys.set('key:previous', 'a'.repeat(64));
  const retained = JSON.stringify({ signingKey: OLD_KEY, expiresAt: null });
  beforeKvs = command => {
    if (command.type === 'UpdateKeys') {
      beforeKvs = undefined;
      keys.set('key:previous', retained);
      revision++;
    }
  };
  const pending = operation === 'initialize' ? handler({ RequestType: 'Update' }) : action('prepare');
  await expect(pending).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  expect(keys.get('key:default')).toBe(OLD_KEY);
  expect(keys.get('key:previous')).toBe(retained);
  expect(keys.has('key:rotation')).toBe(false);
  expect(mutations).toEqual([]);
});

test.each([
  ['ROTATION_OVERLAP_SECONDS', 31449180],
  ['ROTATION_PROPAGATION_SECONDS', 31442280],
  ['ROTATION_IN_FLIGHT_SECONDS', 31442040],
])('accepts exact 364-day total with %s=%s', async (name, value) => {
  process.env[name] = String(value);
  const startedAt = clock / 1000;
  await stage();
  const promoted = await action('promote');
  expect(promoted.cleanupAt - startedAt).toBe(31449600);
  const finished = await action('finalize');
  clock = finished.cleanupAt * 1000;
  expect((await action('cleanup')).phase).toBe('complete');
});

test.each([
  ['ROTATION_OVERLAP_SECONDS', 31449181],
  ['ROTATION_PROPAGATION_SECONDS', 31442281],
  ['ROTATION_IN_FLIGHT_SECONDS', 31442041],
])('rejects 364-day total plus one second with %s=%s before any mutation', async (name, value) => {
  process.env[name] = String(value);
  await expect(action('prepare')).rejects.toMatchObject({ name: 'InvalidRotationConfiguration' });
  expect([...keys]).toEqual([['key:default', OLD_KEY]]);
  expect(mutations).toEqual([]);
  expect(mockSmSend).not.toHaveBeenCalled();
});

test.each([
  ['ROTATION_OVERLAP_SECONDS', '7199'],
  ['ROTATION_PROPAGATION_SECONDS', '299'],
  ['ROTATION_IN_FLIGHT_SECONDS', '0'],
  ['ROTATION_OVERLAP_SECONDS', 'NaN'],
  ['ROTATION_OVERLAP_SECONDS', '7200.5'],
  ['ROTATION_PROPAGATION_SECONDS', '300.5'],
  ['ROTATION_IN_FLIGHT_SECONDS', '1.5'],
  ['ROTATION_OVERLAP_SECONDS', 'Infinity'],
  ['ROTATION_PROPAGATION_SECONDS', '9007199254740992'],
  ['ROTATION_IN_FLIGHT_SECONDS', 'true'],
])('rejects unsafe %s=%s before any staging', async (name, value) => {
  process.env[name] = value;
  await expect(action('prepare')).rejects.toMatchObject({ name: 'InvalidRotationConfiguration' });
  expect(keys.has('key:rotation')).toBe(false);
  expect(mutations).toEqual([]);
});

test('captures configured overlap and margin once, unaffected by later environment changes', async () => {
  process.env.ROTATION_OVERLAP_SECONDS = '172800';
  process.env.ROTATION_PROPAGATION_SECONDS = '600';
  process.env.ROTATION_IN_FLIGHT_SECONDS = '120';
  const prepared = await stage();
  expect(prepared.propagationReadyAt).toBe(1700000600);
  process.env.ROTATION_OVERLAP_SECONDS = '7200';
  process.env.ROTATION_IN_FLIGHT_SECONDS = '1';
  const promoted = await action('promote');
  expect(promoted.cleanupAt).toBe(prepared.propagationReadyAt + 172800 + 60 + 120);
});

test('full-length execution IDs and secret version IDs fit the KVS 1024-byte value limit', async () => {
  const executionId = 'x'.repeat(256);
  const original = versions.get(ORIGINAL_VERSION);
  versions.clear();
  versions.set('0'.repeat(64), original);
  const prepared = await action('prepare', executionId);
  clock = prepared.propagationReadyAt * 1000;
  await action('promote', executionId);
  const finished = await action('finalize', executionId);
  expect(Buffer.byteLength(keys.get('key:rotation'))).toBeLessThanOrEqual(1024);
  expect(state().executionId).toBe(executionId);
  clock = finished.cleanupAt * 1000;
  expect((await action('cleanup', executionId)).executionId).toBe(executionId);
  expect(state().executionId).toBe(executionId);
});

test.each(['é'.repeat(256), '界'.repeat(256), '\u0000'.repeat(256)])('rejects execution IDs whose UTF-8 or JSON bytes exceed the all-phase state limit', async executionId => {
  expect(executionId).toHaveLength(256);
  await expect(action('prepare', executionId)).rejects.toMatchObject({ name: 'RotationStateTooLarge' });
  expect([...keys]).toEqual([['key:default', OLD_KEY]]);
  expect(mutations).toEqual([]);
  expect(mockSmSend.mock.calls.every(([command]) => command.type === 'GetSecret')).toBe(true);
});

test('rejects long signing keys before staging even when the preparation state alone fits', async () => {
  const executionId = 'x'.repeat(256);
  const signingKey = 'k'.repeat(300);
  const original = versions.get(ORIGINAL_VERSION);
  original.value.signingKey = signingKey;
  versions.clear();
  versions.set('0'.repeat(64), original);
  keys.set('key:default', signingKey);
  const preparing = {
    executionId, phase: 'preparing', previousSigningKey: signingKey, nextSigningKey: 'a'.repeat(64),
    previousVersionId: '0'.repeat(64), nextVersionId: 'b'.repeat(64),
    propagationSeconds: 300, overlapSeconds: 7200, inFlightSeconds: 60,
  };
  expect(Buffer.byteLength(JSON.stringify(preparing), 'utf8')).toBeLessThanOrEqual(1024);
  await expect(action('prepare', executionId)).rejects.toMatchObject({ name: 'RotationStateTooLarge' });
  expect([...keys]).toEqual([['key:default', signingKey]]);
  expect(mutations).toEqual([]);
  expect(mintVersion()[0]).toBe('0'.repeat(64));
  expect(mockSmSend.mock.calls.every(([command]) => command.type === 'GetSecret')).toBe(true);
});

test('a later promotion moves AWSPREVIOUS automatically without changing edge cleanup semantics', async () => {
  const first = await finalized();
  const firstVersion = mintVersion()[0];
  clock = first.cleanupAt * 1000;
  await action('cleanup');
  const prepared = await action('prepare', 'execution-2');
  clock = prepared.propagationReadyAt * 1000;
  await action('promote', 'execution-2');
  expect(versions.get(ORIGINAL_VERSION).stages).not.toContain('AWSPREVIOUS');
  expect(versions.get(firstVersion).stages).toEqual(['AWSPREVIOUS']);
  expect(mintVersion()[1].stages).toEqual(expect.arrayContaining(['AWSCURRENT', 'AWSPENDING']));
  expect(previous()).toEqual({ signingKey: versions.get(firstVersion).value.signingKey, expiresAt: null });
  const finished = await action('finalize', 'execution-2');
  clock = finished.cleanupAt * 1000;
  await action('cleanup', 'execution-2');
  expect(keys.has('key:previous')).toBe(false);
  expect(versions.get(firstVersion).stages).toEqual(['AWSPREVIOUS']);
  expect(mintVersion()[1].stages).toEqual(['AWSCURRENT']);
});

test('fails closed when edge keys or current secret disagree with rotation ownership', async () => {
  await stage();
  const saved = keys.get('key:previous');
  keys.set('key:previous', JSON.stringify({ signingKey: 'unexpected', expiresAt: null }));
  await expect(action('promote')).rejects.toMatchObject({ name: 'RotationKeyConflict' });
  keys.set('key:previous', saved);
  const external = 'f'.repeat(32);
  versions.get(ORIGINAL_VERSION).stages = [];
  versions.set(external, { value: { signingKey: state().nextSigningKey }, stages: ['AWSCURRENT'] });
  await expect(action('promote')).rejects.toMatchObject({ name: 'RotationSecretConflict' });
  expect(previous().expiresAt).toBeNull();
});

test('cleanup refuses deletion if the mint current version is no longer confirmed', async () => {
  const finished = await finalized();
  clock = finished.cleanupAt * 1000;
  versions.get(mintVersion()[0]).stages = [];
  versions.get(ORIGINAL_VERSION).stages = ['AWSCURRENT'];
  await expect(action('cleanup')).rejects.toMatchObject({ name: 'RotationSecretConflict' });
  expect(keys.has('key:previous')).toBe(true);
});

test('rejects the obsolete rotate flag and malformed actions without logging inputs or keys', async () => {
  for (const event of [{ rotate: true }, { action: 'prepare' }, { action: 'unknown', executionId: EXECUTION }]) {
    await expect(handler(event)).rejects.toMatchObject({ name: 'InvalidRotationInput' });
  }
  await finalized();
  expect(console.log).not.toHaveBeenCalled();
  expect(console.error).not.toHaveBeenCalled();
  const output = JSON.stringify(await action('prepare'));
  expect(output).not.toContain(OLD_KEY);
  expect(output).not.toContain(state().nextSigningKey);
});
