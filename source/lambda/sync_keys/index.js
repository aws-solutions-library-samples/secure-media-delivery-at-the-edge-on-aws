/**
 * Initial signing-key sync and retry-safe, CAS-owned signing-key rotation.
 * Rotation inputs/outputs deliberately contain no signing-key material.
 */
require("@aws-sdk/signature-v4-crt");

const {
    SecretsManagerClient,
    GetSecretValueCommand,
    PutSecretValueCommand,
    DescribeSecretCommand,
    UpdateSecretVersionStageCommand,
} = require("@aws-sdk/client-secrets-manager");
const {
    CloudFrontKeyValueStoreClient,
    DescribeKeyValueStoreCommand,
    GetKeyCommand,
    UpdateKeysCommand,
} = require("@aws-sdk/client-cloudfront-keyvaluestore");
const crypto = require("crypto");

const sm = new SecretsManagerClient({});
const kvs = new CloudFrontKeyValueStoreClient({});
const STATE_KEY = "key:rotation";
const MAX_CAS_ATTEMPTS = 8;
const CACHE_SECONDS = 60;
const MAX_ROTATION_SECONDS = 31449600; // 364 days; reserve one day for tasks and retries.
const MAX_VALUE_BYTES = 1024;
const now = () => Math.ceil(Date.now() / 1000);

function failure(name, message) {
    const error = new Error(message);
    error.name = name;
    return error;
}

function seconds(name, fallback, minimum) {
    const value = process.env[name] === undefined ? fallback : Number(process.env[name]);
    if (!Number.isSafeInteger(value) || value < minimum) {
        throw failure("InvalidRotationConfiguration", `${name} must be an integer of at least ${minimum}`);
    }
    return value;
}

function executionToken(executionId) {
    return crypto.createHash("sha256").update(executionId).digest("hex");
}

function completedKey(executionId) {
    return `rotation:completed:${executionToken(executionId)}`;
}

async function readKey(kvsArn, key) {
    try {
        const response = await kvs.send(new GetKeyCommand({ KvsARN: kvsArn, Key: key }));
        return response.Value;
    } catch (error) {
        if (error.name === "ResourceNotFoundException") return undefined;
        throw error;
    }
}

async function snapshot(kvsArn, executionId) {
    // The ETag precedes every read; any intervening mutation invalidates our CAS.
    const { ETag } = await kvs.send(new DescribeKeyValueStoreCommand({ KvsARN: kvsArn }));
    const [state, current, previous, completed] = await Promise.all([
        readKey(kvsArn, STATE_KEY),
        readKey(kvsArn, "key:default"),
        readKey(kvsArn, "key:previous"),
        executionId ? readKey(kvsArn, completedKey(executionId)) : undefined,
    ]);
    return {
        etag: ETag,
        state: state === undefined ? undefined : JSON.parse(state),
        current,
        previous,
        completed: completed === undefined ? undefined : JSON.parse(completed),
    };
}

async function update(kvsArn, view, puts, deletes = []) {
    await kvs.send(new UpdateKeysCommand({
        KvsARN: kvsArn,
        IfMatch: view.etag,
        Puts: Object.entries(puts).map(([Key, Value]) => ({ Key, Value })),
        ...(deletes.length ? { Deletes: deletes.map(Key => ({ Key })) } : {}),
    }));
}

async function getSecret(secretId, versionId) {
    const response = await sm.send(new GetSecretValueCommand({
        SecretId: secretId,
        ...(versionId ? { VersionId: versionId } : { VersionStage: "AWSCURRENT" }),
    }));
    const value = JSON.parse(response.SecretString);
    if (typeof value.signingKey !== "string" || !value.signingKey || !response.VersionId) {
        throw failure("InvalidSigningSecret", "Signing secret must contain a signingKey and a version ID");
    }
    return { value, versionId: response.VersionId };
}

function result(state, executionId) {
    return {
        executionId,
        phase: state.phase,
        propagationReadyAt: state.propagationReadyAt,
        propagationReadyTimestamp: new Date(state.propagationReadyAt * 1000).toISOString(),
        ...(state.cleanupAt === undefined ? {} : {
            cleanupAt: state.cleanupAt,
            cleanupTimestamp: new Date(state.cleanupAt * 1000).toISOString(),
        }),
    };
}

function owned(view, executionId) {
    if (!view.state || view.state.executionId !== executionId) {
        throw failure("RotationOwnershipConflict", "This execution does not own the active rotation");
    }
    return view.state;
}

function requireStagedKeys(view, state, expiresAt) {
    const expectedPrevious = JSON.stringify({ signingKey: state.previousSigningKey, expiresAt });
    if (view.current !== state.nextSigningKey || view.previous !== expectedPrevious) {
        throw failure("RotationKeyConflict", "Edge signing keys do not match the active rotation");
    }
}

function isLegacyPrevious(view) {
    // Legacy keys are raw hex rotation output or configurable-length
    // Terraform random_password output (special=false). Never migrate a
    // previous value while any rotation-state record exists.
    return view.state === undefined && typeof view.previous === "string"
        && /^[A-Za-z0-9]+$/.test(view.previous);
}

function requireStateCapacity(state) {
    // Later phases retain every preparation field and add these timestamps.
    // Reserve the widest safe-integer timestamps, not merely today's width,
    // so delayed recovery cannot outgrow a value that was safe when staged.
    const maximumState = {
        ...state,
        phase: "finalized",
        propagationReadyAt: Number.MAX_SAFE_INTEGER,
        proposedCleanupAt: Number.MAX_SAFE_INTEGER,
        promotionConfirmedAt: Number.MAX_SAFE_INTEGER,
        cleanupAt: Number.MAX_SAFE_INTEGER,
    };
    const maximumPrevious = { signingKey: state.previousSigningKey, expiresAt: Number.MAX_SAFE_INTEGER };
    if ([maximumState, maximumPrevious].some(value => Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_VALUE_BYTES)) {
        throw failure("RotationStateTooLarge", "Rotation state and retained key must fit the 1024-byte KVS value limit in every phase");
    }
}

async function initialize(secretName, kvsArn, event) {
    const response = {
        PhysicalResourceId: event.PhysicalResourceId || "key-sync",
        Status: "SUCCESS",
    };
    if (event.RequestType === "Delete") return response;
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const view = await snapshot(kvsArn);
        // Never let a deploy reset staged/promoted edge keys or their ownership.
        if (view.state && view.state.phase !== "complete") return response;
        const secret = await getSecret(secretName);
        const legacyPrevious = isLegacyPrevious(view);
        if (legacyPrevious && view.current && view.current !== secret.value.signingKey) {
            throw failure("RotationKeyConflict", "Legacy migration requires matching current mint and edge signing keys");
        }
        if (view.previous !== undefined && !legacyPrevious) {
            throw failure("RotationKeyConflict", "Initial sync cannot overwrite a retained previous key");
        }
        if (view.current === secret.value.signingKey && !legacyPrevious) return response;
        try {
            await update(kvsArn, view, { "key:default": secret.value.signingKey }, legacyPrevious ? ["key:previous"] : []);
            return response;
        } catch (error) {
            if (error.name !== "ConflictException") throw error;
        }
    }
    throw failure("RotationContention", "Initial sync exceeded its CAS retry limit");
}

async function prepare(secretName, kvsArn, view, executionId) {
    if (view.state && view.state.phase !== "complete") {
        if (view.state.executionId !== executionId) {
            throw failure("RotationInProgress", "Another execution owns the active rotation");
        }
        if (view.state.phase === "preparing") return confirmPrepared(kvsArn, executionId);
        return result(view.state, executionId);
    }
    if (view.previous !== undefined && !isLegacyPrevious(view)) {
        throw failure("RotationKeyConflict", "A previous signing key is still retained");
    }
    const overlapSeconds = seconds("ROTATION_OVERLAP_SECONDS", 7200, 7200);
    const propagationSeconds = seconds("ROTATION_PROPAGATION_SECONDS", 300, 300);
    const inFlightSeconds = seconds("ROTATION_IN_FLIGHT_SECONDS", 60, 1);
    if (propagationSeconds + overlapSeconds + CACHE_SECONDS + inFlightSeconds > MAX_ROTATION_SECONDS) {
        throw failure("InvalidRotationConfiguration", "Propagation, overlap, cache and in-flight durations must total at most 31449600 seconds (364 days)");
    }
    const secret = await getSecret(secretName);
    if (view.current !== secret.value.signingKey) {
        throw failure("RotationKeyConflict", "Current mint and edge signing keys differ");
    }
    const state = {
        executionId,
        phase: "preparing",
        previousSigningKey: secret.value.signingKey,
        nextSigningKey: crypto.randomBytes(32).toString("hex"),
        previousVersionId: secret.versionId,
        nextVersionId: executionToken(executionId),
        propagationSeconds,
        overlapSeconds,
        inFlightSeconds,
    };
    requireStateCapacity(state);
    // A single atomic write retains the mint's old key before exposing the new one.
    await update(kvsArn, view, {
        [STATE_KEY]: JSON.stringify(state),
        "key:default": state.nextSigningKey,
        "key:previous": JSON.stringify({ signingKey: state.previousSigningKey, expiresAt: null }),
    });
    return confirmPrepared(kvsArn, executionId);
}

async function confirmPrepared(kvsArn, executionId) {
    const view = await snapshot(kvsArn, executionId);
    if (view.completed) return result(view.completed, executionId);
    const state = owned(view, executionId);
    if (state.phase !== "preparing") return result(state, executionId);
    requireStagedKeys(view, state, null);
    // Start the full propagation wait only after the edge write is confirmed.
    const staged = { ...state, phase: "staged", propagationReadyAt: now() + state.propagationSeconds };
    await update(kvsArn, view, { [STATE_KEY]: JSON.stringify(staged) });
    return result(staged, executionId);
}

async function promote(secretName, kvsArn, view, executionId) {
    const state = owned(view, executionId);
    if (["promoted", "finalized", "complete"].includes(state.phase)) return result(state, executionId);
    if (!["staged", "promoting"].includes(state.phase)) {
        throw failure("InvalidRotationPhase", "Rotation has not been staged");
    }
    if (Date.now() < state.propagationReadyAt * 1000) {
        throw failure("RotationPropagationPending", "Edge propagation wait has not elapsed");
    }
    requireStagedKeys(view, state, null);
    if (state.phase === "staged") {
        // Persist a conservative proposed deadline before any mint-side changes.
        // The edge deadline stays null until AWSCURRENT promotion is confirmed.
        const promoting = {
            ...state,
            phase: "promoting",
            proposedCleanupAt: now() + state.overlapSeconds + CACHE_SECONDS + state.inFlightSeconds,
        };
        await update(kvsArn, view, { [STATE_KEY]: JSON.stringify(promoting) });
        return promoteConfirmed(secretName, kvsArn, executionId);
    }
    return promoteConfirmed(secretName, kvsArn, executionId);
}

async function promoteConfirmed(secretName, kvsArn, executionId) {
    // Re-read after acquiring durable promotion ownership, not a stale local state.
    const view = await snapshot(kvsArn, executionId);
    if (view.completed) return result(view.completed, executionId);
    const state = owned(view, executionId);
    if (["promoted", "finalized", "complete"].includes(state.phase)) return result(state, executionId);
    if (state.phase !== "promoting") throw failure("InvalidRotationPhase", "Promotion has not started");
    requireStagedKeys(view, state, null);
    const metadata = await sm.send(new DescribeSecretCommand({ SecretId: secretName }));
    const currentVersionId = Object.entries(metadata.VersionIdsToStages || {})
        .find(([, stages]) => stages.includes("AWSCURRENT"))?.[0];
    if (currentVersionId !== state.nextVersionId) {
        if (currentVersionId !== state.previousVersionId) {
            throw failure("RotationSecretConflict", "Current secret version is not owned by this rotation");
        }
        const previous = await getSecret(secretName, state.previousVersionId);
        if (previous.value.signingKey !== state.previousSigningKey) {
            throw failure("RotationSecretConflict", "Retained secret version does not match rotation state");
        }
        await sm.send(new PutSecretValueCommand({
            SecretId: secretName,
            ClientRequestToken: state.nextVersionId,
            VersionStages: ["AWSPENDING"],
            SecretString: JSON.stringify({ ...previous.value, signingKey: state.nextSigningKey }),
        }));
        // The old version is a compare-and-swap guard against stale executions.
        // If a duplicate call already promoted this version, confirm and continue.
        try {
            await sm.send(new UpdateSecretVersionStageCommand({
                SecretId: secretName,
                VersionStage: "AWSCURRENT",
                MoveToVersionId: state.nextVersionId,
                RemoveFromVersionId: state.previousVersionId,
            }));
        } catch (error) {
            const current = await sm.send(new DescribeSecretCommand({ SecretId: secretName }));
            if (!current.VersionIdsToStages?.[state.nextVersionId]?.includes("AWSCURRENT")) throw error;
        }
    }
    const current = await getSecret(secretName);
    if (current.versionId !== state.nextVersionId || current.value.signingKey !== state.nextSigningKey) {
        throw failure("RotationSecretConflict", "Mint promotion could not be confirmed");
    }
    const confirmedAt = now();
    const promoted = {
        ...state,
        phase: "promoted",
        promotionConfirmedAt: confirmedAt,
        cleanupAt: Math.max(state.proposedCleanupAt,
            confirmedAt + state.overlapSeconds + CACHE_SECONDS + state.inFlightSeconds),
    };
    // A failed write here leaves expiresAt:null; retry confirms promotion again
    // and conservatively starts the overlap from its later confirmation time.
    await update(kvsArn, view, { [STATE_KEY]: JSON.stringify(promoted) });
    return result(promoted, executionId);
}

async function finalize(kvsArn, view, executionId) {
    const state = owned(view, executionId);
    if (["finalized", "complete"].includes(state.phase)) return result(state, executionId);
    if (state.phase !== "promoted") {
        throw failure("InvalidRotationPhase", "Mint promotion must be confirmed before finalization");
    }
    requireStagedKeys(view, state, null);
    const finalized = { ...state, phase: "finalized" };
    await update(kvsArn, view, {
        [STATE_KEY]: JSON.stringify(finalized),
        "key:previous": JSON.stringify({ signingKey: state.previousSigningKey, expiresAt: state.cleanupAt }),
    });
    return result(finalized, executionId);
}

async function cleanup(secretName, kvsArn, view, executionId) {
    const state = owned(view, executionId);
    if (state.phase === "complete") return result(state, executionId);
    if (state.phase !== "finalized") {
        throw failure("InvalidRotationPhase", "Rotation must be finalized before cleanup");
    }
    if (Date.now() < state.cleanupAt * 1000) {
        throw failure("RotationOverlapPending", "Previous signing-key overlap has not elapsed");
    }
    requireStagedKeys(view, state, state.cleanupAt);
    const current = await getSecret(secretName);
    if (current.versionId !== state.nextVersionId || current.value.signingKey !== state.nextSigningKey) {
        throw failure("RotationSecretConflict", "Cannot remove a key while the mint secret is unconfirmed");
    }
    // Remove our staging label before releasing ownership. Repeating this is safe.
    const metadata = await sm.send(new DescribeSecretCommand({ SecretId: secretName }));
    if (metadata.VersionIdsToStages?.[state.nextVersionId]?.includes("AWSPENDING")) {
        await sm.send(new UpdateSecretVersionStageCommand({
            SecretId: secretName,
            VersionStage: "AWSPENDING",
            RemoveFromVersionId: state.nextVersionId,
        }));
    }
    const complete = {
        executionId,
        phase: "complete",
        propagationReadyAt: state.propagationReadyAt,
        cleanupAt: state.cleanupAt,
    };
    // The tombstone makes even very old execution retries inert after later rotations.
    await update(kvsArn, view, {
        [STATE_KEY]: JSON.stringify(complete),
        [completedKey(executionId)]: JSON.stringify(complete),
    }, ["key:previous"]);
    return result(complete, executionId);
}

exports.handler = async (event) => {
    const secretName = process.env.SECRET_NAME;
    const kvsArn = process.env.KVS_ARN;
    if (event?.RequestType) return initialize(secretName, kvsArn, event);
    if (!event || !["prepare", "promote", "finalize", "cleanup"].includes(event.action)
        || typeof event.executionId !== "string" || !event.executionId || event.executionId.length > 256) {
        throw failure("InvalidRotationInput", "An action and stable executionId (up to 256 characters) are required");
    }
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
        const view = await snapshot(kvsArn, event.executionId);
        if (view.completed) return result(view.completed, event.executionId);
        try {
            if (event.action === "prepare") return await prepare(secretName, kvsArn, view, event.executionId);
            if (event.action === "promote") return await promote(secretName, kvsArn, view, event.executionId);
            if (event.action === "finalize") return await finalize(kvsArn, view, event.executionId);
            return await cleanup(secretName, kvsArn, view, event.executionId);
        } catch (error) {
            if (error.name !== "ConflictException") throw error;
        }
    }
    throw failure("RotationContention", "Rotation exceeded its CAS retry limit");
};
