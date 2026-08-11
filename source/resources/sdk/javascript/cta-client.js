/**
 * CTA-5007-B Node SDK
 * Generates COSE MAC0 / CWT tokens compatible with cf.cwt.validateToken()
 */

const crypto = require('crypto');
const { Encoder } = require('cbor-x');

const enc = new Encoder({ mapsAsObjects: false, tagUint8Array: false });

// COSE / CWT constants (matching CloudFront docs)
const COSE_ALG = 1;
const COSE_KID = 4;
const HMAC_256 = 5;

const CWT = { ISS: 1, SUB: 2, AUD: 3, EXP: 4, NBF: 5, IAT: 6, CTI: 7 };
const CAT = { CATU: 401, CATNIP: 402, CATM: 403, CATR: 404 };
const CATU = { HOST: 1, PATH: 2, EXT: 3 };
const MATCH = { PREFIX: 1, SUFFIX: 2, EXACT: 3 };

/**
 * Generate a COSE MAC0 / CWT token buffer.
 * @param {Map} claims - CWT claims map with integer keys
 * @param {string} key - Signing key (used as-is for HMAC)
 * @param {object} [opts] - Options: { kid, cwtTag }
 * @returns {Buffer} CBOR-encoded token
 */
function generateToken(claims, key, opts = {}) {
    const kid = opts.kid || 'key:default';

    const protectedBytes = Buffer.from(enc.encode(new Map([[COSE_ALG, HMAC_256]])));
    const unprotectedMap = new Map([[COSE_KID, Buffer.from(kid)]]);
    const payloadBytes = Buffer.from(enc.encode(claims));

    const macStructure = enc.encode(["MAC0", protectedBytes, Buffer.alloc(0), payloadBytes]);
    const tag = crypto.createHmac('sha256', key).update(macStructure).digest();

    const arr = enc.encode([protectedBytes, unprotectedMap, payloadBytes, tag]);
    // Tag(17) = COSE_Mac0, Tag(61) = CWT
    const coseMac0 = Buffer.concat([Buffer.from([0xd8, 0x11]), arr]);
    if (opts.cwtTag === false) return coseMac0;
    return Buffer.concat([Buffer.from([0xd8, 0x3d]), coseMac0]);
}

function parseTTL(ttl) {
    if (typeof ttl === 'number') return ttl;
    const m = String(ttl).match(/^(\d+)([smhd])$/);
    if (!m) return 7200;
    const v = parseInt(m[1]);
    return { s: v, m: v * 60, h: v * 3600, d: v * 86400 }[m[2]] || 7200;
}

class CTAClient {
    constructor(stackName, region = 'us-east-1') {
        this.stackName = stackName;
        this.region = region;
        this.signingKey = null;
    }

    async initSecretsManager(credentials = {}) {
        const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
        this._sm = new SecretsManagerClient({ region: this.region, ...credentials });
        this._Cmd = GetSecretValueCommand;
    }

    async getSigningKeys() {
        if (!this._sm) throw new Error('Call initSecretsManager() first');
        const resp = await this._sm.send(new this._Cmd({ SecretId: `${this.stackName}_CTAKey` }));
        this.signingKey = JSON.parse(resp.SecretString).signingKey;
        return this.signingKey;
    }

    generateCWTToken(policy, viewer = {}) {
        if (!this.signingKey) throw new Error('Call getSigningKeys() first');
        const now = Math.floor(Date.now() / 1000);
        const exp = now + parseTTL(policy.ttl || '2h');

        const claims = new Map();
        claims.set(CWT.ISS, 'cta-secure-media');
        claims.set(CWT.EXP, exp);
        claims.set(CWT.NBF, now);
        claims.set(CWT.IAT, now);
        if (policy.sessionId) claims.set(CWT.CTI, policy.sessionId);
        if (policy.paths?.length) {
            const prefixes = policy.paths.length === 1 ? policy.paths[0] : policy.paths;
            claims.set(CAT.CATU, new Map([[CATU.PATH, new Map([[MATCH.PREFIX, prefixes]])]]));
        }
        if (policy.countries?.length) claims.set(316, policy.countries);

        const tokenBuf = generateToken(claims, this.signingKey);
        const token = tokenBuf.toString('base64url');
        return { token, expiresAt: exp };
    }

    generateSignedUrl(mediaUrl, policy, viewer = {}) {
        const { token, expiresAt } = this.generateCWTToken(policy, viewer);
        if (policy.placement === 'query') {
            const sep = mediaUrl.includes('?') ? '&' : '?';
            return { signedUrl: `${mediaUrl}${sep}CAT=${token}`, token, expiresAt };
        }
        if (policy.placement === 'header') {
            return { url: mediaUrl, headers: { 'CTA-Common-Access-Token': token }, token, expiresAt };
        }
        const url = new URL(mediaUrl);
        return { signedUrl: `${url.protocol}//${url.host}/${token}${url.pathname}${url.search}`, token, expiresAt };
    }
}

module.exports = { CTAClient, generateToken, parseTTL, CWT, CAT, CATU, MATCH };
