/**
 * CTA-5007-B API Client - Calls Lambda-backed API Gateway for token operations
 */
class CTAClient {
    constructor(apiEndpoint) {
        this.apiEndpoint = apiEndpoint.replace(/\/$/, '');
    }

    async generateToken(policy, viewer, mediaUrl, sdk = 'node') {
        const path = sdk === 'python' ? '/token-python' : sdk === 'ruby' ? '/token-ruby' : '/token';
        const resp = await fetch(`${this.apiEndpoint}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy, viewer, mediaUrl })
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.error || 'Token generation failed: ' + resp.statusText);
        }
        return resp.json();
    }

    async revokeToken(sessionId, reason) {
        const resp = await fetch(`${this.apiEndpoint}/revoke`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tokenId: sessionId, reason })
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.error || 'Revocation failed: ' + resp.statusText);
        }
        return resp.json();
    }
}
