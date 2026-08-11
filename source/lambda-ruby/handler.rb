# CTA-5007-B Token Generator Lambda — Ruby
#
# This Lambda function generates CTA-5007-B compliant COSE MAC0 / CWT tokens
# for securing video content delivered through Amazon CloudFront. It serves as
# the reference implementation for the Ruby SDK.
#
# ## Architecture
#
#   API Gateway (POST /token-ruby)
#       → This Lambda
#           → Reads HMAC signing key from AWS Secrets Manager (cached after first call)
#           → Delegates token generation to the CTA Ruby SDK (cta_client.rb)
#           → Returns base64url-encoded CWT token + signed URL
#
# ## SDK Usage
#
# The SDK's `CTA.generate_token(claims, key)` method handles all cryptographic operations:
#
#   1. CBOR-encodes the claims hash using a built-in minimal CBOR encoder (zero external
#      gems). Integer keys are encoded as CBOR unsigned/negative integers, strings as CBOR
#      text strings, and binary strings (Encoding::BINARY) as CBOR byte strings.
#   2. Builds the COSE MAC_structure per RFC 8152 §6.3:
#      `["MAC0", protectedHeaders, externalAad, payload]`
#   3. Computes HMAC-SHA256 over the MAC_structure using OpenSSL::HMAC
#   4. Assembles the COSE_Mac0 array:
#      `[protectedHeaders, unprotectedHeaders, payload, hmacTag]`
#   5. Wraps in CBOR tags: Tag(17) for COSE_Mac0, Tag(61) for CWT
#
# The resulting token is validated at the edge by CloudFront Functions' cf.cwt.validateToken().
# The Ruby SDK produces byte-identical tokens to the Node.js and Python SDKs.
#
# ## Claims
#
# Standard CWT claims (RFC 8392):
#   - CTA::CWT::ISS (1): Issuer — identifies this token generator
#   - CTA::CWT::EXP (4): Expiration time — Unix timestamp
#   - CTA::CWT::NBF (5): Not before — Unix timestamp
#   - CTA::CWT::IAT (6): Issued at — Unix timestamp
#   - CTA::CWT::CTI (7): CWT ID — session identifier for revocation support
#
# CTA-5007-B claims (CloudFront-aligned claim numbers):
#   - CTA::CAT::CATU (401): URI restrictions — nested hash with path prefix matching
#     Structure: `{ CTA::CATU::PATH(2) => { CTA::MATCH::PREFIX(1) => "/path/" } }`
#
# ## Token Placement
#
# The signed URL embeds the token in the URL path by default:
#   https://cdn.example.com/{TOKEN}/video/stream.m3u8
#
# CloudFront Function strips the token segment before forwarding to origin.
# Query parameter placement (?CAT={TOKEN}) is also supported.
#
# ## Environment Variables
#   - SECRET_NAME: AWS Secrets Manager secret ID containing the HMAC signing key
#
# ## Request Format (POST body)
#   {
#     "policy": {
#       "paths": ["/video/"],     // URI prefix restrictions
#       "ttl": "2h",              // Token lifetime (e.g. "30s", "5m", "2h", "1d")
#       "placement": "path",      // "path" (default) or "query"
#       "sessionId": "abc-123"    // Session ID for revocation tracking
#     },
#     "viewer": {},               // Reserved for future viewer attributes
#     "mediaUrl": "https://cdn.example.com/video/stream.m3u8"
#   }
#
# ## Response Format
#   {
#     "token": "2D3YEYRDoQEF...",           // Base64url-encoded CWT token
#     "signedUrl": "https://cdn/TOKEN/...",  // Ready-to-use signed URL
#     "expiresAt": 1776881062,               // Unix timestamp of expiration
#     "sdk": "ruby"                          // SDK identifier
#   }

require 'json'
require 'base64'
require 'uri'
require 'aws-sdk-secretsmanager'
require_relative 'cta_client'

# Secrets Manager client — initialized once per Lambda container.
$sm = Aws::SecretsManager::Client.new

# Signing key cache — persists across invocations in the same container,
# avoiding repeated Secrets Manager API calls.
$cached_key = nil

# Retrieve the HMAC signing key from AWS Secrets Manager.
#
# The key is a 32-byte hex string stored in a JSON secret under the
# "signingKey" field. It is cached in the global $cached_key variable
# after the first retrieval.
def get_signing_key
  return $cached_key if $cached_key
  resp = $sm.get_secret_value(secret_id: ENV['SECRET_NAME'])
  $cached_key = JSON.parse(resp.secret_string)['signingKey']
end

# Lambda handler for CTA token generation.
#
# Parses the API Gateway proxy event, builds CWT claims from the policy,
# delegates to the Ruby SDK for COSE MAC0 token generation, and returns
# the token with a signed URL.
def handler(event:, context:)
  headers = { 'Access-Control-Allow-Origin' => '*' }
  begin
    body = JSON.parse(event['body'])
    policy = body['policy']
    media_url = body['mediaUrl']
    raise 'Missing required fields: policy, mediaUrl' unless policy && media_url
    raise 'mediaUrl must be a valid HTTP(S) URL' unless media_url.start_with?('http://', 'https://')
    key = get_signing_key
    now = Time.now.to_i
    exp = now + CTA.parse_ttl(policy['ttl'] || '2h')

    # Build CWT claims hash with integer keys per CWT/CAT specification.
    # Ruby hashes natively support integer keys, so no special type needed
    # (unlike the Node.js SDK which requires JavaScript Maps for cbor-x).
    claims = {
      CTA::CWT::ISS => 'cta-secure-media',
      CTA::CWT::EXP => exp,
      CTA::CWT::NBF => now,
      CTA::CWT::IAT => now,
    }

    # Session ID for revocation tracking — stored as a CBOR text string
    # so the CloudFront Function validator can match it against the KVS
    # revocation list using string comparison.
    claims[CTA::CWT::CTI] = policy['sessionId'] if policy['sessionId']

    # URI restriction: catu(401) → path(2) → prefix_match(1)
    # Supports multiple path prefixes per CTA-5007-B
    if policy['paths']&.any?
      prefixes = policy['paths'].length == 1 ? policy['paths'].first : policy['paths']
      claims[CTA::CAT::CATU] = { CTA::CATU::PATH => { CTA::MATCH::PREFIX => prefixes } }
    end

    # IP restriction: catnip(402) — array of allowed IPs
    if policy['ips']
      ips = policy['ips'].is_a?(Array) ? policy['ips'] : [policy['ips']]
      claims[CTA::CAT::CATNIP] = ips
    end

    # Generate the COSE MAC0 / CWT token via the SDK.
    # Returns raw bytes containing the CBOR-encoded token.
    token_buf = CTA.generate_token(claims, key)
    token = Base64.urlsafe_encode64(token_buf, padding: false)

    # Build the signed URL with the token embedded in the path or query string.
    uri = URI.parse(media_url)
    if policy['placement'] == 'header'
      return {
        statusCode: 200,
        headers: headers,
        body: JSON.generate({
          token: token,
          url: media_url,
          headers: { 'CTA-Common-Access-Token' => token },
          expiresAt: exp,
          sdk: 'ruby'
        })
      }
    elsif policy['placement'] == 'query'
      sep = media_url.include?('?') ? '&' : '?'
      signed_url = "#{media_url}#{sep}CAT=#{token}"
    else
      signed_url = "#{uri.scheme}://#{uri.host}/#{token}#{uri.path}"
      signed_url += "?#{uri.query}" if uri.query
    end

    {
      statusCode: 200,
      headers: headers,
      body: JSON.generate({
        token: token,
        signedUrl: signed_url,
        expiresAt: exp,
        sdk: 'ruby'
      })
    }
  rescue => e
    { statusCode: 500, headers: headers, body: JSON.generate({ error: e.message }) }
  end
end
