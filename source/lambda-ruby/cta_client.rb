# CTA-5007-B Ruby SDK
# Generates COSE MAC0 / CWT tokens compatible with cf.cwt.validateToken()

require 'openssl'

module CTA
  # COSE / CWT constants (matching CloudFront docs)
  COSE_ALG = 1
  COSE_KID = 4
  HMAC_256 = 5

  module CWT
    ISS = 1; SUB = 2; AUD = 3; EXP = 4; NBF = 5; IAT = 6; CTI = 7
  end

  module CAT
    CATU = 401; CATNIP = 402; CATM = 403; CATR = 404
  end

  module CATU
    HOST = 1; PATH = 2; EXT = 3
  end

  module MATCH
    PREFIX = 1; SUFFIX = 2; EXACT = 3
  end

  # --- Minimal CBOR encoder ---

  def self.cbor_uint_head(major, value)
    m = major << 5
    if value < 24
      [m | value].pack('C')
    elsif value < 0x100
      [m | 24, value].pack('CC')
    elsif value < 0x10000
      [m | 25, value].pack('Cn')
    elsif value < 0x100000000
      [m | 26, value].pack('CN')
    else
      [m | 27, value].pack('CQ>')
    end
  end

  def self.cbor_encode(value)
    case value
    when Integer
      value >= 0 ? cbor_uint_head(0, value) : cbor_uint_head(1, -1 - value)
    when String
      if value.encoding == Encoding::BINARY || value.encoding == Encoding::ASCII_8BIT
        cbor_uint_head(2, value.bytesize) + value
      else
        bytes = value.encode('UTF-8')
        cbor_uint_head(3, bytes.bytesize) + bytes.b
      end
    when Array
      cbor_uint_head(4, value.length) + value.map { |v| cbor_encode(v) }.join
    when Hash
      cbor_uint_head(5, value.length) + value.map { |k, v| cbor_encode(k) + cbor_encode(v) }.join
    when NilClass
      "\xf6".b
    when TrueClass
      "\xf5".b
    when FalseClass
      "\xf4".b
    else
      raise "Cannot CBOR encode: #{value.class}"
    end
  end

  def self.cbor_tag(tag_num, content)
    if tag_num < 24
      [0xd8, tag_num].pack('CC') + content
    else
      cbor_uint_head(6, tag_num) + content
    end
  end

  # --- COSE MAC0 / CWT token generation ---

  def self.generate_token(claims, key, kid: 'key:default', cwt_tag: true)
    protected_bytes = cbor_encode({ COSE_ALG => HMAC_256 })
    unprotected_map = { COSE_KID => kid.encode('UTF-8').b }
    payload_bytes = cbor_encode(claims)

    mac_structure = cbor_encode(["MAC0", protected_bytes, "".b, payload_bytes])
    tag = OpenSSL::HMAC.digest('SHA256', key, mac_structure)

    arr = cbor_encode([protected_bytes, unprotected_map, payload_bytes, tag])
    cose_mac0 = cbor_tag(17, arr)

    cwt_tag ? cbor_tag(61, cose_mac0) : cose_mac0
  end

  def self.parse_ttl(ttl)
    return ttl if ttl.is_a?(Integer)
    m = ttl.to_s.match(/^(\d+)([smhd])$/)
    return 7200 unless m
    v = m[1].to_i
    { 's' => v, 'm' => v * 60, 'h' => v * 3600, 'd' => v * 86400 }[m[2]] || 7200
  end

  class Client
    attr_reader :signing_key

    def initialize(stack_name, region: 'us-east-1')
      @stack_name = stack_name
      @region = region
      @signing_key = nil
      @sm = nil
    end

    def init_secrets_manager(**opts)
      require 'aws-sdk-secretsmanager'
      @sm = Aws::SecretsManager::Client.new(region: @region, **opts)
    end

    def get_signing_keys
      raise 'Call init_secrets_manager first' unless @sm
      resp = @sm.get_secret_value(secret_id: "#{@stack_name}_CTAKey")
      @signing_key = JSON.parse(resp.secret_string)['signingKey']
    end

    def generate_cwt_token(policy, viewer = {})
      raise 'Call get_signing_keys first' unless @signing_key
      now = Time.now.to_i
      exp = now + CTA.parse_ttl(policy[:ttl] || policy['ttl'] || '2h')

      claims = { CWT::ISS => 'cta-secure-media', CWT::EXP => exp, CWT::NBF => now, CWT::IAT => now }
      sid = policy[:sessionId] || policy['sessionId']
      claims[CWT::CTI] = sid if sid
      paths = policy[:paths] || policy['paths']
      if paths&.any?
        prefixes = paths.length == 1 ? paths.first : paths
        claims[CAT::CATU] = { CATU::PATH => { MATCH::PREFIX => prefixes } }
      end
      ips = policy[:ips] || policy['ips']
      claims[CAT::CATNIP] = Array(ips) if ips
      countries = policy[:countries] || policy['countries']
      claims[316] = Array(countries) if countries&.any?

      token_buf = CTA.generate_token(claims, @signing_key)
      token = Base64.urlsafe_encode64(token_buf, padding: false)
      { token: token, expires_at: exp }
    end

    def generate_signed_url(media_url, policy, viewer = {})
      result = generate_cwt_token(policy, viewer)
      token = result[:token]
      placement = policy[:placement] || policy['placement'] || 'path'

      case placement
      when 'query'
        sep = media_url.include?('?') ? '&' : '?'
        result.merge(signed_url: "#{media_url}#{sep}CAT=#{token}")
      when 'header'
        result.merge(url: media_url, headers: { 'CTA-Common-Access-Token' => token })
      else
        uri = URI.parse(media_url)
        signed = "#{uri.scheme}://#{uri.host}/#{token}#{uri.path}"
        signed += "?#{uri.query}" if uri.query
        result.merge(signed_url: signed)
      end
    end
  end
end
