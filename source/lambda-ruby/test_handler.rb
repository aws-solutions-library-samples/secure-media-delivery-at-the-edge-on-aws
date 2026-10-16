require 'minitest/autorun'
require 'minitest/mock'

# Isolate the handler from AWS credentials/network; token signing remains real.
module Aws
  module SecretsManager
    class Client; end
  end
end
$LOADED_FEATURES << 'aws-sdk-secretsmanager.rb'
require_relative 'handler'

class TestMintRotation < Minitest::Test
  def setup
    $cached_key = nil
    $cache_expires_at = 0
    @clock = 1000
    @calls = 0
    @key = 'old-key'
    @fetch = nil
    owner = self
    $sm = Object.new
    $sm.define_singleton_method(:get_secret_value) { |**kwargs| owner.fetch_secret(**kwargs) }
    @previous_secret_name = ENV['SECRET_NAME']
    ENV['SECRET_NAME'] = 'test-secret'
  end

  def teardown
    ENV['SECRET_NAME'] = @previous_secret_name
  end

  def fetch_secret(secret_id:)
    assert_equal 'test-secret', secret_id
    @calls += 1
    @fetch.call if @fetch
    Struct.new(:secret_string).new(JSON.generate({ signingKey: @key }))
  end

  def invoke(ttl = '1h')
    policy = { 'sessionId' => 'test-session' }
    policy['ttl'] = ttl unless ttl == :omitted
    event = { 'body' => JSON.generate({ policy: policy, mediaUrl: 'https://cdn.example.com/video/live.m3u8' }) }
    Time.stub(:now, Time.at(1700000000)) do
      Process.stub(:clock_gettime, ->(*) { @clock }) do
        handler(event: event, context: nil)
      end
    end
  end

  def assert_signed_with(result, key, ttl = 3600)
    assert_equal 200, result[:statusCode]
    body = JSON.parse(result[:body])
    claims = { CTA::CWT::ISS => 'cta-secure-media', CTA::CWT::EXP => 1700000000 + ttl,
               CTA::CWT::NBF => 1700000000, CTA::CWT::IAT => 1700000000, CTA::CWT::CTI => 'test-session' }
    assert_equal CTA.generate_token(claims, key), Base64.urlsafe_decode64(body['token'])
  end

  def test_warm_cache_rotation
    assert_signed_with invoke, 'old-key'
    @key = 'new-key'
    @clock = 1059.999
    assert_signed_with invoke, 'old-key'
    assert_equal 1, @calls
    @clock = 1060
    assert_signed_with invoke, 'new-key'
    assert_equal 2, @calls
  end

  def test_fetch_latency_counts
    @fetch = -> { @clock = 1050 }
    assert_signed_with invoke, 'old-key'
    @fetch = nil
    @clock = 1060
    @key = 'new-key'
    assert_signed_with invoke, 'new-key'
    assert_equal 2, @calls
  end

  def test_failed_refresh_does_not_mint_stale_key
    invoke
    @clock = 1060
    @fetch = -> { raise 'unavailable' }
    assert_equal 500, invoke[:statusCode]
    @fetch = nil
    @key = 'new-key'
    assert_signed_with invoke, 'new-key'
  end

  def test_ttl_boundaries
    [0, -1, 1.5, nil, false, '', 'bad', '0s', '2h1', '121m', '3h', '1d', '25h', 7201, 86400, 86401].each do |ttl|
      result = invoke(ttl)
      assert_equal 500, result[:statusCode]
      assert_includes JSON.parse(result[:body])['error'], 'TTL must be'
    end
    assert_equal 0, @calls
    [['1h', 3600], ['2h', 7200], ['120m', 7200], [1.0, 1], [3600.0, 3600], [1e3, 1000], [7200.0, 7200], [7200, 7200]].each do |ttl, seconds|
      assert_signed_with invoke(ttl), 'old-key', seconds
    end
    assert_signed_with invoke(:omitted), 'old-key', 7200
  end
end
