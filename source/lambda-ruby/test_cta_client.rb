require 'minitest/autorun'
require_relative 'cta_client'

TEST_KEY = 'test-signing-key-for-unit-tests-1234'

class TestParseTTL < Minitest::Test
  def test_seconds; assert_equal 30, CTA.parse_ttl('30s'); end
  def test_minutes; assert_equal 300, CTA.parse_ttl('5m'); end
  def test_hours; assert_equal 7200, CTA.parse_ttl('2h'); end
  def test_maximum_minutes; assert_equal 7200, CTA.parse_ttl('120m'); end
  def test_int_passthrough; assert_equal 3600, CTA.parse_ttl(3600); end
  def test_integer_valued_json_numbers
    require 'json'
    [['1.0', 1], ['3600.0', 3600], ['1e3', 1000], ['7200.0', 7200]].each do |literal, expected|
      seconds = CTA.parse_ttl(JSON.parse(literal))
      assert_instance_of Integer, seconds
      assert_equal expected, seconds
    end
  end
  def test_invalid
    ['bad', '', 0, -1, 1.5, 0.0, -1.0, 0.5, 7199.5, 7200.5, 7201.0, Float::NAN, Float::INFINITY, -Float::INFINITY, nil, false, true, '0s', '2h1', '121m', '3h', '1d', '25h', '2d', 7201, 86400, 86401].each do |ttl|
      assert_raises(ArgumentError) { CTA.parse_ttl(ttl) }
    end
  end
  def test_maximum; assert_equal 7200, CTA.parse_ttl(7200); end
end

class TestCborEncode < Minitest::Test
  def test_zero; assert_equal "\x00".b, CTA.cbor_encode(0); end
  def test_small_int; assert_equal "\x17".b, CTA.cbor_encode(23); end
  def test_one_byte_int; assert_equal "\x18\x18".b, CTA.cbor_encode(24); end
  def test_string; assert_equal "\x63abc".b, CTA.cbor_encode('abc'); end
  def test_bytes; assert_equal "\x42\x01\x02".b, CTA.cbor_encode("\x01\x02".b); end
  def test_list; assert_equal "\x82\x01\x02".b, CTA.cbor_encode([1, 2]); end
  def test_dict; assert_equal "\xa1\x01\x05".b, CTA.cbor_encode({ 1 => 5 }); end
  def test_nil; assert_equal "\xf6".b, CTA.cbor_encode(nil); end
  def test_true; assert_equal "\xf5".b, CTA.cbor_encode(true); end
  def test_false; assert_equal "\xf4".b, CTA.cbor_encode(false); end
  def test_negative; assert_equal "\x20".b, CTA.cbor_encode(-1); end
end

class TestGenerateToken < Minitest::Test
  def setup
    @claims = { CTA::CWT::ISS => 'test-issuer', CTA::CWT::EXP => 1700000000, CTA::CWT::IAT => 1699999000 }
  end

  def test_returns_string
    assert_kind_of String, CTA.generate_token(@claims, TEST_KEY)
  end

  def test_cwt_tag
    token = CTA.generate_token(@claims, TEST_KEY)
    assert_equal 0xd8, token.getbyte(0)
    assert_equal 0x3d, token.getbyte(1)
  end

  def test_cose_mac0_tag
    token = CTA.generate_token(@claims, TEST_KEY)
    assert_equal 0xd8, token.getbyte(2)
    assert_equal 0x11, token.getbyte(3)
  end

  def test_no_cwt_tag
    token = CTA.generate_token(@claims, TEST_KEY, cwt_tag: false)
    assert_equal 0xd8, token.getbyte(0)
    assert_equal 0x11, token.getbyte(1)
  end

  def test_deterministic
    assert_equal CTA.generate_token(@claims, TEST_KEY), CTA.generate_token(@claims, TEST_KEY)
  end

  def test_different_keys
    refute_equal CTA.generate_token(@claims, TEST_KEY), CTA.generate_token(@claims, 'different-key')
  end

  def test_hmac_32_bytes
    token = CTA.generate_token(@claims, TEST_KEY)
    assert_equal 32, token[-32..].bytesize
  end

  def test_hmac_verifiable
    token = CTA.generate_token(@claims, TEST_KEY)
    protected_bytes = CTA.cbor_encode({ 1 => 5 })
    payload_bytes = CTA.cbor_encode(@claims)
    mac_structure = CTA.cbor_encode(["MAC0", protected_bytes, "".b, payload_bytes])
    expected = OpenSSL::HMAC.digest('SHA256', TEST_KEY, mac_structure)
    assert_equal expected, token[-32..]
  end

  def test_path_claim
    claims = { CTA::CWT::ISS => 'test', CTA::CWT::EXP => 1700000000,
               CTA::CAT::CATU => { CTA::CATU::PATH => { CTA::MATCH::PREFIX => '/video/' } } }
    token = CTA.generate_token(claims, TEST_KEY)
    assert_includes token, '/video/'
  end
end

class TestConstants < Minitest::Test
  def test_cwt
    assert_equal 1, CTA::CWT::ISS; assert_equal 4, CTA::CWT::EXP
    assert_equal 5, CTA::CWT::NBF; assert_equal 6, CTA::CWT::IAT; assert_equal 7, CTA::CWT::CTI
  end
  def test_cat
    assert_equal 401, CTA::CAT::CATU; assert_equal 402, CTA::CAT::CATNIP
  end
end
