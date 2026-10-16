"""Unit tests for CTA-5007-B Python SDK"""
import sys, os, unittest, hmac, hashlib
sys.path.insert(0, os.path.dirname(__file__))
from cta_client import generate_token, parse_ttl, cbor_encode, CWT, CAT, CATU, MATCH

TEST_KEY = 'test-signing-key-for-unit-tests-1234'

class TestParseTTL(unittest.TestCase):
    def test_seconds(self): self.assertEqual(parse_ttl('30s'), 30)
    def test_minutes(self): self.assertEqual(parse_ttl('5m'), 300)
    def test_hours(self): self.assertEqual(parse_ttl('2h'), 7200)
    def test_maximum_minutes(self): self.assertEqual(parse_ttl('120m'), 7200)
    def test_int_passthrough(self): self.assertEqual(parse_ttl(3600), 3600)
    def test_integer_valued_json_numbers(self):
        import json
        for literal, expected in (('1.0', 1), ('3600.0', 3600), ('1e3', 1000), ('7200.0', 7200)):
            with self.subTest(literal=literal):
                seconds = parse_ttl(json.loads(literal))
                self.assertIs(type(seconds), int)
                self.assertEqual(seconds, expected)
    def test_invalid(self):
        for ttl in ('bad', '', 0, -1, 1.5, 0.0, -1.0, 0.5, 7199.5, 7200.5, 7201.0, float('nan'), float('inf'), -float('inf'), None, False, True, '0s', '2h1', '121m', '3h', '1d', '25h', '2d', 7201, 86400, 86401):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                parse_ttl(ttl)
    def test_maximum(self): self.assertEqual(parse_ttl(7200), 7200)

class TestCborEncode(unittest.TestCase):
    def test_int(self): self.assertEqual(cbor_encode(0), b'\x00')
    def test_small_int(self): self.assertEqual(cbor_encode(23), b'\x17')
    def test_one_byte_int(self): self.assertEqual(cbor_encode(24), b'\x18\x18')
    def test_string(self): self.assertEqual(cbor_encode('abc'), b'\x63abc')
    def test_bytes(self): self.assertEqual(cbor_encode(b'\x01\x02'), b'\x42\x01\x02')
    def test_list(self): self.assertEqual(cbor_encode([1, 2]), b'\x82\x01\x02')
    def test_dict(self): self.assertEqual(cbor_encode({1: 5}), b'\xa1\x01\x05')
    def test_none(self): self.assertEqual(cbor_encode(None), b'\xf6')
    def test_bool_true(self): self.assertEqual(cbor_encode(True), b'\xf5')
    def test_bool_false(self): self.assertEqual(cbor_encode(False), b'\xf4')
    def test_negative_int(self): self.assertEqual(cbor_encode(-1), b'\x20')

class TestGenerateToken(unittest.TestCase):
    def setUp(self):
        self.claims = {CWT.ISS: 'test-issuer', CWT.EXP: 1700000000, CWT.IAT: 1699999000}

    def test_returns_bytes(self):
        self.assertIsInstance(generate_token(self.claims, TEST_KEY), bytes)

    def test_cwt_tag(self):
        token = generate_token(self.claims, TEST_KEY)
        self.assertEqual(token[0], 0xd8)
        self.assertEqual(token[1], 0x3d)  # Tag(61) CWT

    def test_cose_mac0_tag(self):
        token = generate_token(self.claims, TEST_KEY)
        self.assertEqual(token[2], 0xd8)
        self.assertEqual(token[3], 0x11)  # Tag(17) COSE_Mac0

    def test_no_cwt_tag(self):
        token = generate_token(self.claims, TEST_KEY, cwt_tag=False)
        self.assertEqual(token[0], 0xd8)
        self.assertEqual(token[1], 0x11)  # Tag(17) directly

    def test_deterministic(self):
        t1 = generate_token(self.claims, TEST_KEY)
        t2 = generate_token(self.claims, TEST_KEY)
        self.assertEqual(t1, t2)

    def test_different_keys(self):
        t1 = generate_token(self.claims, TEST_KEY)
        t2 = generate_token(self.claims, 'different-key')
        self.assertNotEqual(t1, t2)

    def test_hmac_32_bytes(self):
        token = generate_token(self.claims, TEST_KEY)
        self.assertEqual(len(token[-32:]), 32)

    def test_hmac_verifiable(self):
        token = generate_token(self.claims, TEST_KEY)
        protected_bytes = cbor_encode({1: 5})
        payload_bytes = cbor_encode(self.claims)
        mac_structure = cbor_encode(["MAC0", protected_bytes, b'', payload_bytes])
        expected = hmac.new(TEST_KEY.encode(), mac_structure, hashlib.sha256).digest()
        self.assertEqual(token[-32:], expected)

    def test_path_claim(self):
        claims = {CWT.ISS: 'test', CWT.EXP: 1700000000,
                  CAT.CATU: {CATU.PATH: {MATCH.PREFIX: '/video/'}}}
        token = generate_token(claims, TEST_KEY)
        self.assertIn(b'/video/', token)

class TestConstants(unittest.TestCase):
    def test_cwt(self):
        self.assertEqual(CWT.ISS, 1); self.assertEqual(CWT.EXP, 4)
        self.assertEqual(CWT.NBF, 5); self.assertEqual(CWT.IAT, 6); self.assertEqual(CWT.CTI, 7)
    def test_cat(self):
        self.assertEqual(CAT.CATU, 401); self.assertEqual(CAT.CATNIP, 402)
    def test_catu(self):
        self.assertEqual(CATU.PATH, 2); self.assertEqual(MATCH.PREFIX, 1)

if __name__ == '__main__':
    unittest.main()
