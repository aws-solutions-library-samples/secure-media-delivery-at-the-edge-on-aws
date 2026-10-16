import base64
import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))
from cta_client import CWT, generate_token


class TestMintRotation(unittest.TestCase):
    def setUp(self):
        self.sm = MagicMock()
        boto3 = MagicMock()
        boto3.client.return_value = self.sm
        spec = importlib.util.spec_from_file_location('mint_handler', os.path.join(os.path.dirname(__file__), 'handler.py'))
        self.mint = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'boto3': boto3}):
            spec.loader.exec_module(self.mint)
        self.clock = 1000
        self.clock_patch = patch.object(self.mint.time, 'monotonic', side_effect=lambda: self.clock)
        self.wall_patch = patch.object(self.mint.time, 'time', return_value=1700000000)
        self.env_patch = patch.dict(os.environ, {'SECRET_NAME': 'test-secret'})
        for item in (self.clock_patch, self.wall_patch, self.env_patch):
            item.start()
            self.addCleanup(item.stop)

    def invoke(self, ttl='1h'):
        # Nonempty policy preserves the existing Python required-policy behavior.
        policy = {'sessionId': 'test-session'}
        if ttl is not None:
            policy['ttl'] = ttl
        return self.mint.handler({'body': json.dumps({'policy': policy, 'mediaUrl': 'https://cdn.example.com/video/live.m3u8'})}, None)

    def assert_signed_with(self, result, key, ttl=3600):
        self.assertEqual(result['statusCode'], 200)
        body = json.loads(result['body'])
        expected = generate_token({CWT.ISS: 'cta-secure-media', CWT.EXP: 1700000000 + ttl, CWT.NBF: 1700000000, CWT.IAT: 1700000000, CWT.CTI: 'test-session'}, key)
        actual = base64.urlsafe_b64decode(body['token'] + '=' * (-len(body['token']) % 4))
        self.assertEqual(actual, expected)

    def test_warm_cache_rotation(self):
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'old-key'})}
        self.assert_signed_with(self.invoke(), 'old-key')
        self.clock = 1059.999
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'new-key'})}
        self.assert_signed_with(self.invoke(), 'old-key')
        self.assertEqual(self.sm.get_secret_value.call_count, 1)
        self.clock = 1060
        self.assert_signed_with(self.invoke(), 'new-key')
        self.assertEqual(self.sm.get_secret_value.call_count, 2)
        self.sm.get_secret_value.assert_called_with(SecretId='test-secret')

    def test_fetch_latency_counts(self):
        def fetch(**kwargs):
            self.clock = 1050
            return {'SecretString': json.dumps({'signingKey': 'old-key'})}
        self.sm.get_secret_value.side_effect = fetch
        self.assert_signed_with(self.invoke(), 'old-key')
        self.clock = 1060
        self.sm.get_secret_value.side_effect = None
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'new-key'})}
        self.assert_signed_with(self.invoke(), 'new-key')

    def test_failed_refresh_does_not_mint_stale_key(self):
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'old-key'})}
        self.invoke()
        self.clock = 1060
        self.sm.get_secret_value.side_effect = RuntimeError('unavailable')
        self.assertEqual(self.invoke()['statusCode'], 500)
        self.sm.get_secret_value.side_effect = None
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'new-key'})}
        self.assert_signed_with(self.invoke(), 'new-key')

    def test_ttl_boundaries(self):
        for ttl in (0, -1, 1.5, False, '', 'bad', '0s', '2h1', '121m', '3h', '1d', '25h', 7201, 86400, 86401):
            with self.subTest(ttl=ttl):
                result = self.invoke(ttl)
                self.assertEqual(result['statusCode'], 500)
                self.assertIn('TTL must be', json.loads(result['body'])['error'])
        self.sm.get_secret_value.assert_not_called()
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps({'signingKey': 'key'})}
        for ttl, seconds in (('1h', 3600), ('2h', 7200), ('120m', 7200), (1.0, 1), (3600.0, 3600), (1e3, 1000), (7200.0, 7200), (7200, 7200)):
            with self.subTest(ttl=ttl):
                self.assert_signed_with(self.invoke(ttl), 'key', seconds)
        self.assert_signed_with(self.invoke(None), 'key', 7200)


if __name__ == '__main__':
    unittest.main()
