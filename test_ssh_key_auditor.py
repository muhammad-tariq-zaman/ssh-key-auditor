import base64, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import audit, key_bits


def make_rsa_key(bits):
    def s(b):
        return struct.pack(">I", len(b)) + b
    def mpint(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return s(raw)
    blob = s(b"ssh-rsa") + mpint(65537) + mpint((1 << (bits - 1)) + 1)
    return "ssh-rsa " + base64.b64encode(blob).decode()


class TestSshKeyAuditor(unittest.TestCase):
    def test_strong_rsa_ok(self):
        self.assertEqual(audit(make_rsa_key(2048)), [])

    def test_short_rsa_flagged(self):
        self.assertEqual(len(audit(make_rsa_key(1024))), 1)

    def test_dss_flagged(self):
        self.assertTrue(any("ssh-dss" in i for i in audit("ssh-dss AAAA comment")))

    def test_ed25519_ok(self):
        blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"\x01" * 32).decode()
        self.assertEqual(audit("ssh-ed25519 " + blob), [])
