"""Audit SSH public keys: flag weak types and short RSA keys.

Usage: python3 main.py authorized_keys
Parses each key's base64 blob to measure the real RSA modulus bit length.
"""
import argparse
import base64
import struct
import sys

WEAK_TYPES = {"ssh-dss"}


def _read_string(data, offset):
    (length,) = struct.unpack(">I", data[offset:offset + 4])
    start = offset + 4
    return data[start:start + length], start + length


def key_bits(key_type, blob):
    if key_type == "ssh-rsa":
        _, off = _read_string(blob, 0)
        _, off = _read_string(blob, off)
        modulus, _ = _read_string(blob, off)
        bits = len(modulus) * 8
        stripped = modulus.lstrip(b"\x00")
        bits -= (len(modulus) - len(stripped)) * 8
        return bits
    if key_type == "ssh-ed25519":
        return 256
    if key_type.startswith("ecdsa-sha2-"):
        return int(key_type.rsplit("-", 1)[1])
    return None


def audit(text):
    issues = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            issues.append(f"line {n}: unparsable key line")
            continue
        key_type, b64 = parts[0], parts[1]
        if key_type in WEAK_TYPES:
            issues.append(f"line {n}: weak key type {key_type}")
            continue
        try:
            blob = base64.b64decode(b64, validate=True)
            bits = key_bits(key_type, blob)
        except Exception:
            issues.append(f"line {n}: invalid base64 key blob")
            continue
        if key_type == "ssh-rsa" and bits is not None and bits < 2048:
            issues.append(f"line {n}: short RSA key ({bits} bits, use at least 2048)")
    return issues


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="authorized_keys-style file")
    args = parser.parse_args(argv)
    with open(args.path, encoding="utf-8") as f:
        issues = audit(f.read())
    print(f"{len(issues)} issue(s).")
    for issue in issues:
        print(f"- {issue}")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
