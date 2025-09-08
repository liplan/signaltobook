#!/usr/bin/env python3
"""
Signal Desktop: decrypt attachment file

Usage examples:
  python3 signal_decode.py --in aaaaa --key-hex 3e3d116a3066b05ccb893a2abefd93a6c6700ff4dbe25e17137edcd7ac7e7ef9
"""

import argparse
import base64
import binascii
import os
import sys
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAGIC_TYPES = [
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"RIFF", ".webp"),
    (b"\x00\x00\x00\x18ftyp", ".mp4"),
    (b"\x1a\x45\xdf\xa3", ".mkv"),
]

def guess_ext(data: bytes) -> str:
    for magic, ext in MAGIC_TYPES:
        if data.startswith(magic):
            if ext == ".webp" and b"WEBP" not in data[:32]:
                continue
            return ext
    return ".bin"

def try_decrypt_gcm(key: bytes, blob: bytes) -> Optional[bytes]:
    for nonce_len in (12, 16):
        if len(blob) <= nonce_len + 16:
            continue
        nonce = blob[:nonce_len]
        tag = blob[-16:]
        ciphertext = blob[nonce_len:-16]
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ciphertext, tag)
            return pt
        except Exception:
            continue
    return None

def try_decrypt_cbc(key: bytes, blob: bytes) -> Optional[bytes]:
    if len(blob) < 16 + 1:
        return None
    iv = blob[:16]
    ct = blob[16:]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        pt = unpad(pt, 16)
        return pt
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="outp", default=None)
    ap.add_argument("--key-b64", dest="key_b64", default=None)
    ap.add_argument("--key-hex", dest="key_hex", default=None, help="AES key in hex (like DB_KEY_HEX)")
    args = ap.parse_args()

    with open(args.inp, "rb") as f:
        blob = f.read()

    key = None
    if args.key_b64:
        key = base64.b64decode(args.key_b64)
    elif args.key_hex:
        key = binascii.unhexlify(args.key_hex)
    else:
        print("Please provide --key-hex or --key-b64", file=sys.stderr)
        sys.exit(2)

    plaintext = try_decrypt_gcm(key, blob)
    if plaintext is None:
        plaintext = try_decrypt_cbc(key, blob)

    if plaintext is None:
        print("Decryption failed", file=sys.stderr)
        sys.exit(3)

    if args.outp:
        out_path = args.outp
    else:
        out_path = args.inp + guess_ext(plaintext)

    with open(out_path, "wb") as f:
        f.write(plaintext)

    print("Decrypted:", out_path)

if __name__ == "__main__":
    main()
