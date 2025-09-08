import os

import pytest

from export_signal_pdf import _decrypt_file_key

try:
    from Crypto.Cipher import AES
except Exception:  # pragma: no cover - optional dependency
    AES = None


@pytest.mark.skipif(AES is None, reason="PyCryptodome not available")
def test_decrypt_file_key_gcm():
    master_key = os.urandom(32)
    file_key = os.urandom(32)
    iv = os.urandom(16)
    plain = file_key + iv
    nonce = os.urandom(12)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plain)
    enc_key = nonce + ct + tag
    derived = _decrypt_file_key(enc_key, master_key)
    assert derived == file_key
