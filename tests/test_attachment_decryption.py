import os

import pytest
from PIL import Image

from signal_attachment_decrypt import decrypt_attachment_file

try:
    from Crypto.Cipher import AES
except Exception:  # pragma: no cover - optional dependency
    AES = None


@pytest.mark.skipif(AES is None, reason="PyCryptodome not available")
def test_decrypt_attachment_gcm(tmp_path, monkeypatch):
    # create a tiny PNG image as plaintext
    img_path = tmp_path / "plain.png"
    Image.new("RGB", (1, 1), color="white").save(img_path)
    data = img_path.read_bytes()

    key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    enc_path = tmp_path / "attach"
    enc_path.write_bytes(nonce + ct + tag)

    monkeypatch.chdir(tmp_path)
    out = decrypt_attachment_file(key, str(enc_path))
    with Image.open(out) as dec:
        assert dec.size == (1, 1)
