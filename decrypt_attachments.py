"""Decrypt Signal attachments and export to a directory."""

from __future__ import annotations

import base64
import logging
import mimetypes
import os
from pathlib import Path
from typing import Optional, Tuple, Iterable

from signal_attachment_decrypt import decrypt_attachment_file

try:
    from Crypto.Cipher import AES  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    AES = None  # type: ignore

try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    keyring = None  # type: ignore

LOGGER = logging.getLogger(__name__)


def load_master_key() -> bytes:
    """Load master key from OS key store.

    The function attempts to access the operating system's credential store via
    :mod:`keyring`. The key is returned as raw bytes without ever being written
    to disk or logged.
    """

    if keyring is None:
        raise RuntimeError("keyring module is required to load master key")
    key = keyring.get_password("signal", "master_key")
    if not key:
        raise RuntimeError("Master key not found in OS key store")
    try:
        return base64.b64decode(key)
    except Exception:
        return bytes.fromhex(key)


def decrypt_file_key(enc_key: bytes, master_key: bytes) -> Tuple[bytes, bytes]:
    """Decrypt encrypted file key using AES-256-GCM.

    The returned tuple contains the raw AES file key and the nonce/IV used to
    encrypt the attachment file itself.
    """

    if AES is None:
        raise RuntimeError("PyCryptodome is required for attachment decryption")
    nonce = enc_key[:12]
    tag = enc_key[-16:]
    cipher_text = enc_key[12:-16]
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(cipher_text, tag)
    return plain[:32], plain[32:48]


def decrypt_attachment(src: Path, key: bytes, iv: bytes, dest: Path) -> None:
    """Decrypt ``src`` to ``dest`` using :mod:`signal_attachment_decrypt`.

    The ``iv`` parameter is accepted for backward compatibility but ignored,
    as :func:`signal_attachment_decrypt.decrypt_attachment_file` expects the
    nonce to be part of the encrypted file.
    """

    decrypt_attachment_file(key, str(src), str(dest))


def fetch_attachment_rows(conn) -> Iterable[tuple]:
    """Read attachment metadata from the Signal database."""

    cur = conn.cursor()
    cur.execute(
        "SELECT attachmentId, messageId, contentType, fileName, path, key FROM attachments"
    )
    return cur.fetchall()


def export_attachments(db_rows: Iterable[tuple], out_dir: Path) -> None:
    """Decrypt and export all attachments described by ``db_rows``."""

    out_dir.mkdir(parents=True, exist_ok=True)
    master_key = load_master_key()
    for row in db_rows:
        (
            attachment_id,
            message_id,
            content_type,
            file_name,
            path,
            enc_key,
        ) = row
        if not path:
            LOGGER.warning("attachment %s skipped: missing path", attachment_id)
            continue
        src = Path(path)
        if not src.exists():
            LOGGER.warning("attachment %s skipped: file not found", attachment_id)
            continue
        try:
            if isinstance(enc_key, (bytes, bytearray, memoryview)):
                enc = bytes(enc_key)
            else:
                enc = bytes.fromhex(str(enc_key))
            file_key, iv = decrypt_file_key(enc, master_key)
            ext = mimetypes.guess_extension(content_type or "") or ""
            dest_name = file_name or f"{attachment_id}{ext}"
            dest = out_dir / dest_name
            decrypt_attachment(src, file_key, iv, dest)
            size = dest.stat().st_size
            LOGGER.info(
                "attachmentId=%s messageId=%s contentType=%s fileName=%s target=%s bytes=%d result=success",
                attachment_id,
                message_id,
                content_type,
                file_name,
                dest,
                size,
            )
        except Exception as exc:
            LOGGER.error(
                "attachmentId=%s messageId=%s result=error reason=%s",
                attachment_id,
                message_id,
                exc,
            )


__all__ = [
    "load_master_key",
    "decrypt_file_key",
    "decrypt_attachment",
    "fetch_attachment_rows",
    "export_attachments",
]
