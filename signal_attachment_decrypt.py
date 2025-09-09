from typing import Optional, Tuple, Dict, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os, struct, logging
from io import BytesIO
from PIL import Image

logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.FileHandler("signal_attachment_decrypt.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.DEBUG)

# ---------------------------
# Basis-Funktionalität
# ---------------------------

_MAGIC_TYPES = [
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"RIFF", ".webp"),
    (b"\x00\x00\x00\x18ftyp", ".mp4"),
    (b"\x1a\x45\xdf\xa3", ".mkv"),
]

def guess_ext(data: bytes) -> str:
    """Guess file extension by inspecting the header.

    Parameters:
        data: Bytes of the decoded attachment.

    Returns:
        Matching extension including the leading dot, or ``".bin"`` if unknown.

    Raises:
        None.
    """
    logger.debug("guess_ext: starting extension detection")
    for magic, ext in _MAGIC_TYPES:
        if data.startswith(magic):
            if ext == ".webp" and b"WEBP" not in data[:32]:
                logger.debug("guess_ext: false positive webp header, continuing")
                continue
            logger.debug("guess_ext: matched magic %s -> %s", magic, ext)
            return ext
    return ".bin"

def _try_decrypt_gcm(key: bytes, blob: bytes, nonce_len: int) -> Optional[bytes]:
    logger.debug("_try_decrypt_gcm: attempting with nonce_len=%d", nonce_len)
    if len(blob) <= nonce_len + 16:
        logger.debug("_try_decrypt_gcm: blob too short")
        return None
    nonce = blob[:nonce_len]
    tag = blob[-16:]
    ciphertext = blob[nonce_len:-16]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ciphertext, tag)
        logger.debug("_try_decrypt_gcm: success")
        return pt
    except Exception as e:
        logger.debug("_try_decrypt_gcm: failed with %s", e)
        return None

def _try_decrypt_cbc(key: bytes, blob: bytes) -> Optional[bytes]:
    logger.debug("_try_decrypt_cbc: attempting")
    if len(blob) < 16 + 1:
        logger.debug("_try_decrypt_cbc: blob too short")
        return None
    iv = blob[:16]
    ct = blob[16:]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            pt = unpad(pt, 16)
        except Exception:
            logger.debug("_try_decrypt_cbc: unpad failed, ignoring")
            pass
        logger.debug("_try_decrypt_cbc: success")
        return pt
    except Exception as e:
        logger.debug("_try_decrypt_cbc: failed with %s", e)
        return None


def decrypt_file_key(enc_key: bytes, master_key: bytes) -> bytes:
    """Return decrypted attachment key.

    Signal stores attachment keys encrypted with the conversation's master
    key.  Newer versions use AES-256-GCM while older databases relied on
    AES-256-CBC.  This helper attempts GCM first and falls back to the legacy
    CBC method for backwards compatibility.
    """

    # Try the current AES-GCM based wrapping.  If decryption or validation
    # fails we fall back to the historic CBC variant below.
    try:
        nonce = enc_key[:12]
        tag = enc_key[-16:]
        cipher_text = enc_key[12:-16]
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(cipher_text, tag)
        return plain[:32]
    except Exception:
        iv = enc_key[:16]
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        return cipher.decrypt(enc_key[16:])

def decrypt_attachment_bytes(key: bytes, blob: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Decrypt an attachment blob using various AES modes.

    Parameters:
        key: Raw 32‑byte AES key.
        blob: Encrypted attachment bytes.

    Returns:
        Tuple of plaintext bytes and metadata about the mode used.

    Raises:
        ValueError: If no supported decryption scheme succeeds.
    """
    logger.debug("decrypt_attachment_bytes: starting decryption")
    pt = _try_decrypt_gcm(key, blob, 12)
    if pt is not None:
        logger.debug("decrypt_attachment_bytes: used AES-GCM nonce 12")
        return pt, {"mode": "AES-GCM", "nonce_len": "12"}

    pt = _try_decrypt_gcm(key, blob, 16)
    if pt is not None:
        logger.debug("decrypt_attachment_bytes: used AES-GCM nonce 16")
        return pt, {"mode": "AES-GCM", "nonce_len": "16"}

    pt = _try_decrypt_cbc(key, blob)
    if pt is not None:
        logger.debug("decrypt_attachment_bytes: used AES-CBC fallback")
        return pt, {"mode": "AES-CBC", "note": "fallback"}

    logger.debug("decrypt_attachment_bytes: all methods failed")
    raise ValueError("Decryption failed: unsupported format or wrong key.")

def decrypt_attachment_file(key: bytes, in_path: str, out_path: Optional[str] = None) -> str:
    """Decrypt an attachment file and write the plaintext to disk.

    Parameters:
        key: Raw 32‑byte AES key.
        in_path: Path to the encrypted file.
        out_path: Optional output path; defaults to ``in_path`` with guessed extension.

    Returns:
        Path to the written plaintext file.

    Raises:
        ValueError: If decryption fails.
        OSError: If reading or writing files fails.
    """
    logger.debug("decrypt_attachment_file: reading %s", in_path)
    with open(in_path, "rb") as f:
        blob = f.read()
    pt, info = decrypt_attachment_bytes(key, blob)
    logger.debug("decrypt_attachment_file: decryption info %s", info)
    ext = guess_ext(pt)
    out = out_path or (in_path + ext)
    logger.debug("decrypt_attachment_file: writing output to %s", out)
    with open(out, "wb") as w:
        w.write(pt)
    return out


def decrypt_attachment_with_enc_key(
    enc_key: bytes, master_key: bytes, in_path: str, out_path: Optional[str] = None
) -> str:
    """Decrypt attachment ``in_path`` using ``enc_key`` and ``master_key``.

    This is a convenience wrapper that first derives the raw file key from the
    encrypted key stored in the database and then delegates to
    :func:`decrypt_attachment_file`.
    """

    file_key = decrypt_file_key(enc_key, master_key)
    return decrypt_attachment_file(file_key, in_path, out_path)

# ---------------------------
# Carving Utilities (Fallback)
# ---------------------------

_MIN_JPEG_SIZE = 100
_MIN_PNG_SIZE = 32
_MIN_GIF_SIZE = 32
_MIN_WEBP_SIZE = 24
_MIN_MP4_SIZE = 32

def _carve_jpegs(buf: bytes, out_dir: str, base: str) -> List[str]:
    logger.debug("_carve_jpegs: scanning for JPEG fragments")
    outs = []
    i = 0
    idx = 1
    while True:
        start = buf.find(b"\xff\xd8\xff", i)
        if start == -1:
            break
        end = buf.find(b"\xff\xd9", start+2)
        if end == -1:
            break
        end += 2
        fragment = buf[start:end]
        if len(fragment) < _MIN_JPEG_SIZE:
            i = end
            continue
        try:
            Image.open(BytesIO(fragment)).verify()
        except Exception:
            i = end
            continue
        out = os.path.join(out_dir, f"{base}_{idx:02d}.jpg")
        with open(out, "wb") as w:
            w.write(fragment)
        logger.debug("_carve_jpegs: wrote %s", out)
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_pngs(buf: bytes, out_dir: str, base: str) -> List[str]:
    logger.debug("_carve_pngs: scanning for PNG fragments")
    outs = []
    sig = b"\x89PNG\r\n\x1a\n"
    i = 0
    idx = 1
    while True:
        start = buf.find(sig, i)
        if start == -1:
            break
        iend = buf.find(b"IEND", start)
        if iend == -1:
            break
        if iend >= 4:
            try:
                length = struct.unpack(">I", buf[iend-4:iend])[0]
                end = iend + 4 + length + 4
            except Exception:
                end = iend + 8
        else:
            end = iend + 8
        if end > len(buf):
            break
        fragment = buf[start:end]
        if len(fragment) < _MIN_PNG_SIZE:
            i = end
            continue
        try:
            Image.open(BytesIO(fragment)).verify()
        except Exception:
            i = end
            continue
        out = os.path.join(out_dir, f"{base}_p{idx:02d}.png")
        with open(out, "wb") as w:
            w.write(fragment)
        logger.debug("_carve_pngs: wrote %s", out)
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_gifs(buf: bytes, out_dir: str, base: str) -> List[str]:
    logger.debug("_carve_gifs: scanning for GIF fragments")
    outs = []
    idx = 1
    for sig in (b"GIF87a", b"GIF89a"):
        i = 0
        while True:
            start = buf.find(sig, i)
            if start == -1:
                break
            end = buf.find(b"\x3B", start+6)
            if end == -1:
                break
            end += 1
            fragment = buf[start:end]
            if len(fragment) < _MIN_GIF_SIZE:
                i = end
                continue
            try:
                Image.open(BytesIO(fragment)).verify()
            except Exception:
                i = end
                continue
            out = os.path.join(out_dir, f"{base}_g{idx:02d}.gif")
            with open(out, "wb") as w:
                w.write(fragment)
            logger.debug("_carve_gifs: wrote %s", out)
            outs.append(out)
            i = end
            idx += 1
    return outs

def _carve_webp(buf: bytes, out_dir: str, base: str) -> List[str]:
    logger.debug("_carve_webp: scanning for WEBP fragments")
    outs = []
    i = 0
    idx = 1
    while True:
        start = buf.find(b"RIFF", i)
        if start == -1:
            break
        if buf[start+8:start+12] != b"WEBP":
            i = start + 4
            continue
        if start + 12 > len(buf):
            break
        size = struct.unpack("<I", buf[start+4:start+8])[0]
        end = start + 8 + size
        if end > len(buf) or size < _MIN_WEBP_SIZE:
            i = start + 4
            continue
        fragment = buf[start:end]
        try:
            Image.open(BytesIO(fragment)).verify()
        except Exception:
            i = end
            continue
        out = os.path.join(out_dir, f"{base}_w{idx:02d}.webp")
        with open(out, "wb") as w:
            w.write(fragment)
        logger.debug("_carve_webp: wrote %s", out)
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_mp4(buf: bytes, out_dir: str, base: str) -> List[str]:
    logger.debug("_carve_mp4: scanning for MP4 fragments")
    outs = []
    i = 0
    idx = 1
    while True:
        pos = buf.find(b"ftyp", i)
        if pos == -1 or pos < 4:
            break
        start = pos - 4
        try:
            size = struct.unpack(">I", buf[start:start+4])[0]
            if size < _MIN_MP4_SIZE or start + size > len(buf):
                i = pos + 4
                continue
            fragment = buf[start:start+size]
            if b"moov" not in fragment and b"mdat" not in fragment:
                i = pos + 4
                continue
            end = start + size
            out = os.path.join(out_dir, f"{base}_v{idx:02d}.mp4")
            with open(out, "wb") as w:
                w.write(fragment)
            logger.debug("_carve_mp4: wrote %s", out)
            outs.append(out)
            i = end
            idx += 1
        except Exception as e:
            logger.debug("_carve_mp4: failed with %s", e)
            i = pos + 4
    return outs

def carve_media(plaintext: bytes, out_dir: str, base: str = "carved") -> List[str]:
    """Extract media fragments from raw bytes and store them as files.

    Parameters:
        plaintext: Bytes to scan for embedded media.
        out_dir: Directory where carved files are written.
        base: Base filename used when generating output names.

    Returns:
        List of paths to carved media files.

    Raises:
        OSError: If the output directory or files cannot be created.
    """
    logger.debug("carve_media: output dir %s base %s", out_dir, base)
    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    outputs += _carve_jpegs(plaintext, out_dir, base)
    outputs += _carve_pngs(plaintext, out_dir, base)
    outputs += _carve_gifs(plaintext, out_dir, base)
    outputs += _carve_webp(plaintext, out_dir, base)
    outputs += _carve_mp4(plaintext, out_dir, base)
    logger.debug("carve_media: carved %d files", len(outputs))
    return outputs

def decrypt_and_carve_files(key: bytes, in_path: str, out_dir: str, base: str = "carved") -> List[str]:
    """Decrypt an attachment file and carve embedded media from it.

    Parameters:
        key: Raw 32‑byte AES key.
        in_path: Path to the encrypted attachment.
        out_dir: Directory where carved files are written.
        base: Base filename used when generating output names.

    Returns:
        List of paths to carved media files.

    Raises:
        ValueError: If decryption fails.
        OSError: If file operations fail.
    """
    logger.debug("decrypt_and_carve_files: reading %s", in_path)
    with open(in_path, "rb") as f:
        blob = f.read()
    pt, info = decrypt_attachment_bytes(key, blob)
    logger.debug("decrypt_and_carve_files: decryption info %s", info)
    return carve_media(pt, out_dir, base)
