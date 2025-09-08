from typing import Optional, Tuple, Dict, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os, struct

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
    for magic, ext in _MAGIC_TYPES:
        if data.startswith(magic):
            if ext == ".webp" and b"WEBP" not in data[:32]:
                continue
            return ext
    return ".bin"

def _try_decrypt_gcm(key: bytes, blob: bytes, nonce_len: int) -> Optional[bytes]:
    if len(blob) <= nonce_len + 16:
        return None
    nonce = blob[:nonce_len]
    tag = blob[-16:]
    ciphertext = blob[nonce_len:-16]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ciphertext, tag)
        return pt
    except Exception:
        return None

def _try_decrypt_cbc(key: bytes, blob: bytes) -> Optional[bytes]:
    if len(blob) < 16 + 1:
        return None
    iv = blob[:16]
    ct = blob[16:]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            pt = unpad(pt, 16)
        except Exception:
            pass
        return pt
    except Exception:
        return None

def decrypt_attachment_bytes(key: bytes, blob: bytes) -> Tuple[bytes, Dict[str, str]]:
    pt = _try_decrypt_gcm(key, blob, 12)
    if pt is not None:
        return pt, {"mode": "AES-GCM", "nonce_len": "12"}

    pt = _try_decrypt_gcm(key, blob, 16)
    if pt is not None:
        return pt, {"mode": "AES-GCM", "nonce_len": "16"}

    pt = _try_decrypt_cbc(key, blob)
    if pt is not None:
        return pt, {"mode": "AES-CBC", "note": "fallback"}

    raise ValueError("Decryption failed: unsupported format or wrong key.")

def decrypt_attachment_file(key: bytes, in_path: str, out_path: Optional[str] = None) -> str:
    with open(in_path, "rb") as f:
        blob = f.read()
    pt, info = decrypt_attachment_bytes(key, blob)
    ext = guess_ext(pt)
    out = out_path or (in_path + ext)
    with open(out, "wb") as w:
        w.write(pt)
    return out

# ---------------------------
# Carving Utilities (Fallback)
# ---------------------------

def _carve_jpegs(buf: bytes, out_dir: str, base: str) -> List[str]:
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
        out = os.path.join(out_dir, f"{base}_{idx:02d}.jpg")
        with open(out, "wb") as w:
            w.write(buf[start:end])
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_pngs(buf: bytes, out_dir: str, base: str) -> List[str]:
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
        out = os.path.join(out_dir, f"{base}_p{idx:02d}.png")
        with open(out, "wb") as w:
            w.write(buf[start:end])
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_gifs(buf: bytes, out_dir: str, base: str) -> List[str]:
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
            out = os.path.join(out_dir, f"{base}_g{idx:02d}.gif")
            with open(out, "wb") as w:
                w.write(buf[start:end])
            outs.append(out)
            i = end
            idx += 1
    return outs

def _carve_webp(buf: bytes, out_dir: str, base: str) -> List[str]:
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
        if start + 8 + 4 > len(buf):
            break
        size = struct.unpack("<I", buf[start+4:start+8])[0]
        end = start + 8 + size
        end = min(end, len(buf))
        out = os.path.join(out_dir, f"{base}_w{idx:02d}.webp")
        with open(out, "wb") as w:
            w.write(buf[start:end])
        outs.append(out)
        i = end
        idx += 1
    return outs

def _carve_mp4(buf: bytes, out_dir: str, base: str) -> List[str]:
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
            if size < 20 or start + size > len(buf):
                i = pos + 4
                continue
            end = start + size
            out = os.path.join(out_dir, f"{base}_v{idx:02d}.mp4")
            with open(out, "wb") as w:
                w.write(buf[start:end])
            outs.append(out)
            i = end
            idx += 1
        except Exception:
            i = pos + 4
    return outs

def carve_media(plaintext: bytes, out_dir: str, base: str = "carved") -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    outputs += _carve_jpegs(plaintext, out_dir, base)
    outputs += _carve_pngs(plaintext, out_dir, base)
    outputs += _carve_gifs(plaintext, out_dir, base)
    outputs += _carve_webp(plaintext, out_dir, base)
    outputs += _carve_mp4(plaintext, out_dir, base)
    return outputs

def decrypt_and_carve_files(key: bytes, in_path: str, out_dir: str, base: str = "carved") -> List[str]:
    with open(in_path, "rb") as f:
        blob = f.read()
    pt, _ = decrypt_attachment_bytes(key, blob)
    return carve_media(pt, out_dir, base)
