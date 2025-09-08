#!/usr/bin/env python3
"""
Export Signal messages from a single conversation to a PDF file.

The script expects a Signal SQLite database (e.g. the `signal.db` from
Signal Desktop or Android).  It exports all messages exchanged within a
specific conversation and optionally embeds image attachments.  Messages are
filtered by a date range, for example from 1 December 2020 to
24 December 2020.

Usage:
    python export_signal_pdf.py --db path/to/signal.db \
                                --conversation 1 \
                                --start 2020-12-01 \
                                --end 2020-12-24 \
                                --output chat.pdf

The database schema can differ depending on the Signal version.  The SQL
query in this script targets the common tables `messages` and
`attachments`.  Adjust the query if your schema deviates.
"""

import argparse
import json
import os
import re
import shutil
import tempfile
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Any

try:
    from pysqlcipher3 import dbapi2 as sqlite3
except ImportError:  # pragma: no cover - fallback only used when pysqlcipher3 missing
    try:
        from sqlcipher3 import dbapi2 as sqlite3
    except ImportError:  # pragma: no cover - handled in open_db
        sqlite3 = None

from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup
from PIL import Image
from premailer import transform

try:  # attachment decryption
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Util.Padding import unpad  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    AES = None  # type: ignore
    unpad = None  # type: ignore

try:  # optional HEIF support
    import pillow_heif  # type: ignore

    pillow_heif.register_heif_opener()  # pragma: no cover - optional dependency
except Exception:  # pragma: no cover - dependency not available
    pass

logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.FileHandler("image_analysis.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(_handler)
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(_console)
logger.setLevel(logging.INFO)

# Sanitize helper -------------------------------------------------------------

def _ensure_latin1(text: str) -> str:
    """Return ``text`` limited to latin-1 characters.

    ``fpdf`` internally encodes page content using latin-1.  When chat
    messages contain characters outside this range (for example emoji),
    the PDF generation would otherwise raise ``UnicodeEncodeError`` when
    writing the document.  Characters not representable in latin-1 are
    replaced with ``?`` so the export can continue without crashing.
    """

    return text.encode("latin-1", "replace").decode("latin-1")


def _format_enc_key(key: Any) -> str:
    """Return a hex representation of an attachment encryption key."""

    if key is None:
        return "None"
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key).hex()
    return str(key)

# Work around missing HTML2FPDF.unescape attribute in fpdf
try:
    from fpdf.html import HTML2FPDF  # type: ignore
    from html import unescape as html_unescape
    if not hasattr(HTML2FPDF, "unescape"):
        HTML2FPDF.unescape = staticmethod(html_unescape)  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    pass


def _normalize_image(path: str) -> Optional[str]:
    """Return a path to ``path`` converted to a PDF-compatible image.

    ``None`` is returned when ``path`` does not point to a readable image.  In
    that case callers should provide a placeholder or skip the reference.
    Supported formats with a proper extension are returned unchanged, others
    are converted to a temporary PNG/JPEG file to ensure compatibility.
    """

    logger.info("Checking image %s", path)
    if not os.path.exists(path):
        logger.warning("Image %s does not exist", path)
        return None
    try:
        with Image.open(path) as img:
            fmt = (img.format or "").upper()
            ext = Path(path).suffix.lower()
            # Accept common formats only when they already have a proper
            # extension.  Otherwise convert to a temp file with one.
            if fmt in {"PNG", "JPEG", "JPG"} and ext in {".png", ".jpg", ".jpeg"}:
                logger.info("Image %s supported without conversion", path)
                return path

            # Convert everything else to PNG except JPEG which keeps its format
            suffix = ".jpg" if fmt in {"JPEG", "JPG"} else ".png"
            tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            out_fmt = "JPEG" if suffix == ".jpg" else "PNG"
            img.save(tmp.name, format=out_fmt)
            logger.info("Converted %s to %s", path, tmp.name)
            return tmp.name
    except Exception:
        # Fallback to ImageMagick via ``wand`` when Pillow cannot read the image.
        try:
            from wand.image import Image as WandImage  # type: ignore

            with WandImage(filename=path) as img:  # pragma: no cover - dependent on wand
                fmt = (img.format or "").upper()
                suffix = ".jpg" if fmt in {"JPEG", "JPG"} else ".png"
                tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
                img.format = "jpeg" if suffix == ".jpg" else "png"
                img.save(filename=tmp.name)
                logger.info("Converted %s to %s via wand", path, tmp.name)
                return tmp.name
        except Exception:
            logger.warning("Unsupported image %s", path)
            return None

    logger.warning("Unsupported image %s", path)
    return None


class PDF(FPDF):
    """FPDF class extended with HTML rendering support."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tmp_images: List[str] = []

    def image_map(self, src: str) -> str:  # type: ignore[override]
        new_src = _normalize_image(src)
        if not new_src:
            return src
        if new_src != src:
            self._tmp_images.append(new_src)
        return new_src

    def cleanup(self) -> None:
        for fp in self._tmp_images:
            try:
                os.remove(fp)
            except OSError:
                pass
        self._tmp_images.clear()


_REWRITE_TMP_IMAGES: List[str] = []
_IMG_TAG_RE = re.compile(r"<img\s+[^>]*src=['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)


def rewrite_img_srcs_in_html(html: str) -> str:
    """Rewrite ``<img src>`` paths to PDF-compatible images.

    Images in formats unsupported by :mod:`fpdf` (e.g. HEIC/WEBP or files
    lacking an extension) are converted to temporary PNG/JPEG files.  Non-image
    sources are replaced with a placeholder text.
    """

    global _REWRITE_TMP_IMAGES
    _REWRITE_TMP_IMAGES = []

    def repl(match: re.Match) -> str:
        src = match.group(1)
        new_src = _normalize_image(src)
        if not new_src:
            return "[Unsupported image]"
        if new_src != src:
            _REWRITE_TMP_IMAGES.append(new_src)
            return match.group(0).replace(src, new_src)
        return match.group(0)

    return _IMG_TAG_RE.sub(repl, html)


def inline_css(html: str, base_path: Optional[Path] = None) -> str:
    """Inline CSS rules using :mod:`premailer` for broader selector support.

    ``base_path`` specifies where linked stylesheets are located. The resulting
    string contains only the body content so that style definitions are not
    rendered as text in the PDF.
    """

    # ``premailer.transform`` expects ``base_url`` to include a URL scheme.
    # :func:`Path.resolve` returns a filesystem path without one which caused
    # ``ValueError: Base URL must have a scheme``.  ``Path.as_uri`` yields a
    # ``file://`` URL, but it lacks a trailing slash for directories.  Adding
    # the slash ensures that relative stylesheet paths resolve correctly.
    base_url = (
        base_path.resolve().as_uri().rstrip("/") + "/" if base_path else None
    )
    inlined = transform(html, base_url=base_url)
    body_match = re.search(r"<body[^>]*>(.*)</body>", inlined, re.DOTALL | re.IGNORECASE)
    return body_match.group(1) if body_match else inlined


DB_KEY_HEX = "3e3d116a3066b05ccb893a2abefd93a6c6700ff4dbe25e17137edcd7ac7e7ef9"

# Label used for messages sent by the user
SELF_LABEL = "You"

CONFIG_FILE = Path.home() / ".signaltobook_config.json"

# Common directories where Signal stores attachments across platforms
ATTACHMENT_SEARCH_DIRS = [
    Path.home() / ".config/Signal/attachments.noindex",
    Path.home() / ".local/share/Signal/attachments.noindex",
    Path.home() / ".local/share/signal-desktop/attachments.noindex",
    Path.home() / "Library/ApplicationSupport/Signal/attachments.noindex",
    Path.home() / "Library/ApplicationSupport/Signal/attachments.noindex",
    Path.home() / "AppData/Roaming/Signal/attachments.noindex",
]


def load_config() -> dict:
    """Load persisted options from :data:`CONFIG_FILE`."""

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: dict) -> None:
    """Persist ``data`` to :data:`CONFIG_FILE`.

    Errors are silently ignored because failing to store configuration should
    not break the main export functionality.
    """

    try:
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def check_readable(path: Path) -> List[Path]:
    """Return a list of files under ``path`` that are not readable."""

    path = path.resolve()
    if path.is_file():
        return [] if os.access(path, os.R_OK) else [path]

    unreadable: List[Path] = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = Path(root) / name
            if not os.access(fp, os.R_OK):
                unreadable.append(fp)
    return unreadable


def fail(message: str) -> None:
    """Abort execution with an error message."""
    raise SystemExit(message)


def ensure_font(font_path: Path) -> None:
    """Ensure that `DejaVuSans.ttf` exists at ``font_path``.

    A :class:`FileNotFoundError` is raised when the font is missing so the
    caller can provide a helpful error message.
    """

    if font_path.exists():
        return

    raise FileNotFoundError(
        f"Unicode font file not found: {font_path}. Ensure the DejaVu Sans "
        "font files are available."
    )

def sanitize_text(text: str, pdf: FPDF) -> str:
    """Return ``text`` unchanged."""

    return text


def resolve_attachment_path(
    raw_path: Optional[str], extra_dir: Optional[str] = None
) -> Optional[str]:
    """Return an existing filesystem path for ``raw_path``.

    Signal stores attachments in different base directories depending on the
    platform and version. The database may only hold a partial path or
    filename. This helper checks several common directories, optionally an
    additional user-supplied directory, and returns the first matching file or
    ``None`` when the attachment cannot be located. If a direct lookup fails,
    the directories are searched recursively for a matching filename.
    """

    if not raw_path:
        return None

    raw_path = raw_path.strip()
    logger.info("Resolving attachment path %s", raw_path)
    path = Path(raw_path)
    candidates = [path, Path(path.name)]

    search_dirs = ATTACHMENT_SEARCH_DIRS.copy()
    if extra_dir:
        search_dirs.insert(0, Path(extra_dir))

    for cand in candidates:
        if cand.exists():
            return str(cand)

    for base in search_dirs:
        for cand in candidates:
            candidate = base / cand
            if candidate.exists():
                return str(candidate)
            if base.is_dir():
                try:
                    match = next(base.rglob(cand.name))
                    return str(match)
                except StopIteration:
                    pass
    return None


def detect_mime_type(path: str) -> Optional[str]:
    """Best-effort MIME type detection for ``path``.

    The function tries multiple strategies to infer the media type so that
    attachments lacking file extensions can still be classified. Only a small
    subset of formats is recognized which is sufficient to distinguish images
    from common audio files. ``None`` is returned when detection fails."""

    import mimetypes
    import imghdr

    if not os.path.exists(path):
        logger.warning("File %s does not exist", path)
        return None

    result: Optional[str] = None
    mime, _ = mimetypes.guess_type(path)
    if mime:
        result = mime
    else:
        try:
            img = imghdr.what(path)
            if img:
                result = f"image/{img}"
        except Exception:
            pass
        if not result:
            try:
                with open(path, "rb") as fh:
                    header = fh.read(12)
                if header.startswith(b"RIFF") and header[8:12] == b"WAVE":
                    result = "audio/wav"
                elif header.startswith(b"ID3") or header[:2] == b"\xff\xfb":
                    result = "audio/mpeg"
                elif header.startswith(b"OggS"):
                    result = "audio/ogg"
                elif header.startswith(b"fLaC"):
                    result = "audio/flac"
            except OSError:
                logger.warning("Failed to read %s for MIME detection", path)
                return None

    logger.info("MIME detection for %s: %s", path, result or "unknown")
    return result


def _decrypt_file_key(enc_key: bytes, master_key: bytes) -> bytes:
    """Return decrypted attachment key using AES-256-CBC."""

    iv = enc_key[:16]
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    return cipher.decrypt(enc_key[16:])


def _decrypt_attachment(path: str, file_key: bytes) -> Optional[str]:
    """Decrypt attachment at ``path`` using ``file_key``.

    A temporary file with the decrypted content is returned or ``None`` when
    decryption fails. Attachments are expected to have a 16 byte IV prefix.
    """

    logger.info("Starting decryption of attachment %s", path)
    if AES is None or unpad is None:
        logger.warning("PyCryptodome is required for attachment decryption")
        return None
    try:
        with open(path, "rb") as fh:
            iv = fh.read(16)
            data = fh.read()
        cipher = AES.new(file_key, AES.MODE_CBC, iv)
        logger.info("Using IV %s", iv.hex())
        dec = cipher.decrypt(data)
        try:
            dec = unpad(dec, AES.block_size)
        except ValueError:
            logger.info("Data for %s not padded", path)
        images_dir = Path("images")
        images_dir.mkdir(exist_ok=True)
        name = Path(path).name
        if name.endswith(".enc"):
            name = name[:-4]
        dest_path = images_dir / name
        with open(dest_path, "wb") as out:
            out.write(dec)
        mime = detect_mime_type(str(dest_path))
        logger.info(
            "Decrypted attachment saved to %s (MIME: %s)",
            dest_path,
            mime or "unknown",
        )
        return str(dest_path)
    except Exception:
        logger.warning("Failed to decrypt attachment %s", path)
        return None


def is_outgoing(flag: Any) -> bool:
    """Return ``True`` if ``flag`` indicates an outgoing message.

    The function accepts common representations such as boolean values,
    numeric markers, or descriptive strings like ``"outgoing"``. Values that
    cannot be interpreted are treated as ``False`` (incoming).
    """

    if flag is None:
        return False
    if isinstance(flag, str):
        return flag.lower() in {"outgoing", "sent", "true", "1"}
    try:
        return int(flag) > 0
    except (TypeError, ValueError):
        return bool(flag)


class SqlCipherError(RuntimeError):
    """Raised when SQLCipher support is missing or inadequate."""


def open_db(db_path: str, key_hex: str) -> sqlite3.Connection:
    """Open a Signal SQLite database using SQLCipher-enabled bindings.

    The database is accessed via a SQLCipher driver such as ``pysqlcipher3``.
    The provided ``key_hex`` is applied to unlock encrypted databases.  A
    :class:`SqlCipherError` is raised when suitable bindings are missing.
    """

    if not os.path.isfile(db_path):
        fail(f"Database file not found: {db_path}")
    if check_readable(Path(db_path)):
        fail(f"Database file not readable: {db_path}. Check permissions.")

    if sqlite3 is None:
        raise SqlCipherError(
            "SQLCipher-enabled Python bindings are required. Install "
            "pysqlcipher3 or sqlcipher3."
        )

    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.DatabaseError as exc:
        fail(f"Could not open SQLite database at {db_path}: {exc}")

    # Ensure the driver actually speaks SQLCipher to avoid silently using the
    # standard sqlite3 module when the dependency is missing.
    try:
        version_row = conn.execute("PRAGMA cipher_version;").fetchone()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise SqlCipherError(
            "Installed bindings do not support PRAGMA cipher_version; "
            "ensure SQLCipher is available"
        ) from exc
    if not version_row or not version_row[0]:
        conn.close()
        raise SqlCipherError(
            "SQLCipher support is required to open this database."
        )

    conn.execute(f"PRAGMA key = \"x'{key_hex}'\";")
    try:
        conn.execute("PRAGMA cipher_migrate;")
    except sqlite3.DatabaseError:
        pass

    # Validate access by running a trivial query. If the database is encrypted
    # and no key was supplied this will raise a DatabaseError.
    try:
        conn.execute("SELECT count(*) FROM sqlite_master;")
    except sqlite3.DatabaseError as exc:
        conn.close()
        fail(
            "Could not read database. The key might be wrong or the database "
            f"corrupted: {exc}"
        )
    return conn


def confirm_db_connection(db_path: str, key_hex: str) -> None:
    """Validate access to ``db_path`` and show available tables."""

    try:
        conn = open_db(db_path, key_hex)
    except SqlCipherError as exc:
        fail(str(exc))
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    except sqlite3.DatabaseError as exc:
        conn.close()
        fail(f"Could not list tables: {exc}")
    tables = [row[0] for row in cur.fetchall()]
    print("Successfully connected to database. Available tables:")
    for name in tables:
        print(f" - {name}")
    conn.close()
    input("Press Enter to continue...")


def list_conversations(db_path: str, key_hex: str) -> List[Tuple[str, str]]:
    """Return sorted list of ``(id, label)`` pairs for each conversation.

    The function attempts several queries to obtain a human friendly label
    such as a profile name or phone number.  When no such information is
    available the identifier itself is used as the label.
    """

    try:
        conn = open_db(db_path, key_hex)
    except SqlCipherError:
        fail(
            "Database is likely encrypted or requires SQLCipher support. "
            "Install SQLCipher-enabled Python bindings (e.g., pysqlcipher3)."
        )
    cur = conn.cursor()

    queries = [
        # Join with recipients table if available to show names or numbers.
        """
        SELECT c.id,
               COALESCE(r.profileName, r.name, r.phone, r.e164,
                        c.name, c.e164, c.id) AS label
        FROM conversations AS c
        LEFT JOIN recipients AS r ON c.recipient_id = r._id
        ORDER BY label;
        """,
        """
        SELECT c.id,
               COALESCE(r.profileName, r.name, r.phone, r.e164,
                        c.name, c.e164, c.id) AS label
        FROM conversations AS c
        LEFT JOIN recipients AS r ON c.recipientId = r._id
        ORDER BY label;
        """,
        "SELECT id, COALESCE(name, e164, id) AS label FROM conversations ORDER BY label;",
        "SELECT _id, COALESCE(name, e164, _id) AS label FROM conversations ORDER BY label;",
        "SELECT id, id AS label FROM conversations ORDER BY id;",
        "SELECT _id, _id AS label FROM conversations ORDER BY _id;",
    ]

    rows: List[Tuple[str, str]] = []
    for query in queries:
        try:
            cur.execute(query)
            rows = [(str(r[0]), str(r[1])) for r in cur.fetchall()]
            if rows:
                break
        except sqlite3.DatabaseError:
            continue

    conn.close()
    if not rows:
        fail("No conversations found in the database.")

    # Only keep conversations with human readable names. The label must contain
    # at least one alphabetic character to avoid showing bare identifiers or
    # phone numbers. This filters the recipients list to entries that actually
    # have a name stored in the database.
    filtered = [
        (cid, label)
        for cid, label in rows
        if any(ch.isalpha() for ch in label)
    ]
    if not filtered:
        fail("No named conversations found in the database.")
    return filtered


def detect_message_schema(cur: Any) -> dict:
    """Return table and column names for message data.

    The schema across Signal versions varies.  This helper inspects all
    available tables and picks the first one that provides the required
    columns to retrieve conversation id, timestamp and message body.
    """

    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cur.fetchall()]

    conv_cols = [
        "conversationId",
        "conversation_id",
        "thread_id",
        "threadId",
        "recipient_id",
        "recipientId",
    ]
    date_cols = [
        "date",
        "date_sent",
        "timestamp",
        "sent_at",
        "created_at",
        "received_at",
    ]
    body_cols = ["body", "message", "text", "content"]
    id_cols = ["_id", "id"]
    sender_cols = [
        "from_me",
        "is_from_me",
        "isOutgoing",
        "is_outgoing",
        "type",
    ]

    for table in tables:
        try:
            cur.execute(f"PRAGMA table_info('{table}')")
        except sqlite3.DatabaseError:
            continue
        cols = {row[1] for row in cur.fetchall()}
        conv_col = next((c for c in conv_cols if c in cols), None)
        date_col = next((c for c in date_cols if c in cols), None)
        body_col = next((c for c in body_cols if c in cols), None)
        id_col = next((c for c in id_cols if c in cols), None)
        sender_col = next((c for c in sender_cols if c in cols), None)
        if conv_col and date_col and body_col and id_col:
            return {
                "table": table,
                "conv": conv_col,
                "date": date_col,
                "body": body_col,
                "id": id_col,
                "sender": sender_col,
            }

    fail("Could not detect messages table with expected columns.")


def detect_attachment_schema(cur: Any, msg_id_col: str) -> Optional[dict]:
    """Return attachment table information or ``None`` if not found."""

    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cur.fetchall()]
    candidates = [t for t in tables if "attach" in t]

    path_cols = ["filePath", "fileName", "path", "filename"]
    mime_cols = ["contentType", "mimetype", "mime_type", "type"]
    key_cols = ["key", "fileKey", "file_key"]
    fk_cols = [
        "message_id",
        "messageId",
        "m_id",
        "msg_id",
        msg_id_col,
    ]

    for table in candidates:
        try:
            cur.execute(f"PRAGMA table_info('{table}')")
        except sqlite3.DatabaseError:
            continue
        cols = {row[1] for row in cur.fetchall()}
        fk_col = next((c for c in fk_cols if c in cols), None)
        paths = [c for c in path_cols if c in cols]
        if fk_col and paths:
            mime_col = next((c for c in mime_cols if c in cols), None)
            key_col = next((c for c in key_cols if c in cols), None)
            return {
                "table": table,
                "fk": fk_col,
                "paths": paths,
                "mime": mime_col,
                "key": key_col,
            }

    return None


def export_chat(
    db_path: str,
    conversation_id: str,
    conversation_label: str,
    start_date: str,
    end_date: str,
    output_pdf: str,
    key_hex: str,
    template_path: Optional[str] = None,
    attachments_dir: Optional[str] = None,
) -> bool:
    """Export messages from ``conversation_id`` between ``start_date`` and ``end_date``.

    Parameters
    ----------
    db_path: str
        Path to the Signal SQLite database.
    conversation_id: str
        Identifier of the conversation selected from the ``conversations`` table.
    conversation_label: str
        Human readable name of the chat partner.
    start_date: str
        Start of the period (``YYYY-MM-DD``).
    end_date: str
        End of the period (``YYYY-MM-DD``).
    output_pdf: str
        Path to the generated PDF file.
    key_hex: str
        Database key in hex format.
    attachments_dir: Optional[str]
        Additional base directory to search for attachments.

    Returns
    -------
    bool
        ``True`` if messages were exported and the PDF was created, ``False``
        when no messages exist for the given selection.
    """

    try:
        conn = open_db(db_path, key_hex)
    except SqlCipherError as exc:
        fail(str(exc))
    cur = conn.cursor()
    schema = detect_message_schema(cur)
    attachment = detect_attachment_schema(cur, schema["id"])

    direction_expr = (
        f"m.{schema['sender']} AS sender" if schema.get("sender") else "NULL AS sender"
    )

    start_ts = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1000)
    end_ts = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1000)

    if attachment:
        path_expr = (
            f"a.{attachment['paths'][0]}" if len(attachment["paths"]) == 1
            else "COALESCE(" + ", ".join(f"a.{p}" for p in attachment["paths"]) + ")"
        )
        mime_expr = f"a.{attachment['mime']}" if attachment["mime"] else "NULL"
        key_expr = f"a.{attachment['key']}" if attachment.get("key") else "NULL"
        query = f"""
        SELECT m.{schema['date']} AS date,
               m.{schema['body']} AS body,
               {path_expr} AS attachment_path,
               {mime_expr} AS contentType,
               {key_expr} AS fileKey,
               {direction_expr}
        FROM {schema['table']} AS m
        LEFT JOIN {attachment['table']} AS a
               ON m.{schema['id']} = a.{attachment['fk']}
        WHERE m.{schema['conv']} = ? AND m.{schema['date']} BETWEEN ? AND ?
        ORDER BY m.{schema['date']} ASC;
        """
    else:
        print(
            "⚠️ No attachments table found (looked for names containing 'attach'). "
            "Proceeding without attachments."
        )
        query = f"""
        SELECT m.{schema['date']} AS date,
               m.{schema['body']} AS body,
               NULL AS attachment_path,
               NULL AS contentType,
               NULL AS fileKey,
               {direction_expr}
        FROM {schema['table']} AS m
        WHERE m.{schema['conv']} = ? AND m.{schema['date']} BETWEEN ? AND ?
        ORDER BY m.{schema['date']} ASC;
        """

    try:
        cur.execute(query, (conversation_id, start_ts, end_ts))
    except sqlite3.DatabaseError as exc:
        fail(
            "Database query failed. Ensure the database is a valid Signal DB and "
            f"the conversation id '{conversation_id}' exists. Original error: {exc}"
        )
    rows = cur.fetchall()
    master_key = bytes.fromhex(key_hex)

    if not rows:
        conn.close()
        print(
            "⚠️ No messages found for the selected conversation and date range."
        )
        return False

    # Initialize PDF document with Unicode support
    pdf = PDF()
    if hasattr(pdf, "core_fonts_encoding"):
        pdf.core_fonts_encoding = "utf-8"
    elif hasattr(pdf, "set_doc_option"):
        pdf.set_doc_option("core_fonts_encoding", "utf-8")
    font_path = Path(__file__).parent / "dejavu-sans" / "DejaVuSans.ttf"
    ensure_font(font_path)
    pdf.add_font("DejaVuSans", "", str(font_path))
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("DejaVuSans", size=12)

    missing_attachments: List[str] = []
    messages: List[dict] = []

    for date_ms, body, attachment_path, mime, enc_key, sender_flag in rows:
        if attachment_path and mime and mime.startswith("image"):
            logger.info(
                "DB image metadata: path=%s mime=%s key=%s",
                attachment_path,
                mime,
                _format_enc_key(enc_key),
            )
        date_str = datetime.fromtimestamp(date_ms / 1000).strftime(
            "%Y-%m-%d %H:%M"
        )

        resolved_path = (
            resolve_attachment_path(attachment_path, attachments_dir)
            if attachment_path
            else None
        )

        if attachment_path:
            logger.info("Processing attachment %s", attachment_path)
        if resolved_path:
            logger.info("Resolved attachment to %s", resolved_path)
            if os.path.exists(resolved_path):
                logger.info("File %s exists", resolved_path)
                if os.access(resolved_path, os.R_OK):
                    logger.info("File %s is readable", resolved_path)
                else:
                    logger.warning("File %s is not readable", resolved_path)
            else:
                logger.warning("Resolved path %s does not exist", resolved_path)
                resolved_path = None
        elif attachment_path:
            logger.warning("Attachment %s could not be resolved", attachment_path)

        file_key: Optional[bytes] = None
        if enc_key:
            logger.info("Attachment %s appears encrypted", attachment_path)
            try:
                if isinstance(enc_key, (bytes, bytearray, memoryview)):
                    enc_bytes = bytes(enc_key)
                else:
                    enc_bytes = bytes.fromhex(str(enc_key))
                file_key = _decrypt_file_key(enc_bytes, master_key)
                logger.info("Decrypted file key for %s", attachment_path)
            except Exception as exc:
                logger.warning(
                    "Failed to derive file key for %s: %s", attachment_path, exc
                )
        else:
            logger.info("Attachment %s is not encrypted", attachment_path)

        if resolved_path and file_key:
            decrypted = _decrypt_attachment(resolved_path, file_key)
            if decrypted:
                logger.info("Decryption succeeded for %s", resolved_path)
                resolved_path = decrypted
            else:
                logger.warning("Decryption failed for %s", resolved_path)
                missing_attachments.append(f"{attachment_path} (decrypt error)")
                resolved_path = None
        elif resolved_path:
            images_dir = Path("images")
            images_dir.mkdir(exist_ok=True)
            dest = images_dir / Path(resolved_path).name
            try:
                shutil.copy(resolved_path, dest)
                logger.info("Copied %s to %s", resolved_path, dest)
                resolved_path = str(dest)
            except OSError as exc:
                logger.warning(
                    "Failed to copy %s to %s: %s", resolved_path, dest, exc
                )
                missing_attachments.append(f"{attachment_path} (copy error)")
                resolved_path = None

        if resolved_path and not mime:
            mime = detect_mime_type(resolved_path)

        if resolved_path and mime and mime.startswith("text"):
            try:
                text_content = Path(resolved_path).read_text(
                    encoding="utf-8", errors="replace"
                )
                body = (body + "\n" + text_content) if body else text_content
            except OSError:
                missing_attachments.append(f"{attachment_path} (read error)")
            resolved_path = None
        elif attachment_path and not resolved_path:
            missing_attachments.append(f"{attachment_path} (not found)")

        if not body and not resolved_path:
            body = "Nachricht wurde gelöscht"

        text = Markup((body or "").replace("\n", "<br>"))
        sender = SELF_LABEL if is_outgoing(sender_flag) else conversation_label
        attachment_name = Path(resolved_path).name if resolved_path else None

        messages.append(
            {
                "date": date_str,
                "sender": sender,
                "text": text,
                "attachment": resolved_path,
                "attachment_name": attachment_name,
                "mime": mime,
            }
        )

    template_file = Path(template_path) if template_path else Path(__file__).parent / "template.html"
    env = Environment(
        loader=FileSystemLoader(str(template_file.parent), encoding="utf-8"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_file.name)
    html = template.render(conversation_label=conversation_label, messages=messages)
    html = inline_css(html, template_file.parent)
    html = rewrite_img_srcs_in_html(html)
    html = _ensure_latin1(html)
    pdf._tmp_images.extend(_REWRITE_TMP_IMAGES)
    pdf.write_html(html)
    pdf.output(output_pdf)
    pdf.cleanup()

    if missing_attachments:
        print("⚠️ Some image attachments could not be embedded:")
        for msg in missing_attachments:
            print(f"   - {msg}")
    conn.close()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Signal chat to PDF")
    parser.add_argument("--db", help="Path to Signal SQLite DB")
    parser.add_argument(
        "--conversation",
        help="Conversation identifier as listed in the 'conversations' table",
    )
    parser.add_argument("--start", help="Start date YYYY-MM-DD")
    parser.add_argument("--end", help="End date YYYY-MM-DD")
    parser.add_argument("--output", help="Path to the output PDF file")
    parser.add_argument("--template", help="Path to HTML template for styling")
    parser.add_argument(
        "--attachments",
        help="Additional directory to search for attachments",
    )

    args = parser.parse_args()

    config = load_config()

    db_prompt = f"Path to Signal SQLite DB [{config.get('db_path', '')}]: "
    db_path = args.db or input(db_prompt).strip() or config.get("db_path")
    if not db_path:
        fail("Path to Signal SQLite DB is required.")
    confirm_db_connection(db_path, DB_KEY_HEX)

    conversations = list_conversations(db_path, DB_KEY_HEX)
    conv_lookup = {cid: label for cid, label in conversations}

    while True:
        if args.conversation:
            conversation_id = args.conversation
            conversation_label = conv_lookup.get(conversation_id, conversation_id)
        else:
            print("Available conversations:")
            for idx, (cid, label) in enumerate(conversations, 1):
                display = f"{label} ({cid})" if label != cid else cid
                print(f"{idx}: {display}")
            prev_id = config.get("conversation_id")
            default_idx = next(
                (i for i, (cid, _label) in enumerate(conversations, 1) if cid == prev_id),
                None,
            )
            while True:
                prompt = "Select conversation number"
                if default_idx:
                    prompt += f" [{default_idx}]"
                choice = input(prompt + ": ").strip()
                if not choice and default_idx:
                    conversation_id = conversations[default_idx - 1][0]
                    break
                if choice.isdigit() and 1 <= int(choice) <= len(conversations):
                    conversation_id = conversations[int(choice) - 1][0]
                    break
                print("Please enter a valid number.")
            conversation_label = conv_lookup.get(conversation_id, conversation_id)

        if args.start and args.end:
            start_date, end_date = args.start, args.end
        else:
            start_default = config.get("start_date", "")
            end_default = config.get("end_date", "")
            while True:
                prompt = "Date range (YYYY-MM-DD YYYY-MM-DD)"
                if start_default and end_default:
                    prompt += f" [{start_default} {end_default}]"
                raw = input(prompt + ": ").strip()
                if not raw and start_default and end_default:
                    start_date, end_date = start_default, end_default
                    break
                date_range = raw.split()
                if len(date_range) == 2:
                    start_date, end_date = date_range
                    try:
                        datetime.strptime(start_date, "%Y-%m-%d")
                        datetime.strptime(end_date, "%Y-%m-%d")
                        break
                    except ValueError:
                        pass
                print("Please provide valid dates separated by space.")

        suggested_output = config.get(
            "output_pdf", f"chat_{start_date}_{end_date}.pdf"
        )
        output_pdf = (
            args.output
            or input(f"Output PDF filename [{suggested_output}]: ").strip()
            or suggested_output
        )

        if export_chat(
            db_path,
            conversation_id,
            conversation_label,
            start_date,
            end_date,
            output_pdf,
            DB_KEY_HEX,
            args.template,
            args.attachments,
        ):
            config.update(
                {
                    "db_path": db_path,
                    "conversation_id": conversation_id,
                    "conversation_label": conversation_label,
                    "start_date": start_date,
                    "end_date": end_date,
                    "output_pdf": output_pdf,
                }
            )
            save_config(config)
            break

        print("Please choose a different conversation or date range.")
        args.conversation = args.start = args.end = args.output = None
