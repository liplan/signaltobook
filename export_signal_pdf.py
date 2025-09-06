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
import os
from datetime import datetime
from pathlib import Path
from typing import List

try:
    from pysqlcipher3 import dbapi2 as sqlite3
except ImportError:  # pragma: no cover - fallback only used when pysqlcipher3 missing
    try:
        from sqlcipher3 import dbapi2 as sqlite3
    except ImportError:  # pragma: no cover - handled in open_db
        sqlite3 = None

from fpdf import FPDF


DB_KEY_HEX = "3e3d116a3066b05ccb893a2abefd93a6c6700ff4dbe25e17137edcd7ac7e7ef9"


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


def list_conversations(db_path: str, key_hex: str) -> List[str]:
    """Return sorted list of conversation identifiers from the database."""

    try:
        conn = open_db(db_path, key_hex)
    except SqlCipherError:
        fail(
            "Database is likely encrypted or requires SQLCipher support. "
            "Install SQLCipher-enabled Python bindings (e.g., pysqlcipher3)."
        )
    cur = conn.cursor()

    # Try to read the conversation identifiers. The primary key column can
    # vary between Signal versions (``id`` or ``_id``). We query whichever is
    # available. Only the identifier is returned to avoid exposing phone
    # numbers or other personal data.
    query = "SELECT id FROM conversations ORDER BY id;"
    try:
        cur.execute(query)
    except sqlite3.DatabaseError:
        query = "SELECT _id FROM conversations ORDER BY _id;"
        try:
            cur.execute(query)
        except sqlite3.DatabaseError as exc:
            conn.close()
            fail(f"Could not read conversations from database: {exc}")

    conversations = [str(row[0]) for row in cur.fetchall()]
    conn.close()
    if not conversations:
        fail("No conversations found in the database.")
    return conversations


def export_chat(
    db_path: str,
    conversation_id: str,
    start_date: str,
    end_date: str,
    output_pdf: str,
    key_hex: str,
) -> None:
    """Export messages from ``conversation_id`` between ``start_date`` and ``end_date``.

    Parameters
    ----------
    db_path: str
        Path to the Signal SQLite database.
    conversation_id: str
        Identifier of the conversation selected from the ``conversations`` table.
    start_date: str
        Start of the period (``YYYY-MM-DD``).
    end_date: str
        End of the period (``YYYY-MM-DD``).
    output_pdf: str
        Path to the generated PDF file.
    key_hex: str
        Database key in hex format.
    """

    try:
        conn = open_db(db_path, key_hex)
    except SqlCipherError as exc:
        fail(str(exc))
    cur = conn.cursor()

    start_ts = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1000)
    end_ts = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1000)

    query = (
        """
        SELECT m.date, m.body,
               COALESCE(a.filePath, a.fileName, a.path) AS attachment_path,
               a.contentType
        FROM messages AS m
        LEFT JOIN attachments AS a ON m._id = a.message_id
        WHERE m.conversationId = ? AND m.date BETWEEN ? AND ?
        ORDER BY m.date ASC;
        """
    )

    try:
        cur.execute(query, (conversation_id, start_ts, end_ts))
    except sqlite3.DatabaseError as exc:
        fail(
            "Database query failed. Ensure the database is a valid Signal DB and "
            f"the conversation id '{conversation_id}' exists. Original error: {exc}"
        )
    rows = cur.fetchall()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    missing_attachments: List[str] = []

    for date_ms, body, attachment_path, mime in rows:
        date_str = datetime.fromtimestamp(date_ms / 1000).strftime(
            "%Y-%m-%d %H:%M"
        )
        text = body or ""
        pdf.multi_cell(0, 10, f"{date_str}: {text}")
        if attachment_path and mime and mime.startswith("image"):
            if not os.path.exists(attachment_path):
                missing_attachments.append(f"{attachment_path} (not found)")
            elif check_readable(Path(attachment_path)):
                missing_attachments.append(
                    f"{attachment_path} (no read permission)"
                )
            else:
                pdf.image(attachment_path, w=100)
                pdf.ln()
        pdf.ln()

    pdf.output(output_pdf)
    if missing_attachments:
        print("⚠️ Some image attachments could not be embedded:")
        for msg in missing_attachments:
            print(f"   - {msg}")
    conn.close()


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

    args = parser.parse_args()

    db_path = args.db or input("Path to Signal SQLite DB: ").strip()
    confirm_db_connection(db_path, DB_KEY_HEX)

    if args.conversation:
        conversation_id = args.conversation
    else:
        conversations = list_conversations(db_path, DB_KEY_HEX)
        print("Available conversations:")
        for idx, cid in enumerate(conversations, 1):
            print(f"{idx}: {cid}")
        while True:
            choice = input("Select conversation number: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(conversations):
                conversation_id = conversations[int(choice) - 1]
                break
            print("Please enter a valid number.")

    if args.start and args.end:
        start_date, end_date = args.start, args.end
    else:
        while True:
            raw = input("Date range (YYYY-MM-DD YYYY-MM-DD): ").strip()
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

    default_output = f"chat_{start_date}_{end_date}.pdf"
    output_pdf = (
        args.output
        or input(f"Output PDF filename [{default_output}]: ").strip()
        or default_output
    )

    export_chat(
        db_path,
        conversation_id,
        start_date,
        end_date,
        output_pdf,
        DB_KEY_HEX,
    )
