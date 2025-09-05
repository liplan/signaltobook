#!/usr/bin/env python3
"""
Export Signal messages with a single contact to a PDF file.

The script expects a Signal SQLite database (e.g. the `signal.db` from
Signal Desktop or Android).  It exports all messages exchanged with a
specific contact and optionally embeds image attachments.  Messages are
filtered by a date range, for example from 1 December 2020 to
24 December 2020.

Usage:
    python export_signal_pdf.py --db path/to/signal.db \
                                --recipient "+4912345678" \
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
import sqlite3
from datetime import datetime
from pathlib import Path

from fpdf import FPDF


def export_chat(db_path: str, recipient: str, start_date: str,
                end_date: str, output_pdf: str) -> None:
    """Export messages with ``recipient`` between ``start_date`` and
    ``end_date`` to ``output_pdf``.

    Parameters
    ----------
    db_path: str
        Path to the Signal SQLite database.
    recipient: str
        Phone number or unique identifier of the contact.
    start_date: str
        Start of the period (``YYYY-MM-DD``).
    end_date: str
        End of the period (``YYYY-MM-DD``).
    output_pdf: str
        Path to the generated PDF file.
    """

    conn = sqlite3.connect(db_path)
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
        WHERE m.address = ? AND m.date BETWEEN ? AND ?
        ORDER BY m.date ASC;
        """
    )

    cur.execute(query, (recipient, start_ts, end_ts))
    rows = cur.fetchall()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    for date_ms, body, attachment_path, mime in rows:
        date_str = datetime.fromtimestamp(date_ms / 1000).strftime(
            "%Y-%m-%d %H:%M"
        )
        text = body or ""
        pdf.multi_cell(0, 10, f"{date_str}: {text}")
        if (
            attachment_path
            and mime
            and mime.startswith("image")
            and os.path.exists(attachment_path)
        ):
            pdf.image(attachment_path, w=100)
            pdf.ln()
        pdf.ln()

    pdf.output(output_pdf)
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Signal chat to PDF")
    parser.add_argument("--db", help="Path to Signal SQLite DB")
    parser.add_argument("--recipient", help="Phone number or contact identifier")
    parser.add_argument("--start", help="Start date YYYY-MM-DD")
    parser.add_argument("--end", help="End date YYYY-MM-DD")
    parser.add_argument("--output", help="Path to the output PDF file")

    args = parser.parse_args()

    config_file = Path.home() / ".signaltobook_config.json"

    def load_config():
        try:
            with open(config_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_config(cfg):
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)

    cfg = load_config()

    db_path = (
        args.db
        or input(f"Path to Signal SQLite DB [{cfg.get('db_path', '')}]: ").strip()
        or cfg.get("db_path")
    )

    recipient = args.recipient or input("Recipient identifier: ").strip()

    if args.start and args.end:
        start_date, end_date = args.start, args.end
    else:
        while True:
            date_range = input("Date range (YYYY-MM-DD YYYY-MM-DD): ").split()
            if len(date_range) == 2:
                start_date, end_date = date_range
                try:
                    datetime.strptime(start_date, "%Y-%m-%d")
                    datetime.strptime(end_date, "%Y-%m-%d")
                    break
                except ValueError:
                    pass
            print("Please provide valid dates separated by space.")

    output_pdf = (
        args.output or input("Output PDF filename [chat.pdf]: ").strip() or "chat.pdf"
    )

    save_config({**cfg, "db_path": db_path})

    export_chat(db_path, recipient, start_date, end_date, output_pdf)
