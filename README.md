# signaltobook

A simple Python utility that exports messages from a Signal SQLite
Database to a formatted PDF document. It can include image attachments
and filter the exported conversation by a date range.

## Usage

```
python export_signal_pdf.py --db path/to/signal.db \
                            --recipient "+4912345678" \
                            --start 2020-12-01 \
                            --end 2020-12-24 \
                            --output chat.pdf
```

The script uses the standard `sqlite3` module and the `fpdf` package for
PDF creation.

