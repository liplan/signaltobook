# signaltobook

A simple Python utility that exports messages from a Signal SQLite
Database to a formatted PDF document. It can include image attachments
and filter the exported conversation by a date range.

## Usage

```
python export_signal_pdf.py --db path/to/signal.db \
                            --config path/to/config.json \
                            --recipient "+4912345678" \
                            --start 2020-12-01 \
                            --end 2020-12-24 \
                            --output chat.pdf
```

The script uses the standard `sqlite3` module and the `fpdf` package for
PDF creation. If the database is encrypted, provide the accompanying
`config.json` so the script can unlock it. The configuration file may
either contain a base64 encoded `key` field or an `encryptedKey` field
with the key already encoded as hex.

## Interactive mode

When run without command line arguments the script will prompt for the
database path and the Signal `config.json` file. It then reads all
recipients from the database and lets you choose which conversation to
export. After selecting the date range the values are stored in
`~/.signaltobook_config.json` and offered as defaults on subsequent
runs. The output PDF name is derived from the selected date range
(e.g. `chat_2020-12-01_2020-12-24.pdf`).

