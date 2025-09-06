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

To obtain the hex-encoded key from ``config.json`` (useful for DB Browser's
"Hex-Key" option) run:

```
python export_signal_pdf.py --config path/to/config.json --print-hex-key
```

The script relies on SQLCipher-enabled Python bindings such as
[`pysqlcipher3`](https://pypi.org/project/pysqlcipher3/) or
[`sqlcipher3`](https://pypi.org/project/sqlcipher3/) together with the
`fpdf` package for PDF creation. Unencrypted Signal databases can be
opened directly, while encrypted ones require the accompanying
`config.json` so the script can unlock them. The configuration file may
either contain a base64 encoded `key` field or an `encryptedKey` field
with the key already encoded as hex.

If the `encryptedKey` is itself encrypted, a dedicated tool may be
required to obtain the usable key. One approach is to compile and run a
community Rust utility (available on GitHub) which produces a decrypted
key via the `signal-descriptions` binary in its `target` directory. This
can be useful when shell based methods fail to decode the `encryptedKey`.

## Interactive mode

When run without command line arguments the script will prompt for the
database path and the Signal `config.json` file. It then reads all
recipients from the database and lets you choose which conversation to
export. After selecting the date range the values are stored in
`~/.signaltobook_config.json` and offered as defaults on subsequent
runs. The output PDF name is derived from the selected date range
(e.g. `chat_2020-12-01_2020-12-24.pdf`).

