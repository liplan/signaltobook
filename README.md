# signaltobook

A simple Python utility that exports messages from a Signal SQLite
Database to a formatted PDF document. It can include image attachments
and filter the exported conversation by a date range. Forwarded messages
and other text-based attachments are included, and attachment paths are
resolved across common Signal storage locations.
Encrypted attachments are detected and transparently decrypted using the
file keys stored in the database so that embedded images appear in the
final PDF.
Unencrypted attachments are copied into an `images/` directory so that
they can be referenced by the HTML template. These copies are retained
after the PDF is generated.

## Usage

```
python export_signal_pdf.py --db path/to/signal.db \
                            --conversation 1 \
                            --start 2020-12-01 \
                            --end 2020-12-24 \
                            --output chat.pdf
```

The script relies on SQLCipher-enabled Python bindings such as
[`pysqlcipher3`](https://pypi.org/project/pysqlcipher3/) or
[`sqlcipher3`](https://pypi.org/project/sqlcipher3/) together with the
`fpdf2` package for PDF creation. Unencrypted Signal databases can be
opened directly, while encrypted ones require the associated SQLCipher
key to access their contents. To render Unicode characters the script
uses the `DejaVuSans` TrueType font bundled in the repository under
`dejavu-sans/DejaVuSans.ttf`.

## Styling with templates

The PDF layout can be customized using an HTML template rendered via
`Jinja2` and converted to PDF with `fpdf2`'s HTML capabilities. Edit the
provided `template.html` or supply your own template file using the
`--template` command-line option to adjust fonts, colors, or other layout
details. Styles from `<style>` blocks and linked stylesheets are now inlined
using [`premailer`](https://pypi.org/project/premailer/), which supports a
broader range of CSS selectors (e.g. combined classes or descendant
selectors) so that template changes are reflected in the generated PDF.

If the `encryptedKey` is itself encrypted, a dedicated tool may be
required to obtain the usable key. One approach is to compile and run a
community Rust utility (available on GitHub) which produces a decrypted
key via the `signal-descriptions` binary in its `target` directory. This
can be useful when shell based methods fail to decode the `encryptedKey`.

## Interactive mode

When run without command line arguments the script will prompt for the
database path. It reads all conversation identifiers from the database and
shows available recipients with known names or phone numbers to choose from.
After selecting the date range the values are stored in
`~/.signaltobook_config.json` and offered as defaults on subsequent runs. The
output PDF name is derived from the selected date range (e.g.
`chat_2020-12-01_2020-12-24.pdf`).

