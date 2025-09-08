import re
from export_signal_pdf import inline_css


def test_inline_css_handles_multiple_classes():
    html = """
    <html><head><style>
    .meta { color: #555; }
    .date { font-size: 10px; }
    .meta.date { font-weight: bold; }
    </style></head><body>
    <div class="meta date">Hello</div>
    </body></html>
    """
    out = inline_css(html)
    match = re.search(r'style="([^"]+)"', out)
    assert match, out
    styles = match.group(1).replace(" ", "")
    assert "color:#555" in styles
    assert "font-size:10px" in styles
    assert "font-weight:bold" in styles
