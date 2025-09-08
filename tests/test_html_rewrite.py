import sys
import types

from PIL import Image

import export_signal_pdf


def test_rewrite_img_srcs_uses_wand_on_pillow_error(monkeypatch, tmp_path):
    src = tmp_path / "image.webp"
    Image.new("RGB", (1, 1)).save(src, format="PNG")

    def fail_open(*_, **__):
        raise OSError("fail")

    monkeypatch.setattr(export_signal_pdf.Image, "open", fail_open)

    class DummyWandImage:
        def __init__(self, filename: str):
            self.filename = filename
            self.format = "WEBP"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def save(self, filename: str):
            Image.new("RGB", (1, 1)).save(filename, format="PNG")

    dummy = types.SimpleNamespace(Image=DummyWandImage)
    monkeypatch.setitem(sys.modules, "wand", types.SimpleNamespace(image=dummy))
    monkeypatch.setitem(sys.modules, "wand.image", dummy)

    html = f'<img src="{src}">'  # noqa: B950
    out = export_signal_pdf.rewrite_img_srcs_in_html(html)
    assert "Unsupported image" not in out
    assert str(src) not in out
    assert export_signal_pdf._REWRITE_TMP_IMAGES
