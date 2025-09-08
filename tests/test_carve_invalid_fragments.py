from signal_attachment_decrypt import (
    _carve_jpegs,
    _carve_pngs,
    _carve_gifs,
    _carve_webp,
    _carve_mp4,
)


def test_carve_jpeg_rejects_short(tmp_path):
    buf = b"\xff\xd8\xff\xd9"
    outs = _carve_jpegs(buf, tmp_path, "img")
    assert outs == []


def test_carve_png_rejects_short(tmp_path):
    buf = b"\x89PNG\r\n\x1a\nIEND"
    outs = _carve_pngs(buf, tmp_path, "img")
    assert outs == []


def test_carve_gif_rejects_short(tmp_path):
    buf = b"GIF89a\x3B"
    outs = _carve_gifs(buf, tmp_path, "img")
    assert outs == []


def test_carve_webp_rejects_short(tmp_path):
    buf = b"RIFF\x04\x00\x00\x00WEBP"
    outs = _carve_webp(buf, tmp_path, "img")
    assert outs == []


def test_carve_mp4_rejects_short(tmp_path):
    buf = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00iso2"
    outs = _carve_mp4(buf, tmp_path, "vid")
    assert outs == []
