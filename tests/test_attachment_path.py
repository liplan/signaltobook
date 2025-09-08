from export_signal_pdf import resolve_attachment_path


def test_resolve_attachment_path_strips_whitespace(tmp_path):
    img = tmp_path / "image.png"
    img.write_text("data")
    result = resolve_attachment_path(str(img) + " \n")
    assert result == str(img)

