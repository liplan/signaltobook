from export_signal_pdf import decode_image
from PIL import Image


def test_decode_image_adds_extension(tmp_path):
    img = Image.new('RGB', (1, 1), color='white')
    tmp_no_ext = tmp_path / 'sample'
    img.save(tmp_no_ext.with_suffix('.png'))
    (tmp_no_ext.with_suffix('.png')).rename(tmp_no_ext)
    result = decode_image(str(tmp_no_ext))
    expected = str(tmp_no_ext.with_suffix('.png'))
    assert result == expected
    assert tmp_no_ext.with_suffix('.png').exists()
    assert not tmp_no_ext.exists()


def test_decode_image_failure(tmp_path):
    bad = tmp_path / 'bad.jpg'
    bad.write_bytes(b'not an image')
    assert decode_image(str(bad)) is None
