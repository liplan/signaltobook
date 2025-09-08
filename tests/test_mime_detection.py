import os
import tempfile
from pathlib import Path

from PIL import Image
import wave
import pytest

from export_signal_pdf import detect_mime_type


def test_detect_mime_image():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        Image.new('RGB', (1, 1)).save(tmp.name, format='PNG')
        assert detect_mime_type(tmp.name) == 'image/png'
    finally:
        tmp.close()
        os.unlink(tmp.name)


def test_detect_mime_audio():
    tmp_path = Path(tempfile.gettempdir()) / 'tmp_audio'
    with wave.open(tmp_path, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(44100)
        w.writeframes(b'\x00' * 10)
    try:
        assert detect_mime_type(str(tmp_path)) == 'audio/wav'
    finally:
        os.unlink(tmp_path)


def test_detect_mime_webp():
    if 'WEBP' not in Image.MIME:
        pytest.skip('webp support missing')
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.webp')
    try:
        Image.new('RGB', (1, 1)).save(tmp.name, format='WEBP')
        assert detect_mime_type(tmp.name) == 'image/webp'
    finally:
        tmp.close()
        os.unlink(tmp.name)


def test_detect_mime_tiff():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.tiff')
    try:
        Image.new('RGB', (1, 1)).save(tmp.name, format='TIFF')
        assert detect_mime_type(tmp.name) == 'image/tiff'
    finally:
        tmp.close()
        os.unlink(tmp.name)
