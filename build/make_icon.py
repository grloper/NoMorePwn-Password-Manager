"""Generate assets/NoMorePwn.ico from the in-app vector logo.

Run once (and whenever the brand mark changes):

    python build/make_icon.py

Requires Pillow and PySide6 (build-time only). The resulting multi-size
.ico is committed and used by PyInstaller and the Inno Setup installer.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QBuffer, QByteArray  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
from PIL import Image  # noqa: E402


def qimage_to_pil(qimg) -> Image.Image:
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QBuffer.WriteOnly)
    qimg.save(buf, "PNG")
    buf.close()
    return Image.open(io.BytesIO(bytes(ba))).convert("RGBA")


def main() -> int:
    app = QApplication([])  # noqa: F841 - needed for QPixmap rendering
    from nomorepwn_app import theme, icons

    theme.set_active(theme.get_palette("dark"))

    base = icons.logo_pixmap(256).toImage()
    pil = qimage_to_pil(base)

    out_dir = ROOT / "assets"
    out_dir.mkdir(parents=True, exist_ok=True)
    ico_path = out_dir / "NoMorePwn.ico"
    png_path = out_dir / "NoMorePwn.png"

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    pil.save(ico_path, format="ICO", sizes=sizes)
    pil.save(png_path, format="PNG")
    print(f"Wrote {ico_path} ({ico_path.stat().st_size} bytes)")
    print(f"Wrote {png_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
