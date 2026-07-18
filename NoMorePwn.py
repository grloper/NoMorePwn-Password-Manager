#!/usr/bin/env python
"""Launch the NoMorePwn desktop app.

    python NoMorePwn.py          # open the window
    python NoMorePwn.py --tray   # start hidden in the system tray (locked)

This is also the entry point PyInstaller bundles into NoMorePwn.exe, which is
why it also handles --native-host: the browser launches the packaged .exe
directly when the extension connects.
"""

import sys

if "--native-host" in sys.argv:
    # Before importing the app: that pulls in Qt, and stray stdout output
    # would corrupt the native-messaging frame stream.
    from nomorepwn_app.native_host import run

    sys.exit(run())

from nomorepwn_app.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
