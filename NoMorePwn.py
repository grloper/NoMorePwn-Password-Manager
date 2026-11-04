#!/usr/bin/env python
"""Launch the NoMorePwn desktop app.

    python NoMorePwn.py          # open the window
    python NoMorePwn.py --tray   # start hidden in the system tray (locked)
"""

import sys

from nomorepwn_app.app import main

if __name__ == "__main__":
    sys.exit(main())
