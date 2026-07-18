# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a single windowed NoMorePwn.exe.

    pyinstaller build/NoMorePwn.spec        (run from the repo root)

Produces dist/NoMorePwn.exe: a portable, no-console tray app with the
brand icon. zxcvbn word lists, certifi's CA bundle, and the argon2 cffi
backend are bundled explicitly so the frozen app behaves like source.
"""

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.getcwd())

hiddenimports = ["_cffi_backend"]
hiddenimports += collect_submodules("zxcvbn")

datas = []
datas += collect_data_files("zxcvbn")
datas += collect_data_files("certifi")

excludes = [
    "tkinter",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.Qt3DCore",
    "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDesigner", "PySide6.QtHelp",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtPositioning",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtStateMachine", "PySide6.QtTextToSpeech",
    "PySide6.QtSpatialAudio",
    "matplotlib", "numpy", "scipy", "pandas", "PIL", "streamlit",
]

a = Analysis(
    [os.path.join(ROOT, "NoMorePwn.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NoMorePwn",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, "assets", "NoMorePwn.ico"),
)
