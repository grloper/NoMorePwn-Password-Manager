"""Application bootstrap: single-instance guard, then hand off to the controller."""

from __future__ import annotations

import getpass
import json
import sys

from PySide6.QtCore import QTimer
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from nomorepwn import ipc_auth

from . import APP_DISPLAY_NAME, APP_NAME, ORG_NAME, __version__, icons


def _server_name() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "default"
    return f"NoMorePwn-instance-{user}"


def _already_running_then_show() -> bool:
    """If another instance owns the lock, ask it to show itself and return True."""
    sock = QLocalSocket()
    sock.connectToServer(_server_name())
    if sock.waitForConnected(300):
        token = ipc_auth.read_token()
        if token is None:
            # Cannot authenticate (no token yet); still treat the running
            # instance as the owner of the lock and do not start a second one.
            sock.disconnectFromServer()
            return True
        sock.write(json.dumps({"type": "show", "token": token}).encode("utf-8"))
        sock.flush()
        sock.waitForBytesWritten(300)
        sock.disconnectFromServer()
        return True
    return False


def main() -> int:
    start_hidden = "--tray" in sys.argv

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(False)  # tray app: closing the window keeps us alive
    app.setWindowIcon(icons.app_icon())

    # Single instance: if one is already running, surface it and exit.
    if _already_running_then_show():
        return 0

    from .controller import AppController  # imported after QApplication exists

    controller = AppController(app)

    # Listen for future launches asking us to show the window.
    # Ensure the per-install token exists before accepting connections, and
    # restrict the socket to the current user.
    ipc_auth.load_or_create_token()
    QLocalServer.removeServer(_server_name())
    server = QLocalServer()
    server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    server.listen(_server_name())

    def _on_new_connection():
        conn = server.nextPendingConnection()
        if conn is not None:
            def handle_ready_read():
                data = conn.readAll().data()
                response = controller.handle_ipc_message(data)
                if response:
                    conn.write(response)
                    conn.flush()
                    conn.waitForBytesWritten(1000)
                conn.disconnectFromServer()
            conn.readyRead.connect(handle_ready_read)
            QTimer.singleShot(4000, conn.deleteLater)

    server.newConnection.connect(_on_new_connection)

    controller.start(start_hidden=start_hidden)
    exit_code = app.exec()
    server.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
