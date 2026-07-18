import sys

if "--native-host" in sys.argv:
    # Dispatch before importing .app, which pulls in Qt. Anything written to
    # stdout would corrupt the native-messaging frame stream.
    from .native_host import run

    sys.exit(run())

from .app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
