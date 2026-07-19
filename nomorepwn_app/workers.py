"""Tiny background-task helper so the UI never blocks.

Argon2id key derivation (used on unlock/create) takes a noticeable
fraction of a second, and the HIBP breach check does network I/O. Both
run on a :class:`QThreadPool` worker and report back to the GUI thread
via signals.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot


class _Signals(QObject):
    done = Signal(object)      # result
    failed = Signal(Exception)


class Task(QRunnable):
    def __init__(self, fn: Callable[..., Any], *args, **kwargs):
        super().__init__()
        # Qt would delete the C++ half the moment run() returns, while Python
        # may still hold the wrapper. Own the lifetime on the Python side
        # instead — see the keep-alive set below.
        self.setAutoDelete(False)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = _Signals()

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.signals.failed.emit(exc)
        else:
            self.signals.done.emit(result)


# In-flight tasks, held so Python cannot collect them mid-run.
#
# Callers almost never keep the returned Task — `workers.run_async(work, done)`
# reads like fire-and-forget. Without this set it *is*: the Task and its
# `_Signals` QObject become unreachable the moment run_async returns, and if a
# collection happens before the worker finishes, the `done`/`failed` signal has
# nowhere to go. The callback silently never runs, and the work itself can be
# cut short. That is how the breach scan came to sit at "Scanning… 17/17"
# forever, reporting nothing — a security check that looks like it ran.
#
# It is a race, so it hides in short tasks and bites the long ones.
_INFLIGHT: set[Task] = set()


def run_async(
    fn: Callable[..., Any],
    on_done: Callable[[Any], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
    *args,
    **kwargs,
) -> Task:
    """Run ``fn`` on the global thread pool; deliver result on the GUI thread.

    The returned Task does not need to be kept alive by the caller.
    """
    task = Task(fn, *args, **kwargs)
    if on_done:
        task.signals.done.connect(on_done)
    if on_error:
        task.signals.failed.connect(on_error)

    # Retire last, so the caller's callbacks have already run.
    def _retire(_result: Any = None) -> None:
        _INFLIGHT.discard(task)

    task.signals.done.connect(_retire)
    task.signals.failed.connect(_retire)

    _INFLIGHT.add(task)
    QThreadPool.globalInstance().start(task)
    return task
