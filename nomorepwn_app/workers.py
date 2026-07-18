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


def run_async(
    fn: Callable[..., Any],
    on_done: Callable[[Any], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
    *args,
    **kwargs,
) -> Task:
    """Run ``fn`` on the global thread pool; deliver result on the GUI thread."""
    task = Task(fn, *args, **kwargs)
    if on_done:
        task.signals.done.connect(on_done)
    if on_error:
        task.signals.failed.connect(on_error)
    QThreadPool.globalInstance().start(task)
    return task
