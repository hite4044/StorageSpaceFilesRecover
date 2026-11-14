"""QThread 工作线程：把 engine 的回调桥接为 Qt 信号。"""
from __future__ import annotations

import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal  # type: ignore

ROOT = Path(__file__).resolve().parents[1]


class WorkerSignals(QObject):
    progress = Signal(object)          # Progress
    error = Signal(object)             # ErrorRecord
    message = Signal(str)
    finished = Signal(object)          # 结果对象
    failed = Signal(str)               # traceback


class ScanPoolWorker(QThread):
    signals = WorkerSignals()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = None

    def run(self):
        try:
            from ssrecover.engine import RecoveryEngine
            self.engine = RecoveryEngine(error_sink=lambda rec: self.signals.error.emit(rec))
            pool = self.engine.scan_local_pool(
                on_progress=lambda p: self.signals.progress.emit(p))
            self.engine._match_partitions(pool, self.engine.pool.virtual_disks[0]
                                          if self.engine.pool.virtual_disks else None) if False else None
            self.signals.finished.emit(pool)
        except Exception:
            self.signals.failed.emit(traceback.format_exc())


class OpenVolumeWorker(QThread):
    """扫池 + 打开卷（复用 ScanPoolWorker 结果亦可）。"""

    def __init__(self, engine, vd, part, parent=None):
        super().__init__(parent)
        self.signals = WorkerSignals()
        self.engine = engine
        self.vd = vd
        self.part = part

    def run(self):
        try:
            vol = self.engine.open_volume(self.vd, self.part)
            self.signals.finished.emit(vol)
        except Exception:
            self.signals.failed.emit(traceback.format_exc())


class ScanFsWorker(QThread):
    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.signals = WorkerSignals()
        self.engine = engine

    def run(self):
        try:
            entries, stats = self.engine.scan_filesystem(
                record_progress=lambda done, total:
                    self.signals.progress.emit({"done": done, "total": total}))
            self.signals.finished.emit({"entries": entries, "stats": stats})
        except Exception:
            self.signals.failed.emit(traceback.format_exc())


class ExportWorker(QThread):
    def __init__(self, engine, selection, cfg, parent=None):
        super().__init__(parent)
        self.signals = WorkerSignals()
        self.engine = engine
        self.selection = selection
        self.cfg = cfg
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        from ssrecover.virtualdisk import AbortExportError
        try:
            ok, fail, outputs = self.engine.export(
                self.selection, self.cfg,
                on_progress=lambda p: self.signals.progress.emit(p),
                cancel=lambda: self._cancel)
            self.signals.finished.emit({"ok": ok, "fail": fail, "outputs": outputs})
        except AbortExportError as e:
            self.signals.finished.emit({"aborted": True, "reason": str(e)})
        except Exception:
            self.signals.failed.emit(traceback.format_exc())
