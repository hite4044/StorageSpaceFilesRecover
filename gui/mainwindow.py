"""主窗口：四页向导（选择分区 → 文件结构 → 参数 → 导出）。"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from PySide6.QtCore import Qt  # type: ignore
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout,  # type: ignore
                               QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QPushButton, QSpinBox,
                               QStackedWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget, QMessageBox)

from gui.widgets import DualProgressWidget, ErrorTableWidget, FileTreeWidget, fmt_size
from gui.workers import ExportWorker, OpenVolumeWorker, ScanFsWorker, ScanPoolWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("存储空间已删除文件恢复 — Storage Space Files Recover")
        self.resize(1080, 720)
        self.engine = None
        self.pool = None
        self.volume = None
        self.entries = []
        self.stats = None
        self.error_records = []
        self.export_worker = None

        central = QWidget()
        lay = QVBoxLayout(central)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack)
        nav = QHBoxLayout()
        self.btn_prev = QPushButton("上一步")
        self.btn_next = QPushButton("下一步")
        nav.addWidget(self.btn_prev)
        nav.addStretch(1)
        nav.addWidget(self.btn_next)
        lay.addLayout(nav)
        self.setCentralWidget(central)

        self.page0 = self._page_select()
        self.page1 = self._page_scan()
        self.page2 = self._page_params()
        self.page3 = self._page_export()
        for pg in (self.page0, self.page1, self.page2, self.page3):
            self.stack.addWidget(pg["widget"])
        self.btn_prev.clicked.connect(self._prev)
        self.btn_next.clicked.connect(self._next)
        self._sync_nav()

    # ------------------------------------------------ 页面构建

    def _page_select(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        tip = QLabel("第 1 页 / 4 —— 扫描存储池并选择要恢复的分区（需管理员权限）")
        f = tip.font(); f.setBold(True); tip.setFont(f)
        lay.addWidget(tip)
        self.btn_scan_pool = QPushButton("扫描存储池")
        lay.addWidget(self.btn_scan_pool)
        self.pool_info = QTextEdit()
        self.pool_info.setReadOnly(True)
        self.pool_info.setMaximumHeight(160)
        lay.addWidget(self.pool_info)
        self.part_list = QListWidget()
        lay.addWidget(self.part_list)
        self.lbl_scan_status = QLabel("")
        lay.addWidget(self.lbl_scan_status)
        self.btn_scan_pool.clicked.connect(self._on_scan_pool)
        return {"widget": w}

    def _page_scan(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        tip = QLabel("第 2 页 / 4 —— 扫描文件结构（$MFT 解析，含已删除条目）")
        f = tip.font(); f.setBold(True); tip.setFont(f)
        lay.addWidget(tip)
        self.lbl_fs_status = QLabel("未开始")
        lay.addWidget(self.lbl_fs_status)
        self.file_tree = FileTreeWidget()
        lay.addWidget(self.file_tree, 1)
        self.lbl_fs_stats = QLabel("")
        lay.addWidget(self.lbl_fs_stats)
        return {"widget": w}

    def _page_params(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        tip = QLabel("第 3 页 / 4 —— 勾选要恢复的文件/文件夹、设置保存路径与参数")
        f = tip.font(); f.setBold(True); tip.setFont(f)
        lay.addWidget(tip)
        self.lbl_sel_stats = QLabel("")
        lay.addWidget(self.lbl_sel_stats)
        form = QFormLayout()
        self.ed_dest = QLineEdit("D:\\Recovery_R")
        btn_browse = QPushButton("浏览…")
        hb = QHBoxLayout()
        hb.addWidget(self.ed_dest, 1)
        hb.addWidget(btn_browse)
        form.addRow("保存路径", hb)
        self.sp_chunk = QSpinBox(); self.sp_chunk.setRange(1, 64); self.sp_chunk.setValue(4)
        form.addRow("读取块大小 (MB)", self.sp_chunk)
        self.sp_retry = QSpinBox(); self.sp_retry.setRange(0, 10); self.sp_retry.setValue(3)
        form.addRow("物理读重试次数", self.sp_retry)
        self.cb_deleted = QCheckBox("导出已删除文件"); self.cb_deleted.setChecked(True)
        self.cb_live = QCheckBox("导出现存文件"); self.cb_live.setChecked(False)
        self.cb_xorr = QCheckBox("遇读失败尝试 XOR 校验重建")
        self.cb_xorr.setChecked(True)
        self.cb_zerochk = QCheckBox("检测全零区域（记录可疑位置）")
        self.cb_zerochk.setChecked(True)
        for c in (self.cb_deleted, self.cb_live, self.cb_xorr, self.cb_zerochk):
            form.addRow("", c)
        lay.addLayout(form)
        self.lbl_est = QLabel("")
        lay.addWidget(self.lbl_est)
        btn_browse.clicked.connect(self._browse_dest)
        self.file_tree.itemChanged.connect(self._on_selection_changed)
        return {"widget": w}

    def _page_export(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        tip = QLabel("第 4 页 / 4 —— 导出进度与错误明细")
        f = tip.font(); f.setBold(True); tip.setFont(f)
        lay.addWidget(tip)
        self.dual = DualProgressWidget()
        lay.addWidget(self.dual)
        self.error_widget = ErrorTableWidget()
        lay.addWidget(self.error_widget, 1)
        hb = QHBoxLayout()
        self.btn_cancel = QPushButton("中止导出")
        self.btn_csv = QPushButton("错误导出 CSV")
        self.btn_csv.setEnabled(False)
        hb.addWidget(self.btn_cancel)
        hb.addWidget(self.btn_csv)
        hb.addStretch(1)
        lay.addLayout(hb)
        self.btn_cancel.clicked.connect(self._cancel_export)
        self.btn_csv.clicked.connect(self._export_csv)
        return {"widget": w}

    # ------------------------------------------------ 导航

    def _sync_nav(self):
        i = self.stack.currentIndex()
        self.btn_prev.setEnabled(i > 0)
        self.btn_next.setEnabled(i < 3)

    def _prev(self):
        i = self.stack.currentIndex()
        if i > 0:
            self.stack.setCurrentIndex(i - 1)
        self._sync_nav()

    def _next(self):
        i = self.stack.currentIndex()
        if i == 0:
            self._start_open_volume()
            return
        if i == 1:
            self.stack.setCurrentIndex(2)
            self._update_sel_stats()
            self._sync_nav()
            return
        if i == 2:
            self._start_export()
            return

    # ------------------------------------------------ 页1：扫池

    def _on_scan_pool(self):
        self.btn_scan_pool.setEnabled(False)
        self.lbl_scan_status.setText("扫描中…")
        self._pool_worker = ScanPoolWorker()
        self._pool_worker.signals.finished.connect(self._pool_scanned)
        self._pool_worker.signals.failed.connect(
            lambda tb: (self.lbl_scan_status.setText("失败"), QMessageBox.critical(self, "扫描失败", tb)))
        self._pool_worker.start()

    def _pool_scanned(self, pool):
        self.engine = self._pool_worker.engine
        self.pool = pool
        self.btn_scan_pool.setEnabled(True)
        vd = next((v for v in pool.virtual_disks if v.windows_vd_number is not None), None)
        self.part_list.clear()
        for i, p in enumerate(self.engine.partitions):
            self.part_list.addItem(
                f"[{i}] @{p.offset_vd:#x} {fmt_size(p.size)} 盘符={p.drive_letter or '-'}")
        if vd is not None:
            self.pool_info.setPlainText(
                f"池 {pool.pool_uuid.hex().upper()} 名称 {pool.windows_pool_name!r}\n"
                f"空间 {vd.name!r}: {vd.mode} {vd.ncols} 列 parity={vd.parity_cols}\n"
                f"组 {len(vd.groups)} 行 {vd.rows} 容量 {fmt_size(vd.raw_vd_size)}\n"
                + "\n".join(f"盘#{d.disk_id} {d.name} → {d.device_path or '未挂载'}"
                            for d in pool.disks))
        self.lbl_scan_status.setText("扫描完成，选择分区后点下一步")

    def _start_open_volume(self):
        idx = self.part_list.currentRow()
        if idx < 0 or self.engine is None:
            QMessageBox.information(self, "提示", "请先扫描并选择分区")
            return
        vd = next((v for v in self.pool.virtual_disks if v.windows_vd_number is not None), None)
        part = self.engine.partitions[idx]
        self.lbl_fs_status.setText("打开卷…")
        self._ov_worker = OpenVolumeWorker(self.engine, vd, part)
        self._ov_worker.signals.finished.connect(self._volume_opened)
        self._ov_worker.signals.failed.connect(
            lambda tb: QMessageBox.critical(self, "打开卷失败", tb))
        self._ov_worker.start()

    def _volume_opened(self, vol):
        self.volume = vol
        self.stack.setCurrentIndex(1)
        self._sync_nav()
        self._start_scan_fs()

    # ------------------------------------------------ 页2：扫描 FS

    def _start_scan_fs(self):
        self.lbl_fs_status.setText("扫描 $MFT…")
        self._fs_worker = ScanFsWorker(self.engine)
        self._fs_worker.signals.progress.connect(
            lambda d: self.lbl_fs_status.setText(f"扫描 $MFT… {d['done']}/{d['total']}"))
        self._fs_worker.signals.finished.connect(self._fs_scanned)
        self._fs_worker.signals.failed.connect(
            lambda tb: QMessageBox.critical(self, "扫描失败", tb))
        self._fs_worker.start()

    def _fs_scanned(self, res):
        self.entries = res["entries"]
        st = res["stats"]
        self.stats = st
        self.file_tree.load_entries(self.entries)
        self.lbl_fs_status.setText("扫描完成")
        self.lbl_fs_stats.setText(
            f"记录 {st.total_records} | 文件 {st.files} 目录 {st.dirs} | "
            f"已删除 {st.deleted_files} 个 / {fmt_size(st.deleted_bytes)} | "
            f"孤儿 {st.orphans}")
        self.error_records = list(self.engine._err_seq_records) if hasattr(self.engine, "_err_seq_records") else []

    # ------------------------------------------------ 页3：选择/参数

    def _on_selection_changed(self, *_):
        self._update_sel_stats()

    def _update_sel_stats(self):
        sel = self.file_tree.collect_checked_files()
        total = sum(e.size for e in sel)
        ndel = sum(1 for e in sel if e.deleted)
        self.lbl_sel_stats.setText(f"已勾选 {len(sel)} 个文件（其中已删除 {ndel}）— {fmt_size(total)}")
        self.lbl_est.setText(f"导出到 {self.ed_dest.text()}，预计 {fmt_size(total)}")

    def _browse_dest(self):
        d = QFileDialog.getExistingDirectory(self, "选择保存目录", self.ed_dest.text())
        if d:
            self.ed_dest.setText(d)

    def _collect_errors(self):
        recs = []
        sink_records = getattr(self.engine, "error_sink_records", None)
        if sink_records:
            recs = list(sink_records)
        return recs

    # ------------------------------------------------ 页4：导出

    def _start_export(self):
        sel = self.file_tree.collect_checked_files()
        if not sel:
            QMessageBox.information(self, "提示", "请先勾选要恢复的文件")
            return
        from ssrecover.config import ExportConfig, ReadParams, ErrorRules
        cfg = ExportConfig(
            dest_root=self.ed_dest.text(),
            read_params=ReadParams(chunk_mb=self.sp_chunk.value(),
                                   max_retries=self.sp_retry.value(),
                                   verify_zero_regions=self.cb_zerochk.isChecked(),
                                   use_parity_rebuild=self.cb_xorr.isChecked()),
            error_rules=ErrorRules(),
            export_deleted=self.cb_deleted.isChecked(),
            export_live=self.cb_live.isChecked())
        self.error_records = []
        self._export_worker = ExportWorker(self.engine, sel, cfg)
        self._export_worker.signals.progress.connect(self.dual.update_progress)
        self._export_worker.signals.finished.connect(self._export_done)
        self._export_worker.signals.failed.connect(
            lambda tb: QMessageBox.critical(self, "导出失败", tb))
        # 错误收集：engine.error_sink 已经是用户回调；这里桥接
        self._export_worker.signals.error.connect(lambda rec: self.error_records.append(rec))
        self.btn_cancel.setEnabled(True)
        self.btn_next.setEnabled(False)
        self._export_worker.start()

    def _cancel_export(self):
        if self._export_worker:
            self._export_worker.cancel()

    def _export_done(self, res):
        self.btn_cancel.setEnabled(False)
        if res.get("aborted"):
            self.lbl_est.setText(f"已中止: {res.get('reason', '')}")
        self.lbl_est.setText(f"导出完成: 成功 {res.get('ok', 0)}, 失败 {res.get('fail', 0)}")
        # 从 engine 收集全部错误记录（engine.error_sink 由 MainWindow 提供）
        self.error_records = list(self.engine._collected_errors)
        self.error_widget.set_records(self.error_records)
        self.btn_csv.setEnabled(True)
        self.btn_next.setEnabled(True)
        self._sync_nav()
        QMessageBox.information(
            self, "完成", f"成功 {res.get('ok', 0)} / 失败 {res.get('fail', 0)}\n"
                          f"保存于 {self.ed_dest.text()}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出错误 CSV", "errors.csv", "CSV (*.csv)")
        if path:
            self.error_widget.to_csv(Path(path))

    # 错误收集：包一层 error_sink
    def _wrap_engine_sink(self):
        engine = self.engine
        if engine is None:
            return
        engine._collected_errors = []
        orig_sink = engine.error_sink

        def sink(rec):
            engine._collected_errors.append(rec)
            if self._export_worker:
                self._export_worker.signals.error.emit(rec)
        engine.error_sink = sink
