"""GUI 组件：文件树（复选）、错误表、双进度。"""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex  # type: ignore
from PySide6.QtGui import QColor, QFont  # type: ignore
from PySide6.QtWidgets import (QHeaderView, QProgressBar, QTableView, QTreeWidget,  # type: ignore
                               QTreeWidgetItem, QVBoxLayout, QWidget, QLabel)


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def filetime_to_unix(ft: int) -> int:
    return max(0, ft // 10_000_000 - 11644473600) if ft > 0 else 0


# ---------------------------------------------------------------- 文件树

class FileTreeWidget(QTreeWidget):
    """目录/文件树：已删文件红色，目录复选框级联勾选。"""

    COLS = ("名称", "大小", "修改时间", "状态")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(4)
        self.setHeaderLabels(self.COLS)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.setAlternatingRowColors(True)

    def load_entries(self, entries):
        self.clear()
        dirs = {}
        for e in entries:
            dirs[e.mft_ref] = e
        nodes = {}   # (parent_ref, name, is_deleted_dir) → QTreeWidgetItem
        root = self.invisibleRootItem()

        def get_node(parent_ref, name, deleted, ref_key):
            key = (parent_ref, name)
            if key in nodes:
                return nodes[key]
            parent_item = nodes.get((None, ""))
            item = QTreeWidgetItem(parent_item or root)
            nodes[key] = item
            return item

        # 先建目录结构（按路径逐段），再挂文件
        dir_cache = {}   # path → item
        dir_meta = {e.mft_ref: e for e in entries if e.is_dir}

        def dir_item_for(fe):
            """按文件的目录路径建立树链，返回文件应挂的父 item。"""
            path = fe.path or ""
            parts = path.replace("/", "\\").split("\\") if path else []
            cur_item = root
            cur_path = ""
            for seg in parts:
                cur_path = f"{cur_path}\\{seg}" if cur_path else seg
                if cur_path in dir_cache:
                    cur_item = dir_cache[cur_path]
                    continue
                item = QTreeWidgetItem(cur_item)
                meta = None
                for e in entries:
                    if e.is_dir and e.path == cur_path:
                        meta = e
                        break
                if meta is not None and meta.deleted:
                    item.setText(0, seg + "  [已删除]")
                    item.setForeground(0, QColor("#c0392b"))
                else:
                    item.setText(0, seg)
                item.setData(0, Qt.ItemDataRole.UserRole, ("dir", meta))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(0, Qt.CheckState.Unchecked)
                dir_cache[cur_path] = item
                cur_item = item
            return cur_item

        for fe in sorted(entries, key=lambda x: (x.path, x.name)):
            parent = dir_item_for(fe)
            item = QTreeWidgetItem(parent)
            item.setText(0, fe.name)
            item.setText(1, fmt_size(fe.size))
            mt = fe.times[1]
            item.setText(2, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mt)) if mt else "")
            if fe.deleted:
                item.setText(3, "已删除")
                item.setForeground(0, QColor("#c0392b"))
                item.setForeground(3, QColor("#c0392b"))
            else:
                item.setText(3, "存在")
            item.setData(0, Qt.ItemDataRole.UserRole, ("file", fe))
            if not fe.is_dir:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(0, Qt.CheckState.Unchecked)

        self.expandToDepth(0)

    def collect_checked_files(self):
        """返回勾选的文件 FileEntry 列表（勾选目录 = 其下全部已删文件）。"""
        out = []

        def walk(item):
            kind, payload = item.data(0, Qt.ItemDataRole.UserRole) or (None, None)
            cs = item.checkState(0)
            if kind == "file" and payload is not None:
                if cs == Qt.CheckState.Checked:
                    out.append(payload)
            elif kind == "dir" and cs == Qt.CheckState.Checked:
                self._collect_deleted_under(item, out)
                return
            for i in range(item.childCount()):
                walk(item.child(i))

        def _collect_deleted_under(item, out):
            for i in range(item.childCount()):
                ch = item.child(i)
                kind, payload = ch.data(0, Qt.ItemDataRole.UserRole) or (None, None)
                if kind == "file" and payload is not None:
                    out.append(payload)
                else:
                    _collect_deleted_under(ch, out)

        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            walk(root.child(i))
        return out


# ---------------------------------------------------------------- 错误表

class ErrorTableModel(QAbstractTableModel):
    HEAD = ("时间", "级别", "错误码", "文件", "卷内偏移", "虚拟偏移", "盘", "物理偏移", "动作")

    def __init__(self, records=None, parent=None):
        super().__init__(parent)
        self.records = records or []
        self._filtered = self.records

    def set_records(self, records):
        self.beginResetModel()
        self.records = records
        self._filtered = records
        self.endResetModel()

    def apply_filter(self, text: str):
        if not text:
            self._filtered = self.records
        else:
            t = text.lower()
            self._filtered = [r for r in self.records
                              if t in (r.code + r.file_path + r.message).lower()]
        self.beginResetModel()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._filtered)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEAD)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        r = self._filtered[index.row()]
        c = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if c == 0:
                return time.strftime("%H:%M:%S", time.localtime(r.time))
            if c == 1:
                return r.level
            if c == 2:
                return r.code
            if c == 3:
                return r.file_path or "-"
            if c == 4:
                return f"{r.volume_offset:#x}" if r.volume_offset >= 0 else "-"
            if c == 5:
                return f"{r.virtual_offset:#x}" if r.virtual_offset >= 0 else "-"
            if c == 6:
                return f"#{r.disk_id} {r.disk_name}" if r.disk_id >= 0 else "-"
            if c == 7:
                return f"{r.physical_offset:#x}" if r.physical_offset >= 0 else "-"
            if c == 8:
                return r.action or "-"
        elif role == Qt.ItemDataRole.ForegroundRole and c == 1:
            return QColor("#c0392b") if r.level in ("ERROR", "FATAL") else QColor("#7f8c8d")
        return None

    def headerData(self, sec, orient, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orient == Qt.Orientation.Horizontal:
            return self.HEAD[sec]
        return None

    def record_at(self, row):
        return self._filtered[row]


class ErrorTableWidget(QWidget):
    """可交互错误列表：过滤 + 表 + 详情面板 + CSV 导出。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.model = ErrorTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        lay.addWidget(self.table)
        self.detail = QLabel("点击行查看详情")
        self.detail.setWordWrap(True)
        self.detail.setStyleSheet("font-family: Consolas; font-size: 12px; background: #fafafa;")
        self.detail.setMinimumHeight(110)
        lay.addWidget(self.detail)
        self.table.clicked.connect(self._on_click)

    def _on_click(self, index):
        rec = self.model.record_at(index.row())
        self.detail.setText(rec.detail())

    def set_records(self, records):
        self.model.set_records(records)

    def to_csv(self, path: Path):
        import csv
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["时间", "级别", "错误码", "消息", "文件", "MFT", "Run",
                        "卷偏移", "虚拟偏移", "盘ID", "盘名", "物理偏移", "长度",
                        "动作", "重试", "附加"])
            for r in self.model.records:
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.time)),
                            r.level, r.code, r.message, r.file_path, r.mft_ref,
                            r.run_index, r.volume_offset, r.virtual_offset,
                            r.disk_id, r.disk_name, r.physical_offset, r.length,
                            r.action, r.retries, r.extra])


# ---------------------------------------------------------------- 双进度

class DualProgressWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        self.lbl_overall = QLabel("总体：--")
        self.bar_overall = QProgressBar()
        self.bar_overall.setRange(0, 1000)
        self.lbl_current = QLabel("当前文件：--")
        self.bar_current = QProgressBar()
        self.bar_current.setRange(0, 1000)
        lay.addWidget(self.lbl_overall)
        lay.addWidget(self.bar_overall)
        lay.addSpacing(8)
        lay.addWidget(self.lbl_current)
        lay.addWidget(self.bar_current)

    def update_progress(self, p):
        if getattr(p, "phase", "") != "export":
            return
        self.lbl_overall.setText(
            f"总体 {p.overall_percent:5.1f}%  {fmt_size(p.overall_done)}/{fmt_size(p.overall_total)}"
            f"  {fmt_size(p.speed)}/s  ETA {int(p.eta // 60)}:{int(p.eta % 60):02d}")
        self.bar_overall.setValue(int(p.overall_percent * 10))
        self.lbl_current.setText(f"当前 {p.current_file}  {fmt_size(p.current_done)}/{fmt_size(p.current_total)}")
        self.bar_current.setValue(int(p.current_percent * 10))
