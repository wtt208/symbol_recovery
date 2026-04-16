"""
exporter.py - 结果导出实现（IResultExporter + ILogger）
将 MatchContext 中的结果写入 SQLite 输出数据库。
"""

from __future__ import annotations
import sqlite3

from .base import IResultExporter, ILogger, MatchContext, PhaseStats


class SqliteExporter(IResultExporter, ILogger):
    """将匹配结果和日志写入 SQLite"""

    def __init__(self, output_db: str):
        self.conn = sqlite3.connect(output_db)
        self._init_schema()

    # ------------------------------------------------------------------
    # IResultExporter
    # ------------------------------------------------------------------

    def export(self, ctx: MatchContext) -> None:
        print("\n正在导出结果...")
        self._export_confirmed(ctx)
        self._export_candidates(ctx)
        print("  ✅ 结果已导出")

    def save_stats(self, stats: PhaseStats) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO statistics VALUES (?, ?, ?, ?, ?)",
            (stats.phase_id, stats.confirmed_count,
             stats.candidate_count, stats.avg_confidence, stats.execution_time),
        )

    def commit(self) -> None:
        self.conn.commit()

    # ------------------------------------------------------------------
    # ILogger
    # ------------------------------------------------------------------

    def log(self, phase: str, bin_id: int, src_id: int,
            score: float, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO mapping_log (phase, bin_func_id, src_func_id, score, reason) "
            "VALUES (?, ?, ?, ?, ?)",
            (phase, bin_id, src_id, score, reason),
        )

    # ------------------------------------------------------------------
    # 私有方法
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        stmts = [
            "DROP TABLE IF EXISTS mapping_results",
            """CREATE TABLE mapping_results (
                bin_func_id   INTEGER PRIMARY KEY,
                bin_address   TEXT,
                src_func_id   INTEGER,
                src_func_name TEXT,
                src_file_path TEXT,
                confidence    REAL,
                method        TEXT,
                ref_type      TEXT,
                shared_strings INTEGER,
                call_similarity REAL,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
            )""",
            "DROP TABLE IF EXISTS mapping_candidates",
            """CREATE TABLE mapping_candidates (
                bin_func_id INTEGER,
                src_func_id INTEGER,
                score       REAL,
                method      TEXT,
                PRIMARY KEY (bin_func_id, src_func_id)
            )""",
            "DROP TABLE IF EXISTS mapping_log",
            """CREATE TABLE mapping_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                phase       TEXT,
                bin_func_id INTEGER,
                src_func_id INTEGER,
                score       REAL,
                reason      TEXT,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
            )""",
            "DROP TABLE IF EXISTS statistics",
            """CREATE TABLE statistics (
                phase            TEXT PRIMARY KEY,
                confirmed_count  INTEGER,
                candidate_count  INTEGER,
                avg_confidence   REAL,
                execution_time   REAL
            )""",
        ]
        for stmt in stmts:
            self.conn.execute(stmt)
        self.conn.commit()

    def _export_confirmed(self, ctx: MatchContext) -> None:
        # 方案A：导出时按 src_func_name 去重，同名函数只保留 evidence 最多（shared_strings 最大）的一条
        confirmed_src_names: set[str] = set()

        # 先按 shared_strings 降序排序，保证同名时优先保留证据最多的
        sorted_matches = sorted(
            ctx.confirmed_matches.items(),
            key=lambda item: len(
                ctx.bin_func_strings.get(item[0], set())
                & ctx.src_func_strings.get(item[1][0], set())
            ),
            reverse=True,
        )

        skipped = 0
        for bin_id, (src_id, confidence, method) in sorted_matches:
            bin_info = ctx.bin_func_info.get(bin_id)
            src_info = ctx.src_func_info.get(src_id)
            if not bin_info or not src_info:
                continue

            # 同名函数只导出一次
            if src_info.name in confirmed_src_names:
                skipped += 1
                continue
            confirmed_src_names.add(src_info.name)

            shared = len(
                ctx.bin_func_strings.get(bin_id, set())
                & ctx.src_func_strings.get(src_id, set())
            )

            # 根据 method 判断引用类型
            ref_type = "indirect" if "indirect" in method else "direct"

            # call_similarity 在阶段1结果中为 0（尚未计算）
            self.conn.execute(
                """INSERT INTO mapping_results
                   (bin_func_id, bin_address, src_func_id, src_func_name,
                    src_file_path, confidence, method, ref_type, shared_strings, call_similarity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (bin_id, bin_info.address, src_id, src_info.name,
                 src_info.file_path, confidence, method, ref_type, shared, 0.0),
            )

        if skipped:
            print(f"  ℹ️  导出时按函数名去重，跳过了 {skipped} 条同名重复记录")

    def _export_candidates(self, ctx: MatchContext) -> None:
        for bin_id, cands in ctx.candidates.items():
            if bin_id in ctx.confirmed_matches:
                continue
            for src_id, score, method in cands[:5]:
                self.conn.execute(
                    "INSERT OR IGNORE INTO mapping_candidates VALUES (?, ?, ?, ?)",
                    (bin_id, src_id, score, method),
                )
