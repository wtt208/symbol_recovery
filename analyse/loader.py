"""
loader.py - 数据加载实现（IDataLoader）
从 SQLite 数据库读取函数信息、字符串映射、调用图，并计算 IDF。
"""

from __future__ import annotations
import math
import sqlite3
from collections import Counter, defaultdict

from .base import IDataLoader, MatchContext, FuncInfo


class SqliteDataLoader(IDataLoader):
    """从 SQLite 数据库加载数据"""

    def __init__(self, src_db: str, bin_db: str):
        self.src_conn = sqlite3.connect(src_db)
        self.bin_conn = sqlite3.connect(bin_db)

    def load(self, ctx: MatchContext) -> None:
        print("正在加载数据...")
        self._load_func_info(ctx)
        self._load_strings(ctx)
        self._compute_idf(ctx)
        self._load_call_graphs(ctx)
        self._print_summary(ctx)

    # ------------------------------------------------------------------
    # 私有加载方法
    # ------------------------------------------------------------------

    def _load_func_info(self, ctx: MatchContext) -> None:
        print("  - 源码函数信息...")
        for func_id, name, file_path, size in self.src_conn.execute(
            "SELECT id, name, file_path, line_end - line_start FROM functions"
        ):
            ctx.src_func_info[func_id] = FuncInfo(
                func_id=func_id, name=name, size=size or 0, file_path=file_path
            )

        print("  - 二进制函数信息...")
        for func_id, address, name, size in self.bin_conn.execute(
            "SELECT id, address, name, size FROM binary_functions WHERE is_library = 0"
        ):
            ctx.bin_func_info[func_id] = FuncInfo(
                func_id=func_id, name=name, size=size or 0, address=address
            )

    def _load_strings(self, ctx: MatchContext) -> None:
        print("  - 源码函数字符串...")
        for func_id, content in self.src_conn.execute("""
            SELECT cg.caller_id, s.content
            FROM function_string_map fsm
            JOIN strings s ON fsm.string_id = s.id
            JOIN functions f ON fsm.function_id = f.id
            JOIN source_call_graph cg ON cg.callee_id = f.id
            WHERE f.is_def = 0
        """):
            ctx.src_func_strings.setdefault(func_id, set()).add(content)

        print("  - 二进制函数字符串...")
        for func_id, content in self.bin_conn.execute("""
            SELECT bfsr.func_id, bs.content
            FROM binary_func_string_refs bfsr
            JOIN binary_strings bs ON bfsr.string_id = bs.id
        """):
            ctx.bin_func_strings.setdefault(func_id, set()).add(content)

    def _compute_idf(self, ctx: MatchContext) -> None:
        print("  - 计算字符串稀有度...")
        freq: Counter = Counter()
        for strings in ctx.bin_func_strings.values():
            freq.update(strings)
        total = len(ctx.bin_func_strings) or 1
        ctx.string_rarity = {
            s: math.log((total + 1) / (f + 1)) for s, f in freq.items()
        }

    def _load_call_graphs(self, ctx: MatchContext) -> None:
        def _empty_graph():
            return {"callers": set(), "callees": set()}

        print("  - 源码调用图...")
        ctx.src_call_graph = defaultdict(_empty_graph)
        for caller, callee in self.src_conn.execute(
            "SELECT DISTINCT caller_id, callee_id FROM source_call_graph"
        ):
            ctx.src_call_graph[caller]["callees"].add(callee)
            ctx.src_call_graph[callee]["callers"].add(caller)

        print("  - 二进制调用图...")
        ctx.bin_call_graph = defaultdict(_empty_graph)
        for caller, callee in self.bin_conn.execute(
            "SELECT DISTINCT caller_id, callee_id FROM binary_call_graph"
        ):
            ctx.bin_call_graph[caller]["callees"].add(callee)
            ctx.bin_call_graph[callee]["callers"].add(caller)

    @staticmethod
    def _print_summary(ctx: MatchContext) -> None:
        src_edges = sum(len(g["callees"]) for g in ctx.src_call_graph.values())
        bin_edges = sum(len(g["callees"]) for g in ctx.bin_call_graph.values())
        print(
            f"\n数据加载完成：\n"
            f"  源码函数: {len(ctx.src_func_info)}\n"
            f"  二进制函数: {len(ctx.bin_func_info)}\n"
            f"  唯一字符串: {len(ctx.string_rarity)}\n"
            f"  源码调用边: {src_edges}\n"
            f"  二进制调用边: {bin_edges}"
        )
