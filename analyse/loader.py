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
        self._compute_indirect_refs(ctx)
        self._print_summary(ctx)

    # ------------------------------------------------------------------
    # 私有加载方法
    # ------------------------------------------------------------------

    def _load_func_info(self, ctx: MatchContext) -> None:
        print("  - 源码函数信息（is_def=0 和 is_def=1）...")
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
        """
        源码侧：function_string_map 里的字符串已是直接引用（归属到 callee）。
        二进制侧：只加载 ref_type='direct' 的记录作为直接引用。
        间接引用通过 _compute_indirect_refs 从调用图推导。
        """
        print("  - 源码函数字符串（直接引用，归属到 callee）...")
        for func_id, content in self.src_conn.execute("""
            SELECT fsm.function_id, s.content
            FROM function_string_map fsm
            JOIN strings s ON fsm.string_id = s.id
        """):
            ctx.src_func_strings.setdefault(func_id, set()).add(content)

        print("  - 二进制函数字符串（直接引用 direct）...")
        for func_id, content in self.bin_conn.execute("""
            SELECT bfsr.func_id, bs.content
            FROM binary_func_string_refs bfsr
            JOIN binary_strings bs ON bfsr.string_id = bs.id
            WHERE bfsr.ref_type = 'direct'
        """):
            ctx.bin_func_strings.setdefault(func_id, set()).add(content)

        # 若二进制库没有 ref_type 字段（旧版本），回退到全量加载
        if not ctx.bin_func_strings:
            print("  - 二进制库无 ref_type 字段，回退到全量加载...")
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

    def _compute_indirect_refs(self, ctx: MatchContext) -> None:
        """
        通过调用图推导间接引用：
        若 caller 调用了 callee，且 callee 直接引用了字符串 s，
        则 caller 间接引用了字符串 s。
        """
        print("  - 推导源码间接引用...")
        for caller_id, graph in ctx.src_call_graph.items():
            indirect_strings = set()
            for callee_id in graph["callees"]:
                # callee 的直接引用字符串，对 caller 来说是间接引用
                indirect_strings.update(ctx.src_func_strings.get(callee_id, set()))
            if indirect_strings:
                ctx.src_func_strings_indirect[caller_id] = indirect_strings

        print("  - 推导二进制间接引用...")
        for caller_id, graph in ctx.bin_call_graph.items():
            indirect_strings = set()
            for callee_id in graph["callees"]:
                indirect_strings.update(ctx.bin_func_strings.get(callee_id, set()))
            if indirect_strings:
                ctx.bin_func_strings_indirect[caller_id] = indirect_strings

    @staticmethod
    def _print_summary(ctx: MatchContext) -> None:
        src_edges = sum(len(g["callees"]) for g in ctx.src_call_graph.values())
        bin_edges = sum(len(g["callees"]) for g in ctx.bin_call_graph.values())
        src_direct = len(ctx.src_func_strings)
        src_indirect = len(ctx.src_func_strings_indirect)
        bin_direct = len(ctx.bin_func_strings)
        bin_indirect = len(ctx.bin_func_strings_indirect)
        print(
            f"\n数据加载完成：\n"
            f"  源码函数: {len(ctx.src_func_info)}\n"
            f"  二进制函数: {len(ctx.bin_func_info)}\n"
            f"  唯一字符串: {len(ctx.string_rarity)}\n"
            f"  源码调用边: {src_edges}\n"
            f"  二进制调用边: {bin_edges}\n"
            f"  源码直接引用函数数: {src_direct}\n"
            f"  源码间接引用函数数: {src_indirect}\n"
            f"  二进制直接引用函数数: {bin_direct}\n"
            f"  二进制间接引用函数数: {bin_indirect}"
        )
