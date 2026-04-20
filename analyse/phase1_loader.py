"""
phase1_loader.py - 阶段1结果加载器
从阶段1的输出数据库中加载已确认的匹配结果，用于阶段2分析。
"""

from __future__ import annotations
import sqlite3
from .base import MatchContext


class Phase1ResultLoader:
    """从阶段1结果数据库加载已确认的匹配"""

    def __init__(self, phase1_db: str):
        self.conn = sqlite3.connect(phase1_db)

    def load_confirmed_matches(self, ctx: MatchContext) -> None:
        """
        从阶段1结果数据库加载已确认的匹配结果到 MatchContext。
        这些结果会被标记为已确认，阶段2不会重复匹配这些函数。
        """
        print("正在加载阶段1结果...")
        count = 0
        for bin_id, src_id, confidence, method in self.conn.execute("""
            SELECT bin_func_id, src_func_id, confidence, method
            FROM mapping_results
        """):
            ctx.confirmed_matches[bin_id] = (src_id, confidence, method)
            count += 1

        print(f"  ✅ 已加载 {count} 条阶段1确认匹配")
