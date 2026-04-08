"""
phase1_unique_string.py - 阶段1：唯一字符串直接匹配（IMatchPhase 实现）

策略：
  若某字符串在源码中只属于一个函数、在二进制中也只属于一个函数，
  则直接将这两个函数配对，置信度 0.95。
"""

from __future__ import annotations
from collections import defaultdict

from .base import IMatchPhase, MatchContext

CONFIDENCE = 0.95
METHOD = "unique_string"


class UniqueStringMatchPhase(IMatchPhase):

    @property
    def phase_id(self) -> str:
        return "phase1"

    @property
    def phase_name(self) -> str:
        return "唯一字符串直接匹配"

    def run(self, ctx: MatchContext) -> int:
        print(f"\n[阶段 1] {self.phase_name}...")

        # 构建 string -> {func_id} 的倒排索引
        src_index: dict[str, set[int]] = defaultdict(set)
        for func_id, strings in ctx.src_func_strings.items():
            for s in strings:
                src_index[s].add(func_id)

        bin_index: dict[str, set[int]] = defaultdict(set)
        for func_id, strings in ctx.bin_func_strings.items():
            for s in strings:
                bin_index[s].add(func_id)

        matches = 0
        for string in src_index.keys() & bin_index.keys():
            src_funcs = src_index[string]
            bin_funcs = bin_index[string]

            # 唯一性：两侧各只有一个函数包含该字符串
            if len(src_funcs) != 1 or len(bin_funcs) != 1:
                continue

            src_id = next(iter(src_funcs))
            bin_id = next(iter(bin_funcs))

            if bin_id in ctx.confirmed_matches:
                continue  # 已被更早的字符串确认过，跳过

            ctx.confirmed_matches[bin_id] = (src_id, CONFIDENCE, METHOD)
            matches += 1

        print(f"  ✅ 通过唯一字符串确认了 {matches} 个匹配")
        return matches
