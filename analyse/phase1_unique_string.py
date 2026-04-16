"""
phase1_unique_string.py - 阶段1：唯一字符串直接匹配（IMatchPhase 实现）

策略：
  若某字符串在源码中只属于一个函数、在二进制中也只属于一个函数，
  则直接将这两个函数配对，置信度 0.95。

  分两轮匹配：
  1. 直接引用匹配（direct）：src_func_strings vs bin_func_strings，置信度 0.95
  2. 间接引用匹配（indirect）：src_func_strings_indirect vs bin_func_strings_indirect，置信度 0.80
     间接引用匹配只对尚未被直接引用匹配确认的函数生效。

改进（v2）：
  1. 解决"先到先得"问题：
     同一对 (bin_id, src_id) 可被多条唯一字符串支撑，
     先收集所有证据（shared_count），再按证据数量排序后统一确认，
     证据越多的配对优先级越高。
  2. 解决"无冲突检测"问题：
     bin_id 和 src_id 均只能被确认一次（双向互斥）。
     若某 bin_id 或 src_id 已被更高证据数的配对占用，
     则将冲突的低证据配对降级写入 candidates，不丢弃。
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, Tuple, Set

from .base import IMatchPhase, MatchContext

CONFIDENCE_DIRECT   = 0.95
CONFIDENCE_INDIRECT = 0.80
METHOD_DIRECT   = "unique_string_direct"
METHOD_INDIRECT = "unique_string_indirect"


class UniqueStringMatchPhase(IMatchPhase):

    @property
    def phase_id(self) -> str:
        return "phase1"

    @property
    def phase_name(self) -> str:
        return "唯一字符串直接匹配"

    def run(self, ctx: MatchContext) -> int:
        print(f"\n[阶段 1] {self.phase_name}...")

        direct_matches = self._match_round(
            ctx,
            src_strings=ctx.src_func_strings,
            bin_strings=ctx.bin_func_strings,
            confidence=CONFIDENCE_DIRECT,
            method=METHOD_DIRECT,
            label="直接引用",
        )

        indirect_matches = self._match_round(
            ctx,
            src_strings=ctx.src_func_strings_indirect,
            bin_strings=ctx.bin_func_strings_indirect,
            confidence=CONFIDENCE_INDIRECT,
            method=METHOD_INDIRECT,
            label="间接引用",
        )

        return direct_matches + indirect_matches

    def _match_round(
        self,
        ctx: MatchContext,
        src_strings: Dict[int, Set[str]],
        bin_strings: Dict[int, Set[str]],
        confidence: float,
        method: str,
        label: str,
    ) -> int:
        # ----------------------------------------------------------------
        # Step 1: 构建 string -> {func_id} 的倒排索引
        # ----------------------------------------------------------------
        src_index: dict[str, set[int]] = defaultdict(set)
        for func_id, strings in src_strings.items():
            for s in strings:
                src_index[s].add(func_id)

        bin_index: dict[str, set[int]] = defaultdict(set)
        for func_id, strings in bin_strings.items():
            for s in strings:
                bin_index[s].add(func_id)

        # ----------------------------------------------------------------
        # Step 2: 收集所有候选配对及其支撑字符串数量
        # ----------------------------------------------------------------
        pair_evidence: Dict[Tuple[int, int], int] = defaultdict(int)

        for string in src_index.keys() & bin_index.keys():
            src_funcs = src_index[string]
            bin_funcs = bin_index[string]

            if len(src_funcs) != 1 or len(bin_funcs) != 1:
                continue

            src_id = next(iter(src_funcs))
            bin_id = next(iter(bin_funcs))
            pair_evidence[(bin_id, src_id)] += 1

        # ----------------------------------------------------------------
        # Step 3: 按证据数量降序排序
        # ----------------------------------------------------------------
        sorted_pairs = sorted(
            pair_evidence.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        # ----------------------------------------------------------------
        # Step 4: 双向互斥确认
        # ----------------------------------------------------------------
        confirmed_bin: set[int] = set(ctx.confirmed_matches.keys())
        confirmed_src: set[int] = {v[0] for v in ctx.confirmed_matches.values()}

        matches = 0
        for (bin_id, src_id), evidence_count in sorted_pairs:
            if bin_id in confirmed_bin or src_id in confirmed_src:
                score = confidence * (1 - 1 / (evidence_count + 1))
                ctx.candidates.setdefault(bin_id, []).append(
                    (src_id, score, method + "_conflict")
                )
                continue

            confirmed_bin.add(bin_id)
            confirmed_src.add(src_id)
            ctx.confirmed_matches[bin_id] = (src_id, confidence, method)
            matches += 1

        conflict_count = len(sorted_pairs) - matches
        print(f"  ✅ [{label}] 确认了 {matches} 个匹配")
        if conflict_count:
            print(f"  ⚠️  [{label}] {conflict_count} 个冲突配对已降级为候选")
        return matches
