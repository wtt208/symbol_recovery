"""
phase2_indirect_string.py - 阶段2：基于间接引用多字符串的加权相似度匹配

策略：
  对于阶段1未匹配的函数，比较其间接引用的字符串集合：
  1. 使用 Jaccard 相似度 + IDF 加权计算字符串集合相似度
  2. 只考虑间接引用字符串（src_func_strings_indirect vs bin_func_strings_indirect）
  3. 相似度阈值 >= 0.6 才确认匹配，置信度 = 相似度 * 0.85
  4. 每个二进制函数只匹配最相似的源码函数（贪心策略）

改进点：
  - 稀有字符串权重更高（IDF 加权）
  - 双向互斥：bin_id 和 src_id 只能被确认一次
  - 按相似度降序处理，优先确认高相似度配对
"""

from __future__ import annotations
from typing import Dict, Set, Tuple, List
from collections import defaultdict

from .base import IMatchPhase, MatchContext

SIMILARITY_THRESHOLD = 0.6
CONFIDENCE_FACTOR = 0.85
METHOD = "indirect_multi_string"


class IndirectStringMatchPhase(IMatchPhase):

    @property
    def phase_id(self) -> str:
        return "phase2"

    @property
    def phase_name(self) -> str:
        return "间接引用多字符串匹配"

    def run(self, ctx: MatchContext) -> int:
        print(f"\n[阶段 2] {self.phase_name}...")

        # 已确认的函数集合
        confirmed_bin: set[int] = set(ctx.confirmed_matches.keys())
        confirmed_src: set[int] = {v[0] for v in ctx.confirmed_matches.values()}

        # 候选配对：[(bin_id, src_id, similarity), ...]
        candidates: List[Tuple[int, int, float]] = []

        # 统计未匹配的二进制函数数量
        unmatched_bin = [
            (bin_id, bin_strings)
            for bin_id, bin_strings in ctx.bin_func_strings_indirect.items()
            if bin_id not in confirmed_bin and bin_strings
        ]
        total = len(unmatched_bin)
        print(f"  待匹配的二进制函数: {total}")

        # 遍历所有未匹配的二进制函数
        for idx, (bin_id, bin_strings) in enumerate(unmatched_bin, 1):
            # 打印进度
            if idx % 10 == 0 or idx == total:
                progress = idx / total * 100
                print(f"  进度: {idx}/{total} ({progress:.1f}%)", end='\r')

            # 计算与所有未匹配源码函数的相似度
            best_src_id = None
            best_similarity = 0.0

            for src_id, src_strings in ctx.src_func_strings_indirect.items():
                if src_id in confirmed_src:
                    continue
                if not src_strings:
                    continue

                similarity = self._weighted_jaccard(
                    bin_strings, src_strings, ctx.string_rarity
                )

                if similarity >= SIMILARITY_THRESHOLD and similarity > best_similarity:
                    best_similarity = similarity
                    best_src_id = src_id

            if best_src_id is not None:
                candidates.append((bin_id, best_src_id, best_similarity))

        print()  # 换行，结束进度条

        # 按相似度降序排序，优先确认高相似度配对
        candidates.sort(key=lambda x: x[2], reverse=True)

        # 双向互斥确认
        matches = 0
        for bin_id, src_id, similarity in candidates:
            if bin_id in confirmed_bin or src_id in confirmed_src:
                # 冲突：降级为候选
                confidence = similarity * CONFIDENCE_FACTOR * 0.9
                ctx.candidates.setdefault(bin_id, []).append(
                    (src_id, confidence, METHOD + "_conflict")
                )
                continue

            confirmed_bin.add(bin_id)
            confirmed_src.add(src_id)
            confidence = similarity * CONFIDENCE_FACTOR
            ctx.confirmed_matches[bin_id] = (src_id, confidence, METHOD)
            matches += 1

        conflict_count = len(candidates) - matches
        print(f"  ✅ 通过间接引用多字符串确认了 {matches} 个匹配")
        if conflict_count:
            print(f"  ⚠️  {conflict_count} 个冲突配对已降级为候选")
        return matches

    @staticmethod
    def _weighted_jaccard(
        set1: Set[str], set2: Set[str], rarity: Dict[str, float]
    ) -> float:
        """
        IDF 加权 Jaccard 相似度：
        weighted_intersection = sum(idf(s) for s in intersection)
        weighted_union = sum(idf(s) for s in union)
        similarity = weighted_intersection / weighted_union
        """
        if not set1 or not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        if not union:
            return 0.0

        weighted_inter = sum(rarity.get(s, 1.0) for s in intersection)
        weighted_union = sum(rarity.get(s, 1.0) for s in union)

        return weighted_inter / weighted_union if weighted_union > 0 else 0.0
