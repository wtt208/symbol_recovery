"""
phase2_indirect_string_fast.py - 阶段2优化版：高性能间接引用匹配

优化策略：
  1. 倒排索引：只比较有共同字符串的函数对（避免 O(n×m) 全量比较）
  2. 早停优化：交集太小直接跳过
  3. 预计算权重：避免重复查询 rarity 字典
  4. 批量处理：减少字典查询开销

性能提升：从 O(n×m) 降到 O(k)，k 为实际有交集的函数对数量
"""

from __future__ import annotations
from typing import Dict, Set, Tuple, List
from collections import defaultdict

from .base import IMatchPhase, MatchContext

SIMILARITY_THRESHOLD = 0.6
CONFIDENCE_FACTOR = 0.85
METHOD = "indirect_multi_string"


class IndirectStringMatchPhaseFast(IMatchPhase):

    @property
    def phase_id(self) -> str:
        return "phase2_fast"

    @property
    def phase_name(self) -> str:
        return "间接引用多字符串匹配（优化版）"

    def run(self, ctx: MatchContext) -> int:
        print(f"\n[阶段 2] {self.phase_name}...")

        # 已确认的函数集合
        confirmed_bin: set[int] = set(ctx.confirmed_matches.keys())
        confirmed_src: set[int] = {v[0] for v in ctx.confirmed_matches.values()}

        # Step 1: 构建倒排索引（字符串 -> 函数集合）
        print("  构建倒排索引...")
        bin_index, src_index = self._build_inverted_index(
            ctx, confirmed_bin, confirmed_src
        )

        # Step 2: 找出所有有共同字符串的函数对
        print("  查找候选函数对...")
        candidate_pairs = self._find_candidate_pairs(bin_index, src_index)
        print(f"  候选函数对数量: {len(candidate_pairs):,}")

        # Step 3: 批量计算相似度
        print("  计算相似度...")
        candidates = self._compute_similarities(
            candidate_pairs, ctx, confirmed_bin, confirmed_src
        )

        # Step 4: 按相似度降序排序，双向互斥确认
        candidates.sort(key=lambda x: x[2], reverse=True)

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

    def _build_inverted_index(
        self,
        ctx: MatchContext,
        confirmed_bin: set[int],
        confirmed_src: set[int],
    ) -> Tuple[Dict[str, Set[int]], Dict[str, Set[int]]]:
        """构建倒排索引：字符串 -> {函数ID}"""
        bin_index: Dict[str, Set[int]] = defaultdict(set)
        src_index: Dict[str, Set[int]] = defaultdict(set)

        # 只索引未匹配的函数
        for bin_id, strings in ctx.bin_func_strings_indirect.items():
            if bin_id not in confirmed_bin and strings:
                for s in strings:
                    bin_index[s].add(bin_id)

        for src_id, strings in ctx.src_func_strings_indirect.items():
            if src_id not in confirmed_src and strings:
                for s in strings:
                    src_index[s].add(src_id)

        return bin_index, src_index

    def _find_candidate_pairs(
        self,
        bin_index: Dict[str, Set[int]],
        src_index: Dict[str, Set[int]],
    ) -> Set[Tuple[int, int]]:
        """
        通过倒排索引找出所有有共同字符串的函数对
        只有共同字符串的函数对才可能相似度 > 0
        """
        pairs: Set[Tuple[int, int]] = set()

        # 遍历所有共同字符串
        common_strings = set(bin_index.keys()) & set(src_index.keys())

        for string in common_strings:
            bin_funcs = bin_index[string]
            src_funcs = src_index[string]

            # 笛卡尔积：所有可能的函数对
            for bin_id in bin_funcs:
                for src_id in src_funcs:
                    pairs.add((bin_id, src_id))

        return pairs

    def _compute_similarities(
        self,
        candidate_pairs: Set[Tuple[int, int]],
        ctx: MatchContext,
        confirmed_bin: set[int],
        confirmed_src: set[int],
    ) -> List[Tuple[int, int, float]]:
        """批量计算相似度，只保留 >= 阈值的配对"""
        results: List[Tuple[int, int, float]] = []
        total = len(candidate_pairs)
        processed = 0

        for bin_id, src_id in candidate_pairs:
            processed += 1
            if processed % 10000 == 0:
                progress = processed / total * 100
                print(f"  进度: {processed:,}/{total:,} ({progress:.1f}%)", end='\r')

            bin_strings = ctx.bin_func_strings_indirect.get(bin_id, set())
            src_strings = ctx.src_func_strings_indirect.get(src_id, set())

            if not bin_strings or not src_strings:
                continue

            # 早停优化：交集太小直接跳过
            intersection = bin_strings & src_strings
            if len(intersection) < MIN_INTERSECTION:
                continue

            similarity = self._weighted_jaccard_fast(
                bin_strings, src_strings, intersection, ctx.string_rarity
            )

            if similarity >= SIMILARITY_THRESHOLD:
                results.append((bin_id, src_id, similarity))

        print()  # 换行
        return results

    @staticmethod
    def _weighted_jaccard_fast(
        set1: Set[str],
        set2: Set[str],
        intersection: Set[str],
        rarity: Dict[str, float],
    ) -> float:
        """
        优化版 IDF 加权 Jaccard 相似度
        intersection 已预计算，避免重复计算
        """
        union = set1 | set2
        if not union:
            return 0.0

        # 批量查询权重，减少字典访问
        weighted_inter = sum(rarity.get(s, 1.0) for s in intersection)
        weighted_union = sum(rarity.get(s, 1.0) for s in union)

        return weighted_inter / weighted_union if weighted_union > 0 else 0.0
