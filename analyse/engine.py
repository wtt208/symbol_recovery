"""
engine.py - 匹配引擎：编排各阶段的执行流程
"""

from __future__ import annotations
import time

from .base import IDataLoader, IMatchPhase, IResultExporter, ILogger, MatchContext, PhaseStats


class MatchEngine:
    """
    编排器：依次执行各阶段，收集统计，最终导出结果。
    各组件通过构造函数注入，方便替换或扩展。
    """

    def __init__(
        self,
        loader: IDataLoader,
        phases: list[IMatchPhase],
        exporter: IResultExporter,
        logger: ILogger,
        phase1_loader=None,
    ):
        self.loader = loader
        self.phases = phases
        self.exporter = exporter
        self.logger = logger
        self.phase1_loader = phase1_loader
        self.ctx = MatchContext()

    def run(self) -> None:
        print("\n" + "=" * 70)
        print("固件函数识别引擎 v3.0（抽象接口版）")
        print("=" * 70)

        # 1. 加载数据
        self.loader.load(self.ctx)

        # 2. 如果提供了阶段1结果加载器，加载已确认的匹配
        if self.phase1_loader:
            self.phase1_loader.load_confirmed_matches(self.ctx)

        # 3. 逐阶段执行
        for phase in self.phases:
            t0 = time.time()
            new_matches = phase.run(self.ctx)
            elapsed = time.time() - t0

            confirmed = len(self.ctx.confirmed_matches)
            candidates = sum(len(c) for c in self.ctx.candidates.values())
            avg_conf = (
                sum(c[1] for c in self.ctx.confirmed_matches.values()) / confirmed
                if confirmed else 0.0
            )

            stats = PhaseStats(
                phase_id=phase.phase_id,
                confirmed_count=confirmed,
                candidate_count=candidates,
                avg_confidence=avg_conf,
                execution_time=elapsed,
            )
            self.exporter.save_stats(stats)
            self.exporter.commit()

        # 4. 导出结果
        self.exporter.export(self.ctx)
        self.exporter.commit()

        self._print_summary()
        print("\n✅ 匹配完成！结果已保存到数据库。")

    def _print_summary(self) -> None:
        from collections import Counter

        total_bin = len(self.ctx.bin_func_info)
        matched = len(self.ctx.confirmed_matches)

        print("\n" + "=" * 70)
        print("匹配结果摘要")
        print("=" * 70)
        print(f"\n  二进制函数总数: {total_bin}")
        print(f"  源码函数总数:   {len(self.ctx.src_func_info)}")
        pct = matched / total_bin * 100 if total_bin else 0
        print(f"  成功匹配:       {matched} ({pct:.1f}%)")

        if matched:
            confs = [c[1] for c in self.ctx.confirmed_matches.values()]
            high = sum(1 for c in confs if c > 0.85)
            mid  = sum(1 for c in confs if 0.70 <= c <= 0.85)
            low  = sum(1 for c in confs if c < 0.70)
            print(f"\n  置信度分布：")
            print(f"    高 (>0.85):      {high}")
            print(f"    中 (0.70-0.85):  {mid}")
            print(f"    低 (<0.70):      {low}")

            method_counts = Counter(c[2] for c in self.ctx.confirmed_matches.values())
            print(f"\n  匹配方法分布：")
            for method, count in method_counts.most_common():
                print(f"    {method}: {count}")
