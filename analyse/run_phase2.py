"""
run_phase2.py - 执行阶段2（间接引用多字符串匹配）

用法:
    python3 run_phase2.py <源码数据库> <二进制数据库> <阶段1结果数据库> <输出数据库>

示例:
    python3 run_phase2.py source.db firmware.db results_phase1.db results_phase2.db

说明:
    - 直接使用阶段1的结果数据库（results_phase1.db）中的匹配结果
    - 只运行阶段2的间接引用分析
    - 将最终结果输出到新的数据库（results_phase2.db）
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyse import (
    SqliteDataLoader,
    IndirectStringMatchPhaseFast,
    SqliteExporter,
    MatchEngine,
)
from analyse.phase1_loader import Phase1ResultLoader


def main() -> None:
    if len(sys.argv) != 5:
        print("用法: python3 run_phase2.py <源码数据库> <二进制数据库> <阶段1结果数据库> <输出数据库>")
        print("示例: python3 run_phase2.py source.db firmware.db results_phase1.db results_phase2.db")
        sys.exit(1)

    src_db, bin_db, phase1_db, out_db = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    loader   = SqliteDataLoader(src_db, bin_db)
    phase1_loader = Phase1ResultLoader(phase1_db)
    exporter = SqliteExporter(out_db)
    phases   = [
        IndirectStringMatchPhaseFast(),
    ]

    engine = MatchEngine(
        loader=loader,
        phases=phases,
        exporter=exporter,
        logger=exporter,
        phase1_loader=phase1_loader,
    )
    engine.run()


if __name__ == "__main__":
    main()
