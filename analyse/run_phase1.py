"""
run_phase1.py - 仅执行阶段1（唯一字符串直接匹配）的入口脚本

用法:
    python3 run_phase1.py <源码数据库> <二进制数据库> <输出数据库>

示例:
    python3 run_phase1.py source.db firmware.db results_phase1.db
"""

import sys
from pathlib import Path

# 将 symbol_recover 加入模块搜索路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyse import (
    SqliteDataLoader,
    UniqueStringMatchPhase,
    SqliteExporter,
    MatchEngine,
)


def main() -> None:
    if len(sys.argv) != 4:
        print("用法: python3 run_phase1.py <源码数据库> <二进制数据库> <输出数据库>")
        sys.exit(1)

    src_db, bin_db, out_db = sys.argv[1], sys.argv[2], sys.argv[3]

    loader   = SqliteDataLoader(src_db, bin_db)
    exporter = SqliteExporter(out_db)
    phases   = [UniqueStringMatchPhase()]

    engine = MatchEngine(
        loader=loader,
        phases=phases,
        exporter=exporter,
        logger=exporter,   # SqliteExporter 同时实现了 ILogger
    )
    engine.run()


if __name__ == "__main__":
    main()
