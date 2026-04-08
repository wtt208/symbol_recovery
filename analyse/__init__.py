"""
analyse/ - 固件函数识别引擎（抽象接口版）

公开接口：
  - MatchContext, FuncInfo, MatchResult, PhaseStats  （数据模型）
  - IDataLoader, IMatchPhase, IResultExporter, ILogger （抽象接口）
  - SqliteDataLoader                                  （数据加载实现）
  - UniqueStringMatchPhase                            （阶段1实现）
  - SqliteExporter                                    （导出 + 日志实现）
  - MatchEngine                                       （编排器）
"""

from .base import (
    FuncInfo, MatchResult, PhaseStats, MatchContext,
    IDataLoader, IMatchPhase, IResultExporter, ILogger,
)
from .loader import SqliteDataLoader
from .phase1_unique_string import UniqueStringMatchPhase
from .exporter import SqliteExporter
from .engine import MatchEngine

##111
__all__ = [
    "FuncInfo", "MatchResult", "PhaseStats", "MatchContext",
    "IDataLoader", "IMatchPhase", "IResultExporter", "ILogger",
    "SqliteDataLoader", "UniqueStringMatchPhase",
    "SqliteExporter", "MatchEngine",
]
