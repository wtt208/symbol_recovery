"""
base.py - 抽象基类与核心数据模型
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Set, List, Tuple, Optional


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class FuncInfo:
    """函数基本信息"""
    func_id: int
    name: str
    size: int = 0
    # 源码函数额外字段
    file_path: Optional[str] = None
    # 二进制函数额外字段
    address: Optional[str] = None


@dataclass
class MatchResult:
    """单条匹配结果"""
    bin_func_id: int
    src_func_id: int
    confidence: float
    method: str
    shared_strings: int = 0
    call_similarity: float = 0.0


@dataclass
class PhaseStats:
    """单阶段统计信息"""
    phase_id: str
    confirmed_count: int
    candidate_count: int
    avg_confidence: float
    execution_time: float


@dataclass
class MatchContext:
    """
    跨阶段共享的匹配上下文（各阶段读写同一份状态）
    """
    # 已确认匹配：{bin_id: (src_id, confidence, method)}
    confirmed_matches: Dict[int, Tuple[int, float, str]] = field(default_factory=dict)
    # 候选匹配：{bin_id: [(src_id, score, method), ...]}
    candidates: Dict[int, List[Tuple[int, float, str]]] = field(default_factory=dict)

    # 函数信息
    src_func_info: Dict[int, FuncInfo] = field(default_factory=dict)
    bin_func_info: Dict[int, FuncInfo] = field(default_factory=dict)

    # 字符串集合
    src_func_strings: Dict[int, Set[str]] = field(default_factory=dict)
    bin_func_strings: Dict[int, Set[str]] = field(default_factory=dict)

    # 调用图：{func_id: {'callers': set, 'callees': set}}
    src_call_graph: Dict[int, Dict[str, Set[int]]] = field(default_factory=dict)
    bin_call_graph: Dict[int, Dict[str, Set[int]]] = field(default_factory=dict)

    # 字符串稀有度（IDF）
    string_rarity: Dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 抽象接口
# ---------------------------------------------------------------------------

class IDataLoader(ABC):
    """数据加载接口：负责从数据库读取原始数据并填充 MatchContext"""

    @abstractmethod
    def load(self, ctx: MatchContext) -> None:
        """加载所有数据到 ctx"""
        ...


class IMatchPhase(ABC):
    """匹配阶段接口：每个阶段实现此接口"""

    @property
    @abstractmethod
    def phase_id(self) -> str:
        """阶段标识符，如 'phase1'"""
        ...

    @property
    @abstractmethod
    def phase_name(self) -> str:
        """阶段可读名称"""
        ...

    @abstractmethod
    def run(self, ctx: MatchContext) -> int:
        """
        执行本阶段匹配逻辑。

        Args:
            ctx: 共享匹配上下文（可读写）

        Returns:
            本阶段新增的确认匹配数量
        """
        ...


class IResultExporter(ABC):
    """结果导出接口：将 MatchContext 中的结果持久化"""

    @abstractmethod
    def export(self, ctx: MatchContext) -> None:
        """导出确认匹配和候选匹配"""
        ...

    @abstractmethod
    def save_stats(self, stats: PhaseStats) -> None:
        """保存单阶段统计信息"""
        ...

    @abstractmethod
    def commit(self) -> None:
        """提交所有待写入数据"""
        ...


class ILogger(ABC):
    """匹配日志接口"""

    @abstractmethod
    def log(self, phase: str, bin_id: int, src_id: int,
            score: float, reason: str) -> None:
        ...
