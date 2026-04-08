#!/usr/bin/env python3
"""
固件函数识别引擎 v2.0
======================
多阶段渐进式匹配策略：
  阶段1: 唯一字符串直接匹配（高置信度种子）
  阶段2: 字符串集合匹配（Jaccard + 加权相似度）
  阶段3: 调用图谱匹配（结构同构）
  阶段4: 混合特征匹配（字符串 + 调用图 + 函数规模）
  阶段5: 迭代传播（利用已确认匹配传播到邻居）


"""

import sqlite3
import math
from collections import defaultdict, Counter
from typing import Dict, Set, List, Tuple, Optional

class FunctionMapper:
    """固件函数识别核心引擎"""
    
    def __init__(self, src_db: str, bin_db: str, output_db: str):
        """
        初始化映射器
        
        Args:
            src_db: 源码数据库路径
            bin_db: 二进制数据库路径
            output_db: 输出结果数据库路径
        """
        self.src_conn = sqlite3.connect(src_db)
        self.bin_conn = sqlite3.connect(bin_db)
        self.out_conn = sqlite3.connect(output_db)
        
        # 核心数据结构
        self.confirmed_matches = {}  # {bin_id: (src_id, confidence, method)}
        self.candidates = defaultdict(list)  # {bin_id: [(src_id, score, method), ...]}
        
        # 缓存数据
        self.src_func_strings = {}  # {func_id: set(strings)}
        self.bin_func_strings = {}
        self.src_call_graph = defaultdict(lambda: {'callers': set(), 'callees': set()})
        self.bin_call_graph = defaultdict(lambda: {'callers': set(), 'callees': set()})
        self.string_rarity = {}  # 字符串稀有度（IDF）
        self.src_func_info = {}  # {func_id: {'name': ..., 'size': ...}}
        self.bin_func_info = {}
        
        self._init_output_db()
        self._load_data()
    
    def _init_output_db(self):
        """初始化输出数据库表结构"""
        self.out_conn.execute('DROP TABLE IF EXISTS mapping_results')
        self.out_conn.execute('''
            CREATE TABLE mapping_results (
                bin_func_id INTEGER PRIMARY KEY,
                bin_address TEXT,
                src_func_id INTEGER,
                src_func_name TEXT,
                src_file_path TEXT,
                confidence REAL,
                method TEXT,
                shared_strings INTEGER,
                call_similarity REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.out_conn.execute('DROP TABLE IF EXISTS mapping_candidates')
        self.out_conn.execute('''
            CREATE TABLE mapping_candidates (
                bin_func_id INTEGER,
                src_func_id INTEGER,
                score REAL,
                method TEXT,
                PRIMARY KEY (bin_func_id, src_func_id)
            )
        ''')
        
        self.out_conn.execute('DROP TABLE IF EXISTS mapping_log')
        self.out_conn.execute('''
            CREATE TABLE mapping_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase TEXT,
                bin_func_id INTEGER,
                src_func_id INTEGER,
                score REAL,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.out_conn.execute('DROP TABLE IF EXISTS statistics')
        self.out_conn.execute('''
            CREATE TABLE statistics (
                phase TEXT PRIMARY KEY,
                confirmed_count INTEGER,
                candidate_count INTEGER,
                avg_confidence REAL,
                execution_time REAL
            )
        ''')
        
        self.out_conn.commit()
    
    def _load_data(self):
        """预加载所有必要数据到内存"""
        print("正在加载数据...")
        
        # 1. 加载函数基本信息
        print("  - 源码函数信息...")
        for row in self.src_conn.execute('''
            SELECT id, name, file_path, line_end - line_start as size
            FROM functions
        '''):
            func_id, name, file_path, size = row
            self.src_func_info[func_id] = {
                'name': name,
                'file_path': file_path,
                'size': size or 0
            }
        
        print("  - 二进制函数信息...")
        for row in self.bin_conn.execute('''
            SELECT id, address, name, size
            FROM binary_functions WHERE is_library = 0
        '''):
            func_id, address, name, size = row
            self.bin_func_info[func_id] = {
                'address': address,
                'name': name,
                'size': size or 0
            }
        
        # 2. 加载函数-字符串映射
        print("  - 源码函数字符串...")
        # 方案A：字符串归属于调用记录（is_def=0），通过 source_call_graph 合并回 caller（is_def=1）
        # 即：caller_func 的字符串 = 其所有 callee 调用记录上挂的字符串之并集
        for func_id, string_content in self.src_conn.execute('''
            SELECT cg.caller_id AS function_id, s.content
            FROM function_string_map fsm
            JOIN strings s ON fsm.string_id = s.id
            JOIN functions f ON fsm.function_id = f.id
            JOIN source_call_graph cg ON cg.callee_id = f.id
            WHERE f.is_def = 0
        '''):
            if func_id not in self.src_func_strings:
                self.src_func_strings[func_id] = set()
            self.src_func_strings[func_id].add(string_content)
        
        print("  - 二进制函数字符串...")
        for func_id, string_content in self.bin_conn.execute('''
            SELECT bfsr.func_id, bs.content
            FROM binary_func_string_refs bfsr
            JOIN binary_strings bs ON bfsr.string_id = bs.id
        '''):
            if func_id not in self.bin_func_strings:
                self.bin_func_strings[func_id] = set()
            self.bin_func_strings[func_id].add(string_content)
        
        # 3. 计算字符串稀有度（IDF）
        print("  - 计算字符串稀有度...")
        string_doc_freq = Counter()
        for strings in self.bin_func_strings.values():
            for s in strings:
                string_doc_freq[s] += 1
        
        total_funcs = len(self.bin_func_strings) or 1
        for string, freq in string_doc_freq.items():
            # IDF = log(总函数数 / 包含该字符串的函数数)
            self.string_rarity[string] = math.log((total_funcs + 1) / (freq + 1))
        
        # 4. 加载调用图
        print("  - 源码调用图...")
        for caller, callee in self.src_conn.execute('''
            SELECT DISTINCT caller_id, callee_id FROM source_call_graph
        '''):
            self.src_call_graph[caller]['callees'].add(callee)
            self.src_call_graph[callee]['callers'].add(caller)
        
        print("  - 二进制调用图...")
        for caller, callee in self.bin_conn.execute('''
            SELECT DISTINCT caller_id, callee_id FROM binary_call_graph
        '''):
            self.bin_call_graph[caller]['callees'].add(callee)
            self.bin_call_graph[callee]['callers'].add(caller)
        
        print(f"\n数据加载完成：")
        print(f"  源码函数: {len(self.src_func_info)}")
        print(f"  二进制函数: {len(self.bin_func_info)}")
        print(f"  唯一字符串: {len(self.string_rarity)}")
        print(f"  源码调用边: {sum(len(g['callees']) for g in self.src_call_graph.values())}")
        print(f"  二进制调用边: {sum(len(g['callees']) for g in self.bin_call_graph.values())}")
    
    def _log_match(self, phase: str, bin_id: int, src_id: int, score: float, reason: str):
        """记录匹配日志"""
        self.out_conn.execute(
            'INSERT INTO mapping_log (phase, bin_func_id, src_func_id, score, reason) VALUES (?, ?, ?, ?, ?)',
            (phase, bin_id, src_id, score, reason)
        )
    
    def _calculate_string_similarity(self, bin_strs: Set[str], src_strs: Set[str]) -> Tuple[float, float, int]:
        """
        计算字符串相似度
        
        Returns:
            (jaccard_score, weighted_score, shared_count)
        """
        intersection = bin_strs & src_strs
        if not intersection:
            return 0.0, 0.0, 0
        
        union = bin_strs | src_strs
        
        # 1. Jaccard 相似度
        jaccard = len(intersection) / len(union)
        
        # 2. 加权相似度（基于 IDF）
        weighted_score = sum(self.string_rarity.get(s, 1.0) for s in intersection)
        max_possible = sum(self.string_rarity.get(s, 1.0) for s in union)
        weighted_sim = weighted_score / max_possible if max_possible > 0 else 0
        
        return jaccard, weighted_sim, len(intersection)
    
    def _calculate_call_similarity(self, bin_id: int, src_id: int) -> float:
        """
        计算调用图相似度
        基于调用者和被调用者的交集
        """
        bin_graph = self.bin_call_graph[bin_id]
        src_graph = self.src_call_graph[src_id]
        
        # 获取已确认匹配的映射关系
        bin_to_src = {b: s for b, (s, _, _) in self.confirmed_matches.items()}
        
        # 计算调用者相似度
        bin_callers_mapped = {bin_to_src.get(c) for c in bin_graph['callers'] if c in bin_to_src}
        bin_callers_mapped.discard(None)
        src_callers = src_graph['callers']
        
        caller_intersection = bin_callers_mapped & src_callers
        caller_union = bin_callers_mapped | src_callers
        caller_sim = len(caller_intersection) / len(caller_union) if caller_union else 0
        
        # 计算被调用者相似度
        bin_callees_mapped = {bin_to_src.get(c) for c in bin_graph['callees'] if c in bin_to_src}
        bin_callees_mapped.discard(None)
        src_callees = src_graph['callees']
        
        callee_intersection = bin_callees_mapped & src_callees
        callee_union = bin_callees_mapped | src_callees
        callee_sim = len(callee_intersection) / len(callee_union) if callee_union else 0
        
        # 综合得分（调用者和被调用者各占一半）
        return (caller_sim + callee_sim) / 2
    
    def run_all(self):
        """执行完整的匹配流程"""
        import time
        
        print("\n" + "="*70)
        print("固件函数识别引擎 v2.0")
        print("="*70)
        
        phases = [
            ("phase1", "唯一字符串直接匹配", self.phase1_unique_string_match),
            ("phase2", "字符串集合匹配", self.phase2_string_set_match),
            ("phase3", "调用图谱匹配", self.phase3_callgraph_match),
            ("phase4", "混合特征匹配", self.phase4_hybrid_match),
            ("phase5", "迭代传播", self.phase5_iterative_propagation),
        ]
        
        for phase_id, phase_name, phase_func in phases:
            start_time = time.time()
            phase_func()
            elapsed = time.time() - start_time
            
            # 统计当前阶段结果
            confirmed_count = len(self.confirmed_matches)
            candidate_count = sum(len(c) for c in self.candidates.values())
            avg_conf = sum(c[1] for c in self.confirmed_matches.values()) / confirmed_count if confirmed_count else 0
            
            self.out_conn.execute(
                'INSERT INTO statistics VALUES (?, ?, ?, ?, ?)',
                (phase_id, confirmed_count, candidate_count, avg_conf, elapsed)
            )
            self.out_conn.commit()
        
        self._export_results()
        self._print_summary()
        print("\n✅ 匹配完成！结果已保存到数据库。")
    
    def phase1_unique_string_match(self):
        """
        阶段1：唯一字符串直接匹配
        如果一个字符串只在源码的一个函数和二进制的一个函数中出现，直接匹配
        置信度：0.95
        """
        print("\n[阶段 1/5] 唯一字符串直接匹配...")
        
        # 统计每个字符串在源码和二进制中的出现次数
        src_string_funcs = defaultdict(set)
        bin_string_funcs = defaultdict(set)
        
        for func_id, strings in self.src_func_strings.items():
            for s in strings:
                src_string_funcs[s].add(func_id)
        
        for func_id, strings in self.bin_func_strings.items():
            for s in strings:
                bin_string_funcs[s].add(func_id)
        
        # 找出唯一字符串
        matches = 0
        for string in src_string_funcs.keys() & bin_string_funcs.keys():
            src_funcs = src_string_funcs[string]
            bin_funcs = bin_string_funcs[string]
            
            # 只在各自一个函数中出现
            if len(src_funcs) == 1 and len(bin_funcs) == 1:
                src_id = list(src_funcs)[0]
                bin_id = list(bin_funcs)[0]
                
                # 避免重复匹配
                if bin_id not in self.confirmed_matches:
                    confidence = 0.95  # 唯一字符串匹配置信度极高
                    self.confirmed_matches[bin_id] = (src_id, confidence, 'unique_string')
                    self._log_match('phase1', bin_id, src_id, confidence, 
                                  f'unique_string: "{string[:60]}"')
                    matches += 1
        
        print(f"  ✅ 通过唯一字符串确认了 {matches} 个匹配")
    
    def phase2_string_set_match(self):
        """
        阶段2：字符串集合匹配
        使用 Jaccard 相似度 + 加权相似度（考虑字符串稀有度）
        置信度：0.6 - 0.9
        """
        print("\n[阶段 2/5] 字符串集合匹配...")
        
        matches = 0
        for bin_id, bin_strs in self.bin_func_strings.items():
            if bin_id in self.confirmed_matches:
                continue
            
            if not bin_strs:
                continue
            
            for src_id, src_strs in self.src_func_strings.items():
                if not src_strs:
                    continue
                
                jaccard, weighted_sim, shared_count = self._calculate_string_similarity(bin_strs, src_strs)
                
                if shared_count == 0:
                    continue
                
                # 综合得分：加权相似度占主导（因为考虑了字符串稀有度）
                combined_score = 0.35 * jaccard + 0.65 * weighted_sim
                
                if combined_score > 0.25:  # 候选阈值
                    self.candidates[bin_id].append((src_id, combined_score, 'string_set'))
                    self._log_match('phase2', bin_id, src_id, combined_score, 
                                  f'jaccard={jaccard:.3f}, weighted={weighted_sim:.3f}, shared={shared_count}')
        
        # 提取高置信度匹配（> 0.75）
        for bin_id, cands in list(self.candidates.items()):
            if bin_id in self.confirmed_matches:
                continue
            
            cands.sort(key=lambda x: -x[1])
            
            # 如果最高分远超第二名，且分数够高，直接确认
            if cands and cands[0][1] > 0.75:
                if len(cands) == 1 or (cands[0][1] - cands[1][1] > 0.15):
                    src_id, score, method = cands[0]
                    self.confirmed_matches[bin_id] = (src_id, score, method)
                    matches += 1
        
        print(f"  ✅ 通过字符串集合确认了 {matches} 个匹配")
        print(f"  📋 生成了 {sum(len(c) for c in self.candidates.values())} 个候选匹配")
    
    def phase3_callgraph_match(self):
        """
        阶段3：调用图谱匹配
        基于已确认的匹配，利用调用关系进行结构匹配
        置信度：0.5 - 0.85
        """
        print("\n[阶段 3/5] 调用图谱匹配...")
        
        if not self.confirmed_matches:
            print("  ⚠️  没有已确认的匹配，跳过调用图匹配")
            return
        
        matches = 0
        
        # 关键优化：只对已有字符串候选的函数对做调用图增强
        # 而不是暴力 O(N×M) 遍历所有组合
        # 策略：
        #   ① 已有候选的 bin 函数 → 直接对候选 src 计算调用图加成
        #   ② 无候选的 bin 函数   → 通过"邻居已确认"推断
        
        # ① 对已有候选的 bin 函数做调用图增强
        for bin_id, cands in list(self.candidates.items()):
            if bin_id in self.confirmed_matches:
                continue

            bin_graph = self.bin_call_graph[bin_id]
            if not bin_graph['callers'] and not bin_graph['callees']:
                continue

            for i, (src_id, cand_score, cand_method) in enumerate(cands):
                src_graph = self.src_call_graph[src_id]
                if not src_graph['callers'] and not src_graph['callees']:
                    continue

                call_sim = self._calculate_call_similarity(bin_id, src_id)
                if call_sim > 0.1:
                    new_score = cand_score * 0.6 + call_sim * 0.4
                    cands[i] = (src_id, new_score, 'string+callgraph')
                    self._log_match('phase3', bin_id, src_id, call_sim,
                                  f'call_similarity={call_sim:.3f}')

        # ② 无候选的 bin 函数：通过邻居推断
        # 构建 src_to_bin 反向映射（已确认的）
        src_to_bin = {s: b for b, (s, _, _) in self.confirmed_matches.items()}

        for bin_id in self.bin_func_info.keys():
            if bin_id in self.confirmed_matches or bin_id in self.candidates:
                continue

            bin_graph = self.bin_call_graph[bin_id]

            # 找 bin 函数的邻居中已确认的，推导可能的 src 邻居
            neighbor_src_candidates = set()
            for nb in list(bin_graph['callers']) + list(bin_graph['callees']):
                if nb in self.confirmed_matches:
                    nb_src = self.confirmed_matches[nb][0]
                    # 把 nb_src 的邻居加入候选
                    neighbor_src_candidates.update(self.src_call_graph[nb_src]['callers'])
                    neighbor_src_candidates.update(self.src_call_graph[nb_src]['callees'])

            for src_id in neighbor_src_candidates:
                if src_id not in self.src_func_info:
                    continue
                call_sim = self._calculate_call_similarity(bin_id, src_id)
                if call_sim > 0.3:
                    self.candidates[bin_id].append((src_id, call_sim * 0.8, 'callgraph'))
                    self._log_match('phase3', bin_id, src_id, call_sim,
                                  f'neighbor_infer, call_similarity={call_sim:.3f}')
        
        # 提取高置信度匹配
        for bin_id, cands in list(self.candidates.items()):
            if bin_id in self.confirmed_matches:
                continue
            
            cands.sort(key=lambda x: -x[1])
            
            if cands and cands[0][1] > 0.70:
                src_id, score, method = cands[0]
                self.confirmed_matches[bin_id] = (src_id, score, method)
                matches += 1
        
        print(f"  ✅ 通过调用图谱确认了 {matches} 个匹配")
    
    def phase4_hybrid_match(self):
        """
        阶段4：混合特征匹配
        综合字符串、调用图、函数规模等多维度特征
        置信度：0.7 - 0.95
        """
        print("\n[阶段 4/5] 混合特征匹配...")
        
        matches = 0
        
        for bin_id, cands in list(self.candidates.items()):
            if bin_id in self.confirmed_matches:
                continue
            
            if not cands:
                continue
            
            bin_strs = self.bin_func_strings.get(bin_id, set())
            bin_size = self.bin_func_info[bin_id]['size']
            
            enhanced_scores = []
            
            for src_id, base_score, method in cands:
                # 跳过未加载的 src_id（如 is_def=0 的函数声明）
                if src_id not in self.src_func_info:
                    continue
                src_strs = self.src_func_strings.get(src_id, set())
                src_size = self.src_func_info[src_id]['size']
                
                # 1. 字符串相似度
                if bin_strs and src_strs:
                    jaccard, weighted_sim, shared_count = self._calculate_string_similarity(bin_strs, src_strs)
                    string_score = 0.4 * jaccard + 0.6 * weighted_sim
                else:
                    string_score = 0
                
                # 2. 调用图相似度
                call_score = self._calculate_call_similarity(bin_id, src_id)
                
                # 3. 函数规模相似度
                if bin_size > 0 and src_size > 0:
                    size_ratio = min(bin_size, src_size) / max(bin_size, src_size)
                    size_score = size_ratio
                else:
                    size_score = 0.5  # 无法比较时给中性分
                
                # 4. 综合得分（加权平均）
                hybrid_score = (
                    0.50 * string_score +
                    0.35 * call_score +
                    0.15 * size_score
                )
                
                enhanced_scores.append((src_id, hybrid_score, 'hybrid'))
                self._log_match('phase4', bin_id, src_id, hybrid_score,
                              f'string={string_score:.3f}, call={call_score:.3f}, size={size_score:.3f}')
            
            # 更新候选列表
            self.candidates[bin_id] = enhanced_scores
            enhanced_scores.sort(key=lambda x: -x[1])
            
            # 确认高置信度匹配
            if enhanced_scores and enhanced_scores[0][1] > 0.70:
                # 检查是否显著优于第二名
                if len(enhanced_scores) == 1 or (enhanced_scores[0][1] - enhanced_scores[1][1] > 0.10):
                    src_id, score, method = enhanced_scores[0]
                    self.confirmed_matches[bin_id] = (src_id, score, method)
                    matches += 1
        
        print(f"  ✅ 通过混合特征确认了 {matches} 个匹配")
    
    def phase5_iterative_propagation(self, max_iterations: int = 5):
        """
        阶段5：迭代传播
        利用已确认的匹配，向邻居函数传播置信度
        每轮迭代都会提升部分候选的得分，直到收敛
        """
        print("\n[阶段 5/5] 迭代传播...")
        
        total_new_matches = 0
        
        for iteration in range(max_iterations):
            new_matches = 0
            
            # 构建当前的映射关系
            bin_to_src = {b: s for b, (s, _, _) in self.confirmed_matches.items()}
            
            # 遍历所有候选
            for bin_id, cands in list(self.candidates.items()):
                if bin_id in self.confirmed_matches:
                    continue
                
                if not cands:
                    continue
                
                bin_graph = self.bin_call_graph[bin_id]
                
                # 计算每个候选的传播加成
                propagation_scores = []
                
                for src_id, base_score, method in cands:
                    # 跳过未加载的 src_id
                    if src_id not in self.src_func_info:
                        continue
                    src_graph = self.src_call_graph[src_id]
                    
                    # 统计邻居匹配度
                    caller_matches = 0
                    caller_total = 0
                    for bin_caller in bin_graph['callers']:
                        if bin_caller in bin_to_src:
                            caller_total += 1
                            if bin_to_src[bin_caller] in src_graph['callers']:
                                caller_matches += 1
                    
                    callee_matches = 0
                    callee_total = 0
                    for bin_callee in bin_graph['callees']:
                        if bin_callee in bin_to_src:
                            callee_total += 1
                            if bin_to_src[bin_callee] in src_graph['callees']:
                                callee_matches += 1
                    
                    # 计算传播加成
                    neighbor_total = caller_total + callee_total
                    neighbor_matches = caller_matches + callee_matches
                    
                    if neighbor_total > 0:
                        propagation_bonus = (neighbor_matches / neighbor_total) * 0.20
                    else:
                        propagation_bonus = 0
                    
                    # 新得分 = 原得分 + 传播加成
                    new_score = min(base_score + propagation_bonus, 0.98)
                    propagation_scores.append((src_id, new_score, f'{method}+propagation'))
                
                # 更新候选列表
                self.candidates[bin_id] = propagation_scores
                propagation_scores.sort(key=lambda x: -x[1])
                
                # 确认高置信度匹配
                if propagation_scores and propagation_scores[0][1] > 0.68:
                    if len(propagation_scores) == 1 or (propagation_scores[0][1] - propagation_scores[1][1] > 0.12):
                        src_id, score, method = propagation_scores[0]
                        self.confirmed_matches[bin_id] = (src_id, score, method)
                        new_matches += 1
                        self._log_match('phase5', bin_id, src_id, score,
                                      f'iteration={iteration+1}, propagation_bonus')
            
            total_new_matches += new_matches
            print(f"  第 {iteration+1} 轮迭代：新增 {new_matches} 个匹配")
            
            if new_matches == 0:
                print(f"  收敛于第 {iteration+1} 轮")
                break
        
        print(f"  ✅ 通过迭代传播确认了 {total_new_matches} 个匹配")
    
    def _export_results(self):
        """导出最终结果到数据库"""
        print("\n正在导出结果...")
        
        # 1. 导出确认的匹配
        for bin_id, (src_id, confidence, method) in self.confirmed_matches.items():
            bin_info = self.bin_func_info.get(bin_id)
            src_info = self.src_func_info.get(src_id)

            # 跳过数据缺失的条目
            if not bin_info or not src_info:
                continue
            
            bin_strs = self.bin_func_strings.get(bin_id, set())
            src_strs = self.src_func_strings.get(src_id, set())
            shared_strings = len(bin_strs & src_strs)
            
            call_sim = self._calculate_call_similarity(bin_id, src_id)
            
            self.out_conn.execute('''
                INSERT INTO mapping_results 
                (bin_func_id, bin_address, src_func_id, src_func_name, src_file_path, 
                 confidence, method, shared_strings, call_similarity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                bin_id,
                bin_info['address'],
                src_id,
                src_info['name'],
                src_info['file_path'],
                confidence,
                method,
                shared_strings,
                call_sim
            ))
        
        # 2. 导出候选匹配（未确认的）
        for bin_id, cands in self.candidates.items():
            if bin_id in self.confirmed_matches:
                continue
            
            for src_id, score, method in cands[:5]:  # 只保留 top-5
                self.out_conn.execute('''
                    INSERT INTO mapping_candidates VALUES (?, ?, ?, ?)
                ''', (bin_id, src_id, score, method))
        
        self.out_conn.commit()
        print("  ✅ 结果已导出")
    
    def _print_summary(self):
        """打印匹配结果摘要"""
        print("\n" + "="*70)
        print("匹配结果摘要")
        print("="*70)
        
        total_bin = len(self.bin_func_info)
        total_src = len(self.src_func_info)
        matched = len(self.confirmed_matches)
        
        print(f"\n总体统计：")
        print(f"  二进制函数总数: {total_bin}")
        print(f"  源码函数总数: {total_src}")
        print(f"  成功匹配: {matched} ({matched/total_bin*100:.1f}%)")
        
        # 按置信度分层
        high_conf = sum(1 for _, (_, c, _) in self.confirmed_matches.items() if c > 0.85)
        mid_conf = sum(1 for _, (_, c, _) in self.confirmed_matches.items() if 0.70 <= c <= 0.85)
        low_conf = sum(1 for _, (_, c, _) in self.confirmed_matches.items() if c < 0.70)
        
        print(f"\n置信度分布：")
        print(f"  高置信度 (>0.85): {high_conf} ({high_conf/matched*100:.1f}%)")
        print(f"  中置信度 (0.70-0.85): {mid_conf} ({mid_conf/matched*100:.1f}%)")
        print(f"  低置信度 (<0.70): {low_conf} ({low_conf/matched*100:.1f}%)")
        
        # 按方法分类
        method_counts = Counter(method for _, (_, _, method) in self.confirmed_matches.items())
        print(f"\n匹配方法分布：")
        for method, count in method_counts.most_common():
            print(f"  {method}: {count}")
        
        # 查询示例
        print(f"\n查询示例：")
        print(f"  查看所有匹配: SELECT * FROM mapping_results ORDER BY confidence DESC;")
        print(f"  查看候选匹配: SELECT * FROM mapping_candidates ORDER BY score DESC;")
        print(f"  查看详细日志: SELECT * FROM mapping_log WHERE phase = 'phase1';")


def main():
    """主函数"""
    import sys
    
    if len(sys.argv) != 4:
        print("用法: python function_mapper_v2.py <源码数据库> <二进制数据库> <输出数据库>")
        print("示例: python function_mapper_v2.py source.db firmware.db results.db")
        sys.exit(1)
    
    src_db = sys.argv[1]
    bin_db = sys.argv[2]
    out_db = sys.argv[3]
    
    mapper = FunctionMapper(src_db, bin_db, out_db)
    mapper.run_all()


if __name__ == '__main__':
    main()

