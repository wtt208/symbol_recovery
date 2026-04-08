#!/usr/bin/env python3
"""
结果查询和分析工具
==================
用于查询和分析 function_mapper_v2.py 的输出结果
"""

import sqlite3
import sys
from typing import Optional

class ResultAnalyzer:
    def __init__(self, result_db: str):
        self.conn = sqlite3.connect(result_db)
        self.conn.row_factory = sqlite3.Row
    
    def show_summary(self):
        """显示匹配结果摘要"""
        print("\n" + "="*80)
        print("匹配结果摘要")
        print("="*80)
        
        # 总体统计
        cursor = self.conn.execute('''
            SELECT 
                COUNT(*) as total,
                AVG(confidence) as avg_conf,
                MIN(confidence) as min_conf,
                MAX(confidence) as max_conf
            FROM mapping_results
        ''')
        row = cursor.fetchone()
        
        print(f"\n总体统计：")
        print(f"  匹配总数: {row['total']}")
        print(f"  平均置信度: {row['avg_conf']:.3f}")
        print(f"  置信度范围: {row['min_conf']:.3f} - {row['max_conf']:.3f}")
        
        # 置信度分布
        cursor = self.conn.execute('''
            SELECT 
                CASE 
                    WHEN confidence > 0.85 THEN 'high'
                    WHEN confidence >= 0.70 THEN 'medium'
                    ELSE 'low'
                END as level,
                COUNT(*) as count
            FROM mapping_results
            GROUP BY level
        ''')
        
        print(f"\n置信度分布：")
        for row in cursor:
            level_name = {'high': '高 (>0.85)', 'medium': '中 (0.70-0.85)', 'low': '低 (<0.70)'}
            print(f"  {level_name.get(row['level'], row['level'])}: {row['count']}")
        
        # 方法分布
        cursor = self.conn.execute('''
            SELECT method, COUNT(*) as count
            FROM mapping_results
            GROUP BY method
            ORDER BY count DESC
        ''')
        
        print(f"\n匹配方法分布：")
        for row in cursor:
            print(f"  {row['method']}: {row['count']}")
        
        # 阶段统计
        cursor = self.conn.execute('''
            SELECT phase, confirmed_count, candidate_count, avg_confidence, execution_time
            FROM statistics
            ORDER BY phase
        ''')
        
        print(f"\n各阶段统计：")
        print(f"  {'阶段':<15} {'确认数':<10} {'候选数':<10} {'平均置信度':<12} {'耗时(秒)'}")
        print(f"  {'-'*60}")
        for row in cursor:
            print(f"  {row['phase']:<15} {row['confirmed_count']:<10} {row['candidate_count']:<10} "
                  f"{row['avg_confidence']:<12.3f} {row['execution_time']:.2f}")
    
    def show_top_matches(self, limit: int = 20, min_confidence: float = 0.0):
        """显示置信度最高的匹配"""
        print(f"\n" + "="*80)
        print(f"Top {limit} 匹配结果 (置信度 >= {min_confidence})")
        print("="*80)
        
        cursor = self.conn.execute('''
            SELECT 
                bin_address,
                src_func_name,
                src_file_path,
                confidence,
                method,
                shared_strings,
                call_similarity
            FROM mapping_results
            WHERE confidence >= ?
            ORDER BY confidence DESC
            LIMIT ?
        ''', (min_confidence, limit))
        
        print(f"\n{'二进制地址':<18} {'源码函数':<30} {'置信度':<10} {'方法':<20}")
        print("-"*80)
        
        for row in cursor:
            print(f"{row['bin_address']:<18} {row['src_func_name']:<30} "
                  f"{row['confidence']:<10.3f} {row['method']:<20}")
            if row['shared_strings'] > 0:
                print(f"  └─ 共享字符串: {row['shared_strings']}, 调用相似度: {row['call_similarity']:.3f}")
    
    def show_candidates(self, bin_func_id: Optional[int] = None, limit: int = 10):
        """显示候选匹配（未确认的）"""
        print(f"\n" + "="*80)
        print("候选匹配（未确认）")
        print("="*80)
        
        if bin_func_id:
            cursor = self.conn.execute('''
                SELECT mc.*, f.name as src_name
                FROM mapping_candidates mc
                JOIN functions f ON mc.src_func_id = f.id
                WHERE mc.bin_func_id = ?
                ORDER BY mc.score DESC
            ''', (bin_func_id,))
        else:
            cursor = self.conn.execute('''
                SELECT mc.*, f.name as src_name
                FROM mapping_candidates mc
                JOIN functions f ON mc.src_func_id = f.id
                ORDER BY mc.score DESC
                LIMIT ?
            ''', (limit,))
        
        print(f"\n{'二进制ID':<12} {'源码函数':<30} {'得分':<10} {'方法':<20}")
        print("-"*80)
        
        for row in cursor:
            print(f"{row['bin_func_id']:<12} {row['src_name']:<30} "
                  f"{row['score']:<10.3f} {row['method']:<20}")
    
    def search_by_name(self, name_pattern: str):
        """按函数名搜索"""
        print(f"\n搜索结果: '{name_pattern}'")
        print("="*80)
        
        cursor = self.conn.execute('''
            SELECT 
                bin_address,
                src_func_name,
                src_file_path,
                confidence,
                method
            FROM mapping_results
            WHERE src_func_name LIKE ?
            ORDER BY confidence DESC
        ''', (f'%{name_pattern}%',))
        
        results = cursor.fetchall()
        if not results:
            print("未找到匹配结果")
            return
        
        print(f"\n找到 {len(results)} 个结果：\n")
        for row in results:
            print(f"  {row['bin_address']} -> {row['src_func_name']}")
            print(f"    文件: {row['src_file_path']}")
            print(f"    置信度: {row['confidence']:.3f} ({row['method']})")
            print()
    
    def export_to_ida(self, output_file: str):
        """导出为 IDA Python 脚本"""
        print(f"\n正在导出 IDA 脚本到 {output_file}...")
        
        cursor = self.conn.execute('''
            SELECT bin_address, src_func_name, confidence
            FROM mapping_results
            WHERE confidence >= 0.70
            ORDER BY confidence DESC
        ''')
        
        with open(output_file, 'w') as f:
            f.write("# IDA Python 脚本 - 自动重命名函数\n")
            f.write("# 由 function_mapper_v2.py 生成\n\n")
            f.write("import idaapi\n")
            f.write("import idc\n\n")
            f.write("def rename_functions():\n")
            f.write("    renamed = 0\n")
            f.write("    failed = 0\n\n")
            
            for row in cursor:
                addr = row['bin_address']
                name = row['src_func_name']
                conf = row['confidence']
                
                f.write(f"    # 置信度: {conf:.3f}\n")
                f.write(f"    if idc.set_name(0x{addr}, '{name}', idc.SN_CHECK):\n")
                f.write(f"        renamed += 1\n")
                f.write(f"    else:\n")
                f.write(f"        failed += 1\n")
                f.write(f"        print(f'Failed to rename 0x{addr} to {name}')\n\n")
            
            f.write("    print(f'重命名完成: {renamed} 成功, {failed} 失败')\n\n")
            f.write("if __name__ == '__main__':\n")
            f.write("    rename_functions()\n")
        
        print(f"  ✅ 已导出到 {output_file}")
        print(f"  使用方法: 在 IDA 中 File -> Script file -> 选择该文件")


def main():
    if len(sys.argv) < 2:
        print("用法: python analyze_results.py <结果数据库> [命令]")
        print("\n可用命令:")
        print("  summary              - 显示摘要统计")
        print("  top [N] [min_conf]   - 显示 Top N 匹配 (默认 20)")
        print("  candidates [N]       - 显示候选匹配 (默认 10)")
        print("  search <name>        - 按函数名搜索")
        print("  export_ida <file>    - 导出 IDA 脚本")
        sys.exit(1)
    
    result_db = sys.argv[1]
    analyzer = ResultAnalyzer(result_db)
    
    if len(sys.argv) == 2:
        # 默认显示摘要
        analyzer.show_summary()
        analyzer.show_top_matches(20)
    else:
        command = sys.argv[2]
        
        if command == 'summary':
            analyzer.show_summary()
        
        elif command == 'top':
            limit = int(sys.argv[3]) if len(sys.argv) > 3 else 20
            min_conf = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
            analyzer.show_top_matches(limit, min_conf)
        
        elif command == 'candidates':
            limit = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            analyzer.show_candidates(limit=limit)
        
        elif command == 'search':
            if len(sys.argv) < 4:
                print("错误: 需要提供搜索关键词")
                sys.exit(1)
            analyzer.search_by_name(sys.argv[3])
        
        elif command == 'export_ida':
            if len(sys.argv) < 4:
                print("错误: 需要提供输出文件名")
                sys.exit(1)
            analyzer.export_to_ida(sys.argv[3])
        
        else:
            print(f"未知命令: {command}")
            sys.exit(1)


if __name__ == '__main__':
    main()
