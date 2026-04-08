#!/usr/bin/env python3
"""
并行源码分析调度器 v2
用法: python3 parallel_analyzer.py <目标源码目录> <输出数据库路径> [进程数]
"""

import os
import sys
import time
import multiprocessing
import sqlite3
from pathlib import Path

# 引用原分析器模块（确保 source_analyzer.py 在同目录下）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from source_analyzer import SourceAnalyzer, init_db, LANG_EXT_MAP, SKIP_DIRS


# ============================================================
# 子进程任务
# ============================================================

def process_chunk(args):
    """
    子进程任务：分析分配到的文件列表，写入独立临时库
    使用单参数元组以兼容 pool.map
    """
    file_list, temp_db_path, worker_id = args
    try:
        analyzer = SourceAnalyzer(temp_db_path)
        for file_path in file_list:
            try:
                analyzer.analyze_file(file_path)
            except Exception as e:
                # 单文件失败不影响整个 worker
                print(f"  [worker-{worker_id}] ✗ 跳过 {file_path}: {e}")
        analyzer.close()
        return (worker_id, len(file_list), True)
    except Exception as e:
        print(f"  [worker-{worker_id}] 进程崩溃: {e}")
        return (worker_id, len(file_list), False)


# ============================================================
# 合并逻辑：直接读数据，不用 ATTACH
# ============================================================

def merge_databases(temp_dbs, final_db):
    """
    将多个临时数据库合并到最终数据库
    核心改动：不使用 ATTACH，改为逐行读取后写入，彻底避免 "already in use" 问题
    """
    print(f"\n正在合并 {len(temp_dbs)} 个临时数据库 -> {final_db}")

    final_conn = sqlite3.connect(final_db)
    final_conn.execute("PRAGMA journal_mode=WAL")
    final_conn.execute("PRAGMA synchronous=NORMAL")
    init_db(final_conn)
    cur = final_conn.cursor()

    for idx, db_path in enumerate(temp_dbs):
        if not os.path.exists(db_path):
            print(f"  [{idx}] 临时库不存在，跳过: {db_path}")
            continue

        print(f"  合并 [{idx+1}/{len(temp_dbs)}] {db_path} ...")
        tmp_conn = sqlite3.connect(db_path)
        tmp_conn.row_factory = sqlite3.Row

        # ---- 1. 合并 functions，记录旧 id -> 新 id 的映射 ----
        func_id_map = {}  # old_id -> new_id
        for row in tmp_conn.execute("SELECT * FROM functions"):
            cur.execute(
                "INSERT OR IGNORE INTO functions "
                "(name, file_path, line_start, line_end, hash, is_def) "
                "VALUES (?,?,?,?,?,?)",
                (row["name"], row["file_path"], row["line_start"],
                 row["line_end"], row["hash"], row["is_def"])
            )
            # 无论是否新插入，都查出最终 id
            cur.execute("SELECT id FROM functions WHERE hash = ?", (row["hash"],))
            new_id = cur.fetchone()[0]
            func_id_map[row["id"]] = new_id

        # ---- 2. 合并 strings，记录旧 id -> 新 id 的映射 ----
        str_id_map = {}
        for row in tmp_conn.execute("SELECT * FROM strings"):
            cur.execute(
                "INSERT OR IGNORE INTO strings (content, length) VALUES (?,?)",
                (row["content"], row["length"])
            )
            cur.execute("SELECT id FROM strings WHERE content = ?", (row["content"],))
            new_id = cur.fetchone()[0]
            str_id_map[row["id"]] = new_id

        # ---- 3. 合并 function_string_map（用映射后的 id）----
        for row in tmp_conn.execute("SELECT * FROM function_string_map"):
            new_func_id = func_id_map.get(row["function_id"])
            new_str_id  = str_id_map.get(row["string_id"])
            if new_func_id and new_str_id:
                cur.execute(
                    "INSERT INTO function_string_map (function_id, string_id, usage_count) "
                    "VALUES (?,?,?) ON CONFLICT(function_id, string_id) "
                    "DO UPDATE SET usage_count = usage_count + excluded.usage_count",
                    (new_func_id, new_str_id, row["usage_count"])
                )

        # ---- 4. 合并 source_call_graph（用映射后的 id）----
        for row in tmp_conn.execute("SELECT * FROM source_call_graph"):
            new_caller = func_id_map.get(row["caller_id"])
            new_callee = func_id_map.get(row["callee_id"])
            if new_caller and new_callee:
                cur.execute(
                    "INSERT OR IGNORE INTO source_call_graph "
                    "(caller_id, callee_id, call_line) VALUES (?,?,?)",
                    (new_caller, new_callee, row["call_line"])
                )

        tmp_conn.close()
        final_conn.commit()  # 每合并完一个临时库就 commit 一次

        # 删除临时库
        os.remove(db_path)
        print(f"    ✓ 已合并并删除 {db_path}")

    final_conn.close()
    print("✅ 合并完成！")


# ============================================================
# 主流程
# ============================================================

def scan_files(target_dir):
    """扫描目录下所有支持的源码文件"""
    all_files = []
    exts = set(LANG_EXT_MAP.keys())

    for root, dirs, files in os.walk(target_dir):
        # 跳过无用目录
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if Path(f).suffix.lower() in exts:
                all_files.append(os.path.join(root, f))

    return all_files


def main():
    if len(sys.argv) < 3:
        print("用法: python3 parallel_analyzer.py <目录> <输出库> [进程数]")
        print("示例: python3 parallel_analyzer.py ./linux-src source_code.db 8")
        sys.exit(1)

    target_dir = sys.argv[1]
    final_db   = sys.argv[2]
    n_workers  = int(sys.argv[3]) if len(sys.argv) > 3 else multiprocessing.cpu_count()

    if not os.path.isdir(target_dir):
        print(f"错误: 目录不存在 -> {target_dir}")
        sys.exit(1)

    # 1. 扫描文件
    print(f"扫描目录: {os.path.abspath(target_dir)}")
    all_files = scan_files(target_dir)
    total = len(all_files)
    if total == 0:
        print("未找到任何支持的源码文件")
        sys.exit(0)

    print(f"找到 {total} 个源码文件，使用 {n_workers} 个进程并发分析")

    # 2. 均匀分块（按文件大小排序后交叉分配，避免某个 worker 全拿大文件）
    all_files.sort(key=lambda f: os.path.getsize(f), reverse=True)
    chunks = [[] for _ in range(n_workers)]
    for i, f in enumerate(all_files):
        chunks[i % n_workers].append(f)

    # 3. 生成临时库路径（放在输出库同目录下）
    out_dir  = os.path.dirname(os.path.abspath(final_db)) or "."
    temp_dbs = [os.path.join(out_dir, f"_tmp_worker_{i}.db") for i in range(n_workers)]

    # 构建任务列表（只保留非空块）
    tasks = [
        (chunk, temp_dbs[i], i)
        for i, chunk in enumerate(chunks)
        if chunk
    ]
    actual_temp_dbs = [temp_dbs[i] for i, chunk in enumerate(chunks) if chunk]

    # 4. 并行执行
    t_start = time.time()
    print(f"\n开始并行分析...")

    with multiprocessing.Pool(processes=len(tasks)) as pool:
        results = pool.map(process_chunk, tasks)

    t_elapsed = time.time() - t_start
    success = sum(1 for _, _, ok in results if ok)
    print(f"\n并行分析完成：{success}/{len(tasks)} 个 worker 成功，耗时 {t_elapsed:.1f}s")

    # 5. 合并所有临时库
    merge_databases(actual_temp_dbs, final_db)

    # 6. 打印最终统计
    conn = sqlite3.connect(final_db)
    print("\n" + "="*60)
    print("📊 最终数据库统计")
    print("="*60)
    for table, label in [
        ("functions",           "函数总数"),
        ("strings",             "字符串总数"),
        ("function_string_map", "函数-字符串映射"),
        ("source_call_graph",   "调用关系边数"),
    ]:
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {label:<16}: {count:,}")

    def_count = conn.execute("SELECT COUNT(*) FROM functions WHERE is_def=1").fetchone()[0]
    ref_count = conn.execute("SELECT COUNT(*) FROM functions WHERE is_def=0").fetchone()[0]
    print(f"  {'  其中 函数定义':<16}: {def_count:,}")
    print(f"  {'  其中 函数调用':<16}: {ref_count:,}")
    conn.close()
    print(f"\n📁 输出数据库: {os.path.abspath(final_db)}")
    print(f"⏱  总耗时: {time.time() - t_start:.1f}s")


if __name__ == "__main__":
    main()
