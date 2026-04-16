#!/usr/bin/env python3
"""
ghidra_import_to_db.py
Reads ghidra_output.json and imports data into SQLite DB.

字符串归属策略（直接引用 + 间接引用）：
  对每条 func_string_refs，识别两种引用关系：
  1. 间接引用 (indirect)：原始 caller 函数对字符串的引用
  2. 直接引用 (direct)：ref_addr 之后最近的 call 指令的 callee 函数对字符串的引用（距离 <= 64 bytes）

  例如：main() { printf("aaa") }
  - main 对 "aaa" 是间接引用
  - printf 对 "aaa" 是直接引用

Usage:
    python3 ghidra_import_to_db.py
    python3 ghidra_import_to_db.py --json /path/to/ghidra_output.json --db /path/to/firmware.db
"""

import sqlite3
import json
import argparse
import os
import sys
from collections import defaultdict

WORK_DIR  = '/home/admin_wsl/symbol_recover'
JSON_PATH = os.path.join(WORK_DIR, 'binary', 'ghidra_output.json')
DB_PATH   = os.path.join(WORK_DIR, 'binary', 'ghidra_binary_code.db')


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db(conn):
    conn.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS binary_functions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            address     TEXT UNIQUE,
            name        TEXT,
            size        INTEGER,
            is_library  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS binary_strings (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            content TEXT,
            length  INTEGER
        );

        CREATE TABLE IF NOT EXISTS binary_func_string_refs (
            func_id     INTEGER,
            string_id   INTEGER,
            ref_addr    TEXT,
            ref_type    TEXT DEFAULT 'direct',  -- 'direct' or 'indirect'
            PRIMARY KEY (func_id, string_id, ref_addr, ref_type),
            FOREIGN KEY (func_id)   REFERENCES binary_functions(id) ON DELETE CASCADE,
            FOREIGN KEY (string_id) REFERENCES binary_strings(id)   ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS binary_call_graph (
            caller_id   INTEGER,
            callee_id   INTEGER,
            call_addr   TEXT,
            PRIMARY KEY (caller_id, callee_id, call_addr),
            FOREIGN KEY (caller_id) REFERENCES binary_functions(id) ON DELETE CASCADE,
            FOREIGN KEY (callee_id) REFERENCES binary_functions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_bin_func_addr ON binary_functions(address);
        CREATE INDEX IF NOT EXISTS idx_bin_func_name ON binary_functions(name);
        CREATE INDEX IF NOT EXISTS idx_bin_str_addr  ON binary_strings(address);
        CREATE INDEX IF NOT EXISTS idx_bin_caller    ON binary_call_graph(caller_id);
        CREATE INDEX IF NOT EXISTS idx_bin_callee    ON binary_call_graph(callee_id);
    ''')
    conn.commit()
    print('[+] Schema ready')


# ── Import functions ──────────────────────────────────────────────────────────

def import_functions(cursor, functions):
    rows = [(f['address'], f['name'], f['size'], f['is_library']) for f in functions]
    cursor.executemany(
        'INSERT OR IGNORE INTO binary_functions (address, name, size, is_library) VALUES (?,?,?,?)',
        rows
    )
    print('[+] Functions inserted: {}'.format(len(rows)))


def import_strings(cursor, strings):
    rows = [(s['address'], s['content'], s['length']) for s in strings]
    cursor.executemany(
        'INSERT OR IGNORE INTO binary_strings (address, content, length) VALUES (?,?,?)',
        rows
    )
    print('[+] Strings inserted: {}'.format(len(rows)))


# ── Import call graph ─────────────────────────────────────────────────────────

def import_call_graph(cursor, call_graph):
    inserted = 0
    skipped  = 0
    for edge in call_graph:
        cursor.execute('SELECT id FROM binary_functions WHERE address=?', (edge['caller'],))
        row = cursor.fetchone()
        if row is None:
            skipped += 1
            continue
        caller_id = row[0]

        cursor.execute('SELECT id FROM binary_functions WHERE address=?', (edge['callee'],))
        row = cursor.fetchone()
        if row is None:
            skipped += 1
            continue
        callee_id = row[0]

        cursor.execute(
            'INSERT OR IGNORE INTO binary_call_graph (caller_id, callee_id, call_addr) VALUES (?,?,?)',
            (caller_id, callee_id, edge['call_addr'])
        )
        inserted += 1

    print('[+] Call graph edges inserted: {} (skipped: {})'.format(inserted, skipped))


# ── Import func-string refs ───────────────────────────────────────────────────

def _build_call_index(call_graph):
    """
    构建 caller_addr -> sorted [(call_addr_int, callee_addr), ...] 索引。
    """
    index = defaultdict(list)
    for edge in call_graph:
        index[edge['caller']].append((int(edge['call_addr'], 16), edge['callee']))
    for lst in index.values():
        lst.sort(key=lambda x: x[0])
    return index


def _find_callee(ref_addr_int, caller_addr, call_index, max_dist=64):
    """
    在 caller 的 call 列表中，找 ref_addr 之后最近且距离 <= max_dist 的 callee。
    找不到返回 None。
    """
    for call_addr_int, callee_addr in call_index.get(caller_addr, []):
        if call_addr_int > ref_addr_int:
            if call_addr_int - ref_addr_int <= max_dist:
                return callee_addr
            break
    return None


def import_func_string_refs(cursor, refs, call_graph):
    """
    将字符串引用分为直接引用和间接引用：
    - 直接引用：ref_addr 之后最近的 call 的 callee 函数（距离 <= 64 bytes）
    - 间接引用：原始的 caller 函数

    例如：main() { printf("aaa") }
    - main 对 "aaa" 是间接引用 (indirect)
    - printf 对 "aaa" 是直接引用 (direct)
    """
    call_index = _build_call_index(call_graph)
    inserted_direct = 0
    inserted_indirect = 0
    skipped  = 0
    fallback = 0

    for ref in refs:
        cursor.execute('SELECT id FROM binary_strings WHERE address=?', (ref['string_addr'],))
        row = cursor.fetchone()
        if row is None:
            skipped += 1
            continue
        string_id = row[0]

        ref_addr_int = int(ref['ref_addr'], 16)
        caller_addr  = ref['func_addr']
        callee_addr  = _find_callee(ref_addr_int, caller_addr, call_index)

        # 获取 caller 的 func_id（用于间接引用）
        cursor.execute('SELECT id FROM binary_functions WHERE address=?', (caller_addr,))
        row = cursor.fetchone()
        if row is None:
            skipped += 1
            continue
        caller_id = row[0]

        # 插入间接引用：caller -> string (indirect)
        cursor.execute(
            'INSERT OR IGNORE INTO binary_func_string_refs (func_id, string_id, ref_addr, ref_type) VALUES (?,?,?,?)',
            (caller_id, string_id, ref['ref_addr'], 'indirect')
        )
        inserted_indirect += 1

        # 如果找到了 callee，插入直接引用：callee -> string (direct)
        if callee_addr:
            cursor.execute('SELECT id FROM binary_functions WHERE address=?', (callee_addr,))
            row = cursor.fetchone()
            if row is not None:
                callee_id = row[0]
                cursor.execute(
                    'INSERT OR IGNORE INTO binary_func_string_refs (func_id, string_id, ref_addr, ref_type) VALUES (?,?,?,?)',
                    (callee_id, string_id, ref['ref_addr'], 'direct')
                )
                inserted_direct += 1
            else:
                skipped += 1
        else:
            # 找不到 callee，只有间接引用
            fallback += 1

    print('[+] Func-string refs inserted: {} direct, {} indirect (skipped: {}, no callee found: {})'.format(
        inserted_direct, inserted_indirect, skipped, fallback))


# ── Stats ─────────────────────────────────────────────────────────────────────

def print_stats(conn):
    tables = ['binary_functions', 'binary_strings', 'binary_func_string_refs', 'binary_call_graph']
    print('\n[*] Database summary:')
    for t in tables:
        count = conn.execute('SELECT COUNT(*) FROM {}'.format(t)).fetchone()[0]
        print('    {:35s} {:>8} rows'.format(t, count))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Import Ghidra JSON output into SQLite DB')
    parser.add_argument('--json', default=JSON_PATH, help='Path to ghidra_output.json')
    parser.add_argument('--db',   default=DB_PATH,   help='Path to output SQLite database')
    args = parser.parse_args()

    if not os.path.exists(args.json):
        print('[!] JSON file not found: {}'.format(args.json))
        sys.exit(1)

    print('[*] Loading: {}'.format(args.json))
    with open(args.json, 'r') as f:
        data = json.load(f)

    print('[*] Program : {}'.format(data.get('program', '?')))
    print('[*] Base    : {}'.format(data.get('image_base', '?')))

    conn   = sqlite3.connect(args.db)
    cursor = conn.cursor()

    init_db(conn)

    print('\n[*] Importing functions...')
    import_functions(cursor, data.get('functions', []))

    print('[*] Importing strings...')
    import_strings(cursor, data.get('strings', []))
    conn.commit()

    print('[*] Importing call graph...')
    import_call_graph(cursor, data.get('call_graph', []))
    conn.commit()

    print('[*] Importing func-string refs (direct + indirect)...')
    import_func_string_refs(cursor, data.get('func_string_refs', []), data.get('call_graph', []))
    conn.commit()

    print_stats(conn)
    conn.close()
    print('\n[+] Done. DB saved to: {}'.format(args.db))


if __name__ == '__main__':
    main()
