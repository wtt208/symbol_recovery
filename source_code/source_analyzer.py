#!/usr/bin/env python3
"""
源码分析工具 v2 - 完整版（用于符号恢复）

新增功能：
1. 区分函数定义和函数调用（is_def 字段）
2. 建立完整的函数调用图谱（source_call_graph 表）
3. 为符号恢复提供完整的源码侧数据

数据库结构（符合符号恢复需求）：
- functions: 存储所有函数（定义+调用）
- strings: 存储所有字符串
- function_string_map: 函数与字符串的映射
- source_call_graph: 函数调用关系图谱

用法:
    venv/bin/python3 source_analyzer_v2.py [目录/文件] [数据库文件名]
"""

import os
import hashlib
import sqlite3
import traceback
from pathlib import Path
from typing import Optional, List, Dict

import sys
# 查看当前限制
print(f"当前深度限制: {sys.getrecursionlimit()}")
# 将限制提高到 5000（根据你的需求调整，但不要太大，防止物理内存溢出）
sys.setrecursionlimit(5000)
print(f"更改深度限制为: {sys.getrecursionlimit()}")

try:
    from tree_sitter_languages import get_language, get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

# ============================================================
# 数据库操作
# ============================================================

def get_db_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection):
    """初始化源码侧数据库（符合符号恢复规范）"""
    cursor = conn.cursor()

    # 函数表（区分定义和调用）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS functions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            file_path  TEXT    NOT NULL,
            line_start INTEGER,
            line_end   INTEGER,
            hash       TEXT    UNIQUE,
            is_def     INTEGER DEFAULT 1
        )
    ''')

    # 字符串表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS strings (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT    NOT NULL UNIQUE,
            length  INTEGER
        )
    ''')

    # 函数-字符串映射表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS function_string_map (
            function_id INTEGER,
            string_id   INTEGER,
            usage_count INTEGER DEFAULT 1,
            PRIMARY KEY (function_id, string_id),
            FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE CASCADE,
            FOREIGN KEY (string_id)   REFERENCES strings(id)   ON DELETE CASCADE
        )
    ''')

    # 【核心】函数调用图谱表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS source_call_graph (
            caller_id INTEGER,
            callee_id INTEGER,
            call_line INTEGER,
            PRIMARY KEY (caller_id, callee_id, call_line),
            FOREIGN KEY (caller_id) REFERENCES functions(id) ON DELETE CASCADE,
            FOREIGN KEY (callee_id) REFERENCES functions(id) ON DELETE CASCADE
        )
    ''')

    # 索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_func_name   ON functions(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_func_file   ON functions(file_path)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_func_isdef  ON functions(is_def)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_str_content ON strings(content)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_caller      ON source_call_graph(caller_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_callee      ON source_call_graph(callee_id)")

    # 兼容旧数据库
    try:
        cursor.execute("ALTER TABLE strings ADD COLUMN length INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE functions ADD COLUMN is_def INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    conn.commit()


def compute_hash(file_path: str, func_name: str, line_start: int, line_end: int) -> str:
    key = f"{file_path}:{func_name}:{line_start}:{line_end}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]


# ============================================================
# Tree-sitter 配置
# ============================================================

FUNC_NODE_TYPES = {
    'python':     {'function_definition', 'async_function_definition'},
    'javascript': {'function_declaration', 'function', 'arrow_function', 'method_definition'},
    'typescript': {'function_declaration', 'function', 'arrow_function', 'method_definition'},
    'go':         {'function_declaration', 'method_declaration'},
    'java':       {'method_declaration', 'constructor_declaration'},
    'rust':       {'function_item'},
    'c':          {'function_definition'},
    'cpp':        {'function_definition'},
}

BODY_NODE_TYPES = {
    'python':     {'block'},
    'javascript': {'statement_block'},
    'typescript': {'statement_block'},
    'go':         {'block'},
    'java':       {'block'},
    'rust':       {'block'},
    'c':          {'compound_statement'},
    'cpp':        {'compound_statement'},
}

STRING_NODE_TYPES = {
    'python':     {'string', 'concatenated_string'},
    'javascript': {'string', 'template_string'},
    'typescript': {'string', 'template_string'},
    'go':         {'interpreted_string_literal', 'raw_string_literal'},
    'java':       {'string_literal'},
    'rust':       {'string_literal', 'raw_string_literal'},
    'c':          {'string_literal'},
    'cpp':        {'string_literal', 'raw_string_literal'},
}

KEYWORD_BLACKLIST = {
    'if', 'else', 'elif', 'switch', 'case', 'default',
    'for', 'while', 'do', 'break', 'continue', 'return',
    'try', 'catch', 'finally', 'throw', 'raise', 'except',
    'class', 'struct', 'enum', 'union', 'typedef',
    'import', 'export', 'from', 'as', 'with', 'using',
    'and', 'or', 'not', 'in', 'is', 'lambda',
    'true', 'false', 'null', 'nil', 'none',
    'new', 'delete', 'sizeof', 'typeof', 'instanceof',
    'public', 'private', 'protected', 'static', 'const', 'let', 'var',
    'void', 'int', 'char', 'float', 'double', 'bool', 'string',
    'goto', 'volatile', 'register', 'extern', 'inline',
    'async', 'await', 'yield', 'match',
}

LANG_EXT_MAP = {
    '.py':   'python',
    '.js':   'javascript', '.jsx': 'javascript', '.mjs':  'javascript', '.cjs': 'javascript',
    '.ts':   'typescript', '.tsx': 'typescript', '.mts':  'typescript', '.cts': 'typescript',
    '.go':   'go',
    '.java': 'java',
    '.rs':   'rust',
    '.c':    'c', 
    '.cpp':  'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp':  'cpp', '.hxx': 'cpp',
}

SKIP_DIRS = {
    'venv', '.venv', 'env', '.env',
    '.git', '.svn', '.hg',
    '__pycache__', 'node_modules',
    'build', 'dist', '.idea', '.vscode',
}


# ============================================================
# 辅助函数
# ============================================================

def _is_valid_func_name(name: str) -> bool:
    if not name or len(name) == 0:
        return False
    if name.lower() in KEYWORD_BLACKLIST:
        return False
    return True


def _get_node_text(node) -> str:
    t = node.text
    if isinstance(t, bytes):
        return t.decode('utf-8', errors='replace')
    return t or ''


def _extract_func_name_c_cpp(node) -> Optional[str]:
    """C/C++ 专用：从 function_definition 中提取函数名"""
    for child in node.children:
        if child.type == 'function_declarator':
            for grandchild in child.children:
                if grandchild.type == 'identifier':
                    name = _get_node_text(grandchild)
                    if _is_valid_func_name(name):
                        return name
                elif grandchild.type in ('pointer_declarator', 'parenthesized_declarator'):
                    for ggchild in grandchild.children:
                        if ggchild.type == 'identifier':
                            name = _get_node_text(ggchild)
                            if _is_valid_func_name(name):
                                return name
    return None


def _collect_strings(node, str_types: set, out: list):
    """递归收集节点下所有字符串字面量"""
    if node.type in str_types:
        raw = _get_node_text(node)
        if len(raw) >= 2:
            if raw.startswith(('"""', "'''")):
                raw = raw[3:-3]
            elif raw[0] in ('"', "'", '`'):
                raw = raw[1:-1]
        out.append(raw)
        return
    for child in node.children:
        _collect_strings(child, str_types, out)


# ============================================================
# 核心解析逻辑（带调用图谱）
# ============================================================

class SourceCodeCollector:
    """源码收集器（支持调用图谱）"""
    
    def __init__(self, lang: str, file_path: str):
        self.lang = lang
        self.file_path = file_path
        self.func_types = FUNC_NODE_TYPES.get(lang, set())
        self.body_types = BODY_NODE_TYPES.get(lang, set())
        self.str_types = STRING_NODE_TYPES.get(lang, {'string_literal'})
        
        self.functions = []      # 存储所有函数定义
        self.calls = []          # 存储所有函数调用
        self.caller_stack = []   # 当前所在的函数定义栈（用于建立调用关系）
        self.visited = set()
    
    def collect(self, node):
        """迭代式遍历语法树（无递归深度限制）"""
        # 使用栈来模拟递归：(节点, 是否为退出标记, 函数信息)
        stack = [(node, False, None)]
        
        while stack:
            current_node, is_exit, func_info = stack.pop()
            node_id = id(current_node)
            
            # 防环检查
            if node_id in self.visited:
                continue
            
            # 处理退出标记（用于函数定义的 caller_stack 管理）
            if is_exit:
                if func_info and self.caller_stack and self.caller_stack[-1] == func_info:
                    self.caller_stack.pop()
                continue
            
            # 标记为已访问
            self.visited.add(node_id)
            
            # 1. 处理函数定义
            if current_node.type in self.func_types:
                func_info = self._extract_function_def(current_node)
                if func_info:
                    self.functions.append(func_info)
                    self.caller_stack.append(func_info)
                    # 压入退出标记（在处理完所有子节点后弹出 caller_stack）
                    stack.append((current_node, True, func_info))
                    # 压入子节点（逆序，保证遍历顺序）
                    for child in reversed(current_node.children):
                        stack.append((child, False, None))
                    continue
            
            # 2. 处理函数调用
            elif current_node.type == 'call_expression':
                call_info = self._extract_function_call(current_node)
                if call_info:
                    if self.caller_stack:
                        call_info['caller'] = self.caller_stack[-1]
                    self.calls.append(call_info)
            
            # 3. 压入子节点继续遍历
            for child in reversed(current_node.children):
                stack.append((child, False, None))
    
    def _extract_function_def(self, node) -> Optional[Dict]:
        """提取函数定义信息（不再从函数体收集字符串，字符串归属于调用记录）"""
        if self.lang in ('c', 'cpp'):
            func_name = _extract_func_name_c_cpp(node)
        else:
            func_name = None
            for child in node.children:
                if child.type == 'identifier':
                    name = _get_node_text(child)
                    if _is_valid_func_name(name):
                        func_name = name
                        break
        
        if not func_name:
            return None
        
        func_body = None
        for child in node.children:
            if child.type in self.body_types:
                func_body = child
                break
        
        if not func_body:
            return None
        
        line_start = func_body.start_point[0] + 1
        line_end = func_body.end_point[0] + 1
        
        return {
            'name': func_name,
            'file_path': self.file_path,
            'line_start': line_start,
            'line_end': line_end,
            'hash': compute_hash(self.file_path, func_name, line_start, line_end),
            'strings': [],   # 字符串不归属于函数定义，归属于调用记录
            'is_def': 1,
        }
    
    def _extract_function_call(self, node) -> Optional[Dict]:
        """提取函数调用信息（字符串只从 argument_list 收集）"""
        call_name = None
        for child in node.children:
            if child.type == 'identifier':
                call_name = _get_node_text(child)
                break
        
        if not call_name or not _is_valid_func_name(call_name):
            return None
        
        # 只收集 argument_list 下的字符串，精确归属到被调用函数
        strings = []
        for child in node.children:
            if child.type == 'argument_list':
                _collect_strings(child, self.str_types, strings)
                break
        
        line_num = node.start_point[0] + 1
        
        return {
            'name': call_name,
            'file_path': self.file_path,
            'line_start': line_num,
            'line_end': line_num,
            'hash': compute_hash(self.file_path, call_name, line_num, line_num),
            'strings': strings,
            'is_def': 0,
            'caller': None,  # 将在 collect 中填充
        }


# ============================================================
# 主分析类
# ============================================================

class SourceAnalyzer:
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = get_db_connection(db_path)
        init_db(self.conn)
        self._parsers = {}
        if HAS_TREE_SITTER:
            self._load_parsers()
        else:
            print("警告: tree-sitter-languages 未安装")
    
    def _load_parsers(self):
        langs = set(LANG_EXT_MAP.values())
        for lang in langs:
            try:
                get_language(lang)
                parser = get_parser(lang)
                self._parsers[lang] = parser
            except Exception as e:
                print(f"  ✗ {lang} parser 加载失败: {e}")
        ok = sorted(self._parsers.keys())
        print(f"已加载 parser: {', '.join(ok)}")
    
    def _detect_lang(self, file_path: str) -> Optional[str]:
        ext = Path(file_path).suffix.lower()
        return LANG_EXT_MAP.get(ext)
    
    def analyze_file(self, file_path: str) -> int:
        """分析单个文件"""
        lang = self._detect_lang(file_path)
        if not lang or lang not in self._parsers:
            return 0
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            print(f"  ✗ 读取失败 {file_path}: {e}")
            return 0
        
        try:
            parser = self._parsers[lang]
            tree = parser.parse(content)
            
            # 使用 SourceCodeCollector 收集函数和调用关系
            collector = SourceCodeCollector(lang, file_path)
            collector.collect(tree.root_node)
            
            # 存入数据库
            self._save_to_db(collector.functions, collector.calls)
            
            return len(collector.functions) + len(collector.calls)
        except Exception:
            print(f"  ✗ 解析失败: {file_path}")
            traceback.print_exc()
            return 0
    
    def _save_to_db(self, functions: List[Dict], calls: List[Dict]):
        """将函数和调用关系存入数据库"""
        cursor = self.conn.cursor()
        
        # 1. 先存储所有函数定义
        func_id_map = {}  # hash -> id
        for func in functions:
            cursor.execute("SELECT id FROM functions WHERE hash = ?", (func['hash'],))
            row = cursor.fetchone()
            if row:
                func_id = row['id']
            else:
                cursor.execute(
                    "INSERT INTO functions (name, file_path, line_start, line_end, hash, is_def) VALUES (?,?,?,?,?,?)",
                    (func['name'], func['file_path'], func['line_start'], func['line_end'], func['hash'], func['is_def'])
                )
                func_id = cursor.lastrowid
            
            func_id_map[func['hash']] = func_id
            
            # 存储字符串映射
            for str_content in func['strings']:
                if not str_content:
                    continue
                cursor.execute("INSERT OR IGNORE INTO strings (content, length) VALUES (?,?)", (str_content, len(str_content)))
                cursor.execute("SELECT id FROM strings WHERE content = ?", (str_content,))
                str_id = cursor.fetchone()['id']
                cursor.execute(
                    "INSERT INTO function_string_map (function_id, string_id, usage_count) VALUES (?,?,1) "
                    "ON CONFLICT(function_id, string_id) DO UPDATE SET usage_count = usage_count + 1",
                    (func_id, str_id)
                )
        
        # 2. 存储所有函数调用
        for call in calls:
            cursor.execute("SELECT id FROM functions WHERE hash = ?", (call['hash'],))
            row = cursor.fetchone()
            if row:
                callee_id = row['id']
            else:
                cursor.execute(
                    "INSERT INTO functions (name, file_path, line_start, line_end, hash, is_def) VALUES (?,?,?,?,?,?)",
                    (call['name'], call['file_path'], call['line_start'], call['line_end'], call['hash'], call['is_def'])
                )
                callee_id = cursor.lastrowid
            
            # 存储字符串映射
            for str_content in call['strings']:
                if not str_content:
                    continue
                cursor.execute("INSERT OR IGNORE INTO strings (content, length) VALUES (?,?)", (str_content, len(str_content)))
                cursor.execute("SELECT id FROM strings WHERE content = ?", (str_content,))
                str_id = cursor.fetchone()['id']
                cursor.execute(
                    "INSERT INTO function_string_map (function_id, string_id, usage_count) VALUES (?,?,1) "
                    "ON CONFLICT(function_id, string_id) DO UPDATE SET usage_count = usage_count + 1",
                    (callee_id, str_id)
                )
            
            # 3. 【核心】存储调用关系到 source_call_graph
            if call.get('caller'):
                caller_hash = call['caller']['hash']
                caller_id = func_id_map.get(caller_hash)
                if caller_id:
                    cursor.execute(
                        "INSERT OR IGNORE INTO source_call_graph (caller_id, callee_id, call_line) VALUES (?,?,?)",
                        (caller_id, callee_id, call['line_start'])
                    )
        
        self.conn.commit()
    
    def analyze_directory(self, directory: str) -> dict:
        """分析整个目录"""
        stats = {'files': 0, 'functions': 0}
        
        print(f"\n扫描目录: {os.path.abspath(directory)}")
        print(f"支持扩展名: {', '.join(sorted(LANG_EXT_MAP.keys()))}\n")
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            for filename in files:
                ext = Path(filename).suffix.lower()
                if ext not in LANG_EXT_MAP:
                    continue
                
                file_path = os.path.join(root, filename)
                stats['files'] += 1
                n = self.analyze_file(file_path)
                stats['functions'] += n
                if n > 0:
                    print(f"  ✓ {file_path}  ({n} 个函数/调用)")
        
        # 统计
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM strings")
        stats['strings'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM function_string_map")
        stats['mappings'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM source_call_graph")
        stats['call_edges'] = cur.fetchone()[0]
        
        return stats
    
    def print_summary(self):
        """打印统计摘要"""
        cur = self.conn.cursor()
        print("\n" + "=" * 60)
        print("📊 源码数据库统计")
        print("=" * 60)
        
        cur.execute("SELECT COUNT(*) FROM functions WHERE is_def = 1")
        func_defs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM functions WHERE is_def = 0")
        func_calls = cur.fetchone()[0]
        
        print(f"  函数定义:     {func_defs}")
        print(f"  函数调用:     {func_calls}")
        print(f"  总计:         {func_defs + func_calls}")
        
        cur.execute("SELECT COUNT(*) FROM strings")
        print(f"  字符串总数:   {cur.fetchone()[0]}")
        
        cur.execute("SELECT COUNT(*) FROM source_call_graph")
        call_edges = cur.fetchone()[0]
        print(f"  调用关系:     {call_edges} 条边")
        
        print("-" * 60)
        print("  被调用最多的函数 (Top 10):")
        cur.execute('''
            SELECT f.name, COUNT(cg.caller_id) as call_count
            FROM functions f
            JOIN source_call_graph cg ON f.id = cg.callee_id
            WHERE f.is_def = 1
            GROUP BY f.id
            ORDER BY call_count DESC
            LIMIT 10
        ''')
        for row in cur.fetchall():
            print(f"    {row['name']}(): 被调用 {row['call_count']} 次")
        
        print("-" * 60)
        print("  调用其他函数最多的函数 (Top 10):")
        cur.execute('''
            SELECT f.name, COUNT(cg.callee_id) as call_out
            FROM functions f
            JOIN source_call_graph cg ON f.id = cg.caller_id
            WHERE f.is_def = 1
            GROUP BY f.id
            ORDER BY call_out DESC
            LIMIT 10
        ''')
        for row in cur.fetchall():
            print(f"    {row['name']}(): 调用了 {row['call_out']} 个函数")
        
        print("-" * 60)
        print("  唯一字符串统计（用于符号恢复）:")
        cur.execute('''
            SELECT COUNT(*) as unique_count
            FROM (
                SELECT s.content
                FROM strings s
                JOIN function_string_map fsm ON s.id = fsm.string_id
                JOIN functions f ON fsm.function_id = f.id
                WHERE f.is_def = 1
                GROUP BY s.content
                HAVING COUNT(DISTINCT f.id) = 1
            )
        ''')
        unique_strings = cur.fetchone()[0]
        print(f"    唯一字符串数量: {unique_strings}")
        print(f"    （这些字符串只被一个函数使用，可用于高置信度匹配）")
        
        print("=" * 60)
    
    def close(self):
        self.conn.close()


# ============================================================
# 入口
# ============================================================

def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    db_name = sys.argv[2] if len(sys.argv) > 2 else "source_code.db"
    
    analyzer = SourceAnalyzer(db_name)
    
    if os.path.isfile(target):
        n = analyzer.analyze_file(target)
        stats = {'files': 1, 'functions': n}
        cur = analyzer.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM strings")
        stats['strings'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM function_string_map")
        stats['mappings'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM source_call_graph")
        stats['call_edges'] = cur.fetchone()[0]
    else:
        stats = analyzer.analyze_directory(target)
    
    print(f"\n✅ 源码分析完成！")
    print(f"   扫描文件:    {stats['files']}")
    print(f"   函数/调用:   {stats['functions']}")
    print(f"   字符串:      {stats['strings']}")
    print(f"   字符串映射:  {stats['mappings']}")
    print(f"   调用关系:    {stats.get('call_edges', 0)} 条边")
    
    analyzer.print_summary()
    analyzer.close()
    print(f"\n📁 数据库: {db_name}")
    print("💡 提示: 此数据库可用于符号恢复的源码侧匹配")


if __name__ == "__main__":
    main()
