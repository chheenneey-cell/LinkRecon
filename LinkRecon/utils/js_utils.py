# -*- coding: utf-8 -*-

"""
JavaScript处理工具模块
"""

import re
import bisect
import logging
from utils.js_evidence import calls
from typing import List, Dict, Any, Optional

logger = logging.getLogger('LinkRecon.utils.js')

# 单次调用产出的可疑模式条数上限。
# SUSPICIOUS_PATTERNS 里有 `\+\s*"`、`\[\d+\]` 这类在任何真实 JS 中都会命中
# 上万次的模式，不封顶的话大文件会产出海量带上下文的 dict。
MAX_SUSPICIOUS_MATCHES = 2000

_PATTERN_CACHE = {}


def _compiled_suspicious_pattern(pattern_str: str):
    """缓存编译结果，避免每次扫描都重新 compile 一遍全部模式。"""
    cached = _PATTERN_CACHE.get(pattern_str)
    if cached is None:
        cached = re.compile(pattern_str, re.IGNORECASE)
        _PATTERN_CACHE[pattern_str] = cached
    return cached

# 常见的可疑JavaScript模式
SUSPICIOUS_PATTERNS = [
    # 文档写入相关
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'document\.createElement\s*\(\s*["\']script["\']\s*\)',
    
    # DOM操作相关
    r'appendChild\s*\(',
    r'insertBefore\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    
    # 编码解码相关
    r'decodeURIComponent\s*\(',
    r'decodeURI\s*\(',
    r'eval\s*\(',
    r'Function\s*\(',
    r'fromCharCode\s*\(',
    
    # URL相关
    r'location\.href\s*=',
    r'window\.location\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    
    # 定时器相关
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    
    # AJAX相关
    r'XMLHttpRequest',
    r'fetch\s*\(',
    r'axios',
    
    # 混淆相关
    r'\+\s*"',  # 字符串拼接
    r'["\']\s*\+\s*["\']',  # 空字符串拼接
    r'\[\d+\]',  # 数字索引访问
]

def extract_suspicious_patterns(js_content: str) -> List[Dict[str, str]]:
    """
    提取可疑的JavaScript模式
    
    Args:
        js_content: JavaScript代码
    
    Returns:
        可疑模式列表
    """
    suspicious_matches = []

    try:
        # 行偏移只算一次，之后每条命中用 bisect 定位，避免 O(n^2)
        offsets = build_line_index(js_content)
        for pattern_str in SUSPICIOUS_PATTERNS:
            pattern = _compiled_suspicious_pattern(pattern_str)
            for match in pattern.finditer(js_content):
                # 命中数封顶，防止大文件产出上万条带上下文的结果撑爆内存
                if len(suspicious_matches) >= MAX_SUSPICIOUS_MATCHES:
                    logger.warning(
                        f"可疑模式命中数超过上限 {MAX_SUSPICIOUS_MATCHES}，后续结果已截断")
                    return suspicious_matches

                start_pos = match.start(0)
                end_pos = match.end(0)

                suspicious_matches.append({
                    'pattern': pattern_str,
                    'code_segment': match.group(0),
                    'context': get_code_context(js_content, start_pos, end_pos, offsets=offsets),
                    'position': (start_pos, end_pos)
                })

    except Exception as e:
        logger.error(f"提取可疑模式失败: {str(e)}")

    return suspicious_matches

# 单条上下文的字符上限。压缩后的 JS 常常整个文件只有一行，
# 若按"行"取上下文会把整个文件复制一份给每一条命中。
MAX_CODE_CONTEXT = 500


def build_line_index(js_content: str) -> List[int]:
    """
    预计算每一行的起始偏移量，供 get_code_context 用 bisect 定位行号。

    调用方在扫描入口算一次并传给每次 get_code_context 调用即可把
    「定位行号」从 O(n) 降到 O(log n)。
    """
    offsets = [0]
    pos = js_content.find('\n')
    while pos != -1:
        offsets.append(pos + 1)
        pos = js_content.find('\n', pos + 1)
    return offsets


def get_code_context(js_content: str, start_pos: int, end_pos: int,
                     context_lines: int = 3, offsets: Optional[List[int]] = None) -> str:
    """
    获取代码上下文。

    原实现每次调用都对整个文件做 split('\\n') 并线性累加字符数定位行号。
    由于 SUSPICIOUS_PATTERNS 里有 `\\+\\s*"`、`\\[\\d+\\]` 这类在任何真实 JS 中
    都会命中上万次的模式，命中数正比于文件大小，整体退化为 O(n^2)
    （实测 39KB 0.39s / 78KB 1.47s / 156KB 5.99s）。
    这里改为「预计算行偏移 + bisect」，并对超长单行退化为字符窗口。

    Args:
        js_content: 完整代码
        start_pos: 开始位置
        end_pos: 结束位置
        context_lines: 上下文行数
        offsets: 可选，build_line_index() 的结果；不传则内部计算一次

    Returns:
        包含上下文的代码段
    """
    try:
        if not js_content:
            return ''
        start_pos = max(0, min(int(start_pos), len(js_content)))
        end_pos = max(start_pos, min(int(end_pos), len(js_content)))

        if offsets is None:
            offsets = build_line_index(js_content)

        cur = bisect.bisect_right(offsets, start_pos) - 1
        cur = max(0, cur)

        s = offsets[max(0, cur - context_lines)]
        e_idx = cur + context_lines + 1
        e = offsets[e_idx] if e_idx < len(offsets) else len(js_content)

        # 压缩 JS（单行超长）时退化为字符窗口，避免整文件拷贝
        if e - s > MAX_CODE_CONTEXT:
            s = max(0, start_pos - MAX_CODE_CONTEXT // 2)
            e = min(len(js_content), end_pos + MAX_CODE_CONTEXT // 2)

        return js_content[s:e]

    except Exception as e:
        logger.error(f"获取代码上下文失败: {str(e)}")
        # 回退到简单的字符上下文
        context_start = max(0, start_pos - 100)
        context_end = min(len(js_content), end_pos + 100)
        return js_content[context_start:context_end]

def detect_dynamic_urls(js_content: str) -> List[Dict[str, str]]:
    """
    检测动态生成的URL
    
    Args:
        js_content: JavaScript代码
    
    Returns:
        动态URL列表
    """
    dynamic_urls = []
    
    # 检测常见的URL赋值模式
    url_patterns = [
        re.compile(r'(?:href|src|url)\s*=\s*([^;\n]+);', re.DOTALL),
        re.compile(r'(?:location\.href|window\.location)\s*=\s*([^;\n]+);', re.DOTALL),
        re.compile(r'fetch\s*\(\s*([^)]+)\s*\)', re.DOTALL),
        re.compile(r'\.open\s*\(\s*["\'](get|post|put|delete)["\']\s*,\s*([^)]+)\s*\)', re.DOTALL),
    ]
    
    try:
        for pattern in url_patterns:
            matches = pattern.finditer(js_content)
            
            for match in matches:
                code_segment = match.group(0)
                start_pos = match.start(0)
                end_pos = match.end(0)
                
                # 判断是否包含变量或表达式
                if any(ch in code_segment for ch in ['+', '\'', '"', '`', '[', ']', '(', ')']):
                    # 优先尝试从表达式中提取规范化URL常量
                    url_const = None
                    m_http = re.search(r'["\'`]\s*(https?://[^"\'`\s]+)\s*["\'`]', code_segment)
                    if m_http:
                        url_const = m_http.group(1)
                    m_proto = re.search(r'["\'`]\s*(//[^"\'`\s]+)\s*["\'`]', code_segment)
                    if (not url_const) and m_proto:
                        url_const = 'https:' + m_proto.group(1)
                    dynamic_urls.append({
                        'url': url_const if url_const else None,
                        'expression': code_segment,
                        'reason': '动态构建的URL',
                        'context': get_code_context(js_content, start_pos, end_pos),
                        'position': (start_pos, end_pos)
                    })
    
    except Exception as e:
        logger.error(f"检测动态URL失败: {str(e)}")
    
    return dynamic_urls

def detect_obfuscated_code(js_content: str) -> List[Dict[str, str]]:
    """
    检测混淆的JavaScript代码
    
    Args:
        js_content: JavaScript代码
    
    Returns:
        混淆代码列表
    """
    obfuscated_segments = []
    
    # 检测常见的混淆模式
    obfuscation_patterns = [
        # 大量的字符串拼接
        (r'("[^"\\]*(?:\\.[^"\\]*)*"\s*\+\s*){3,}', 'multiple_string_concatenation'),
        # 长的十六进制字符串
        (r'(\\x[0-9a-fA-F]{2}){10,}', 'hex_encoding'),
        # Unicode编码
        (r'(\\u[0-9a-fA-F]{4}){5,}', 'unicode_encoding'),
        # 数组混淆
        (r'(\[\s*\d+\s*\]\s*\+){3,}', 'array_obfuscation'),
        # eval + 字符串
        (r'eval\s*\(\s*["\'](?:[^"\'\\]|\\.)*["\']\s*\)', 'eval_with_string'),
        # 大量的变量替换
        (r'(var|let|const)\s+[a-z]\s*=\s*[^;]+;\s*[a-z]\s*\+\s*=[^;]+;', 'variable_replacement'),
    ]
    
    try:
        for pattern_str, obfuscation_type in obfuscation_patterns:
            pattern = re.compile(pattern_str, re.DOTALL)
            matches = pattern.finditer(js_content)
            
            for match in matches:
                code_segment = match.group(0)
                start_pos = match.start(0)
                end_pos = match.end(0)
                
                obfuscated_segments.append({
                    'type': obfuscation_type,
                    'code_segment': code_segment,
                    'context': get_code_context(js_content, start_pos, end_pos),
                    'position': (start_pos, end_pos)
                })
    
    except Exception as e:
        logger.error(f"检测混淆代码失败: {str(e)}")
    
    return obfuscated_segments

def extract_function_calls(js_content: str, function_name: str) -> List[Dict[str, str]]:
    """
    提取特定函数调用
    
    Args:
        js_content: JavaScript代码
        function_name: 函数名
    
    Returns:
        函数调用列表
    """
    function_calls = []
    
    try:
        for name, arguments, (start_pos, end_pos) in calls(js_content):
            if name != function_name:
                continue
            full_call = js_content[start_pos:end_pos]
            
            function_calls.append({
                'function': function_name,
                'arguments': arguments,
                'full_call': full_call,
                'context': get_code_context(js_content, start_pos, end_pos),
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取函数调用失败: {str(e)}")
    
    return function_calls

def detect_document_modification(js_content: str) -> List[Dict[str, str]]:
    """
    检测文档修改操作
    
    Args:
        js_content: JavaScript代码
    
    Returns:
        文档修改操作列表
    """
    modifications = []
    
    # 文档修改相关的模式
    modification_patterns = [
        (r'document\.write\s*\(', 'document.write'),
        (r'document\.writeln\s*\(', 'document.writeln'),
        (r'innerHTML\s*=', 'innerHTML assignment'),
        (r'outerHTML\s*=', 'outerHTML assignment'),
        (r'appendChild\s*\(', 'appendChild'),
        (r'insertBefore\s*\(', 'insertBefore'),
        (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
        (r'createElement\s*\(', 'createElement'),
    ]
    
    try:
        for pattern_str, modification_type in modification_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = pattern.finditer(js_content)
            
            for match in matches:
                code_segment = match.group(0)
                start_pos = match.start(0)
                end_pos = match.end(0)
                
                target = modification_type
                value = code_segment
                modifications.append({
                    'action': 'modify_document',
                    'target': target,
                    'value': value,
                    'description': modification_type,
                    'context': get_code_context(js_content, start_pos, end_pos),
                    'position': (start_pos, end_pos)
                })
    
    except Exception as e:
        logger.error(f"检测文档修改失败: {str(e)}")
    
    return modifications

def extract_variable_assignments(js_content: str, variable_name: str) -> List[Dict[str, str]]:
    """
    提取变量赋值
    
    Args:
        js_content: JavaScript代码
        variable_name: 变量名
    
    Returns:
        变量赋值列表
    """
    assignments = []
    
    try:
        # 构建变量赋值的正则表达式
        pattern_str = rf'(?:var|let|const)?\s*{re.escape(variable_name)}\s*=\s*([^;\n]+)'  # 避免 re.escape 对 \ 进行转义
        pattern = re.compile(pattern_str, re.DOTALL)
        matches = pattern.finditer(js_content)
        
        for match in matches:
            full_assignment = match.group(0)
            value = match.group(1)
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            assignments.append({
                'variable': variable_name,
                'value': value,
                'full_assignment': full_assignment,
                'context': get_code_context(js_content, start_pos, end_pos),
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取变量赋值失败: {str(e)}")
    
    return assignments

def extract_comments(js_content: str) -> List[Dict[str, Any]]:
    """
    提取JavaScript注释
    
    Args:
        js_content: JavaScript代码
    
    Returns:
        注释列表
    """
    comments = []
    
    try:
        # 匹配单行注释
        single_line_pattern = re.compile(r'//(.*?)$', re.MULTILINE)
        single_line_matches = single_line_pattern.finditer(js_content)
        
        for match in single_line_matches:
            comment_content = match.group(1).strip()
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            comments.append({
                'type': 'single_line',
                'content': comment_content,
                'position': (start_pos, end_pos)
            })
        
        # 匹配多行注释
        multi_line_pattern = re.compile(r'/\*(.*?)\*/', re.DOTALL)
        multi_line_matches = multi_line_pattern.finditer(js_content)
        
        for match in multi_line_matches:
            comment_content = match.group(1).strip()
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            comments.append({
                'type': 'multi_line',
                'content': comment_content,
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取JavaScript注释失败: {str(e)}")
    
    return comments

def strip_comments(js_content: str) -> str:
    """
    移除JavaScript注释
    """
    try:
        s = js_content
        out = []
        i = 0
        n = len(s)
        in_sq = False
        in_dq = False
        in_bt = False
        while i < n:
            ch = s[i]
            if not in_sq and not in_dq and not in_bt and ch == '/' and i + 1 < n:
                nxt = s[i+1]
                if nxt == '/':
                    j = i + 2
                    while j < n and s[j] not in '\n\r':
                        j += 1
                    i = j
                    continue
                if nxt == '*':
                    j = i + 2
                    while j + 1 < n and not (s[j] == '*' and s[j+1] == '/'):
                        j += 1
                    i = j + 2 if j + 1 < n else n
                    continue
            out.append(ch)
            if ch == "'" and not in_dq and not in_bt:
                esc = i > 0 and s[i-1] == '\\'
                if not esc:
                    in_sq = not in_sq
            elif ch == '"' and not in_sq and not in_bt:
                esc = i > 0 and s[i-1] == '\\'
                if not esc:
                    in_dq = not in_dq
            elif ch == '`' and not in_sq and not in_dq:
                in_bt = not in_bt
            i += 1
        return ''.join(out)
    except Exception as e:
        logger.error(f"移除JavaScript注释失败: {str(e)}")
        return js_content

# 兼容性函数，为了支持js_detector.py中的导入
def identify_obfuscated_code(js_content: str) -> Dict[str, Any]:
    """
    识别混淆代码并返回聚合信息
    """
    segments = detect_obfuscated_code(js_content)
    is_obf = len(segments) > 0
    patterns = [seg.get('type', '') for seg in segments]
    sample = segments[0].get('code_segment', '') if segments else ''
    return {
        'is_obfuscated': is_obf,
        'detected_patterns': patterns,
        'sample': sample
    }

## 兼容别名已移除，请使用 detect_document_modification

## 兼容别名已移除，请使用 strip_comments
    
