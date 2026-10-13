# -*- coding: utf-8 -*-

"""
关键字检测器模块
"""

import os
import re
from utils.detection_errors import report_detection_error
import logging
from array import array
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit
from typing import List, Dict, Tuple
import chardet

logger = logging.getLogger('LinkRecon.detector.keyword')


def _decode_field(raw, start, is_url=False):
    """解码展示文本，同时保留到原始源码的偏移映射，供报告定位。"""
    text, offsets, ends, previous = [], array('Q'), array('Q'), 0
    token_re = re.compile(r'&(?:#x[0-9a-f]+|#\d+|[a-z][a-z0-9]+);?', re.I)
    for match in token_re.finditer(raw):
        # 普通字符和实体分别映射，不能用解码后的索引直接截原始 HTML。
        prefix = raw[previous:match.start()]
        text.append(prefix)
        offsets.extend(range(start + previous, start + match.start()))
        ends.extend(range(start + previous + 1, start + match.start() + 1))
        decoded = unescape(match.group())
        text.append(decoded)
        if decoded == match.group():
            offsets.extend(range(start + match.start(), start + match.end()))
            ends.extend(range(start + match.start() + 1, start + match.end() + 1))
        else:
            offsets.extend([start + match.start()] * len(decoded))
            ends.extend([start + match.end()] * len(decoded))
        previous = match.end()
    text.append(raw[previous:])
    offsets.extend(range(start + previous, start + len(raw)))
    ends.extend(range(start + previous + 1, start + len(raw) + 1))
    value = ''.join(text)
    if not is_url:
        return value, offsets, ends
    # URL 中的百分号编码可能隐藏真实的中文词；资源编号仍由字段类型排除。
    decoded, mapped, mapped_ends, previous = [], array('Q'), array('Q'), 0
    for match in re.finditer(r'(?:%[0-9a-fA-F]{2})+', value):
        decoded.append(value[previous:match.start()])
        mapped.extend(offsets[previous:match.start()])
        mapped_ends.extend(ends[previous:match.start()])
        encoded = bytes.fromhex(match.group().replace('%', ''))
        index = 0
        while index < len(encoded):
            token, length = '\ufffd', 1
            for size in range(1, min(4, len(encoded) - index) + 1):
                try:
                    character = encoded[index:index + size].decode('utf-8')
                except UnicodeDecodeError:
                    continue
                if len(character) == 1:
                    token, length = character, size
                    break
            decoded.append(token)
            mapped.append(offsets[match.start() + index * 3])
            mapped_ends.append(ends[match.start() + (index + length) * 3 - 1])
            index += length
        previous = match.end()
    decoded.append(value[previous:])
    mapped.extend(offsets[previous:])
    mapped_ends.extend(ends[previous:])
    return ''.join(decoded), mapped, mapped_ends


class _KeywordFields(HTMLParser):
    """只提取内容字段，不把标签、CSS 选择器、id/class 等当自然语言。"""
    _ATTR_RE = re.compile(r'''([^\s=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?''')
    _TEXT_ATTRS = {'alt', 'title', 'placeholder', 'aria-label', 'aria-description', 'label',
                   'data-title', 'data-text', 'data-description', 'data-label', 'data-content'}
    _URL_ATTRS = {'href', 'src', 'srcset', 'action', 'formaction', 'poster', 'data', 'cite',
                  'longdesc', 'data-href', 'data-src'}
    # 字符串和注释保留为候选内容；代码标识符、数值常量交给 JS/CSS 检测器。
    _CODE_RE = re.compile(r'''/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''', re.S)
    _CSS_CODE_RE = re.compile(r"""/\*.*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""", re.S)

    def __init__(self, content, depth=0):
        super().__init__(convert_charrefs=False)
        self.content = content
        self.fields = []
        self.raw_tag = None
        self.depth = depth
        self.lines = [0] + [m.end() for m in re.finditer('\n', content)]

    def position(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def add(self, raw, start, kind):
        if not raw.strip():
            return
        value, offsets, ends = _decode_field(raw, start, kind == 'url')
        if kind == 'code_string' and not re.search(r'\s', value) and (
                re.match(r'(?i)(?:https?://|//|\.?\.?/|[a-z]:[\\/])', value)
                or re.search(r'(?i)\.(?:png|jpg|jpeg|gif|svg|webp|js|css|html?|json)(?:[?#].*)?$', value)):
            kind = 'url'
            value, offsets, ends = _decode_field(raw, start, True)
        if kind in {'embedded_html', 'code_string'} and self.depth < 3 and re.search(r'<[A-Za-z][\w:-]*\b', value):
            nested = _KeywordFields(value, self.depth + 1)
            nested.feed(value)
            nested.close()
            for field in nested.fields:
                field['offsets'] = [offsets[pos] for pos in field['offsets']]
                field['ends'] = [ends[pos - 1] for pos in field['ends']]
                self.fields.append(field)
            return
        self.fields.append({'text': value, 'offsets': offsets, 'ends': ends, 'kind': kind})

    def code(self, raw, start, css=False):
        for match in (self._CSS_CODE_RE if css else self._CODE_RE).finditer(raw):
            token = match.group()
            if token.startswith(('/*', '//')):
                self.add(token, start + match.start(), 'comment')
            else:
                self.add(token[1:-1], start + match.start() + 1, 'code_string')

    def handle_starttag(self, tag, attrs):
        raw, start = self.get_starttag_text(), self.position()
        values = dict(attrs)
        for match in self._ATTR_RE.finditer(raw[len(tag) + 1:]):
            name = match.group(1).lower()
            group = next((i for i in (2, 3, 4) if match.group(i) is not None), None)
            if group is None:
                continue
            value_start = start + len(tag) + 1 + match.start(group)
            value = match.group(group)
            if name in self._TEXT_ATTRS or (name == 'value' and tag == 'input'
                    and values.get('type', 'text').lower() in {'text', 'search', 'button', 'submit'}):
                self.add(value, value_start, 'attribute')
            elif name == 'content' and tag == 'meta':
                if (values.get('name') or values.get('property') or '').lower() in {
                        'keywords', 'description', 'og:title', 'og:description', 'twitter:title', 'twitter:description'}:
                    self.add(value, value_start, 'metadata')
            elif name in self._URL_ATTRS:
                self.add(value, value_start, 'url')
            elif name in {'srcdoc', 'data-html'}:
                self.add(value, value_start, 'embedded_html')
            elif name.startswith('on'):
                self.code(value, value_start)
        if tag in {'script', 'style'}:
            self.raw_tag = tag

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.raw_tag = None

    def handle_endtag(self, tag):
        if tag == self.raw_tag:
            self.raw_tag = None

    def handle_data(self, data):
        if self.raw_tag:
            self.code(data, self.position(), css=self.raw_tag == 'style')
        else:
            # 合并相邻文本/实体回调，但不跨标签拼接，避免 regex 横跨无关字段。
            start = self.position()
            if self.fields and self.fields[-1]['kind'] == 'text' and self.fields[-1]['ends'][-1] == start:
                value, offsets, ends = _decode_field(data, start)
                self.fields[-1]['text'] += value
                self.fields[-1]['offsets'].extend(offsets)
                self.fields[-1]['ends'].extend(ends)
            else:
                self.add(data, start, 'text')

    def handle_entityref(self, name):
        self.handle_data('&' + name + (';' if self.content[self.position() + len(name) + 1:self.position() + len(name) + 2] == ';' else ''))

    def handle_charref(self, name):
        self.handle_entityref('#' + name)

    def handle_comment(self, data):
        self.add(data, self.position() + 4, 'comment')

class KeywordDetector:
    """关键字检测器"""
    MATCH_POLICY_VERSION = 'context-v2'
    # 规则库里这些词也有常见正常含义，不能仅凭原始类别/权重作风险结论。
    # 保留候选而非删除规则；业务歧义词可通过配置追加。
    _AMBIGUOUS_TERMS = frozenset({
        'adult', 'strip', '成人', '激情', '福利', '美女', '直播', '视频', '写真',
        '春光', '自拍', '约会', '寂寞', '陪聊', '视频聊', '机场', '梯子', '花园',
        '洋葱', '护照', '移民', '独立', '自由', '民主', '人权', '离岸', '开户',
        '存款', '提款', '取款', '阴道', '阴茎', '乳房', '胸部', '臀部', '屁股',
        r'注册[^。！？!?\r\n]{0,16}送', r'资金[^。！？!?\r\n]{0,16}安全',
    })
    
    def __init__(self, config):
        self.config = config
        self.keywords = []  # 存储关键字列表 [(keyword, category, weight), ...]
        self.keyword_patterns = []  # 编译后的正则表达式模式列表
    
    def load_keywords(self, keywords_file: str) -> bool:
        """
        从文件加载关键字。

        注意：结果先装进临时列表，全部解析成功后才整体替换 self.keywords。
        否则中途失败时回退到 _load_default_keywords() 会在半截列表上继续
        追加，导致关键字翻倍、扫描耗时翻倍。
        """
        loaded = []
        try:
            # 检测文件编码
            with open(keywords_file, 'rb') as f:
                raw_data = f.read(10000)
                result = chardet.detect(raw_data)
                encoding = result['encoding'] or 'utf-8'
            
            # 读取关键字文件
            with open(keywords_file, 'r', encoding=encoding) as f:
                import csv
                reader = csv.reader(f)
                for line_num, parts in enumerate(reader, 1):
                    # 去除空行
                    if not parts or all((p.strip() == '' for p in parts)):
                        continue
                    # 忽略注释行
                    if parts and parts[0].strip().startswith('#'):
                        continue
                    if len(parts) < 3:
                        logger.warning(f"关键字文件第{line_num}行格式错误，跳过: {parts}")
                        continue
                    keyword = parts[0].strip()
                    category = parts[1].strip()
                    # 验证风险权重
                    try:
                        weight = int(parts[2].strip())
                        if not 1 <= weight <= 10:
                            logger.warning(f"关键字文件第{line_num}行风险权重超出范围(1-10)，使用默认值5: {parts}")
                            weight = 5
                    except Exception:
                        logger.warning(f"关键字文件第{line_num}行风险权重不是数字，使用默认值5: {parts}")
                        weight = 5
                    valid_categories = ['gambling', 'porn', 'malware', 'phishing', 'political', 'other']
                    if category not in valid_categories:
                        logger.warning(f"关键字文件第{line_num}行类别无效，使用默认类别other: {parts}")
                        category = 'other'
                    loaded.append((keyword, category, weight))

            # 全部解析成功后才整体替换，避免半截状态
            self.keywords = loaded
            self._compile_keyword_patterns()

            logger.info(f"成功加载 {len(self.keywords)} 个关键字")
            return True

        except Exception as e:
            logger.error(f"加载关键字文件失败: {str(e)}", exc_info=True)
            # 如果加载失败，使用内置的默认关键字
            self._load_default_keywords()
            return False

    def _load_default_keywords(self):
        """
        回退：从项目根目录读取 keywords_example.txt。

        用 _loading_default 做重入保护——否则默认文件本身有问题时，
        load_keywords 失败 -> _load_default_keywords -> load_keywords 会无限递归。
        路径基于本文件位置推导，不依赖 os.getcwd()。
        """
        if getattr(self, '_loading_default', False):
            logger.error("默认关键字文件加载失败，不再重试")
            self.keywords = []
            self.keyword_patterns = []
            return
        self._loading_default = True
        try:
            proj_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            path = os.path.join(proj_root, 'keywords_example.txt')
            if os.path.exists(path):
                self.load_keywords(path)
                return
            logger.warning("未找到默认关键字文件 keywords_example.txt，关键字功能将受限")
            self.keywords = []
            self.keyword_patterns = []
        except Exception as e:
            logger.error(f"加载默认关键字失败: {str(e)}")
            self.keywords = []
            self.keyword_patterns = []
        finally:
            self._loading_default = False
    
    def _is_regex_pattern(self, keyword: str) -> bool:
        """判断关键字是否包含正则表达式语法"""
        if '.*' in keyword:
            return True
        if '\\' in keyword:
            return True
        if keyword.endswith('$'):
            return True
        return False

    def _compile_keyword_patterns(self):
        """编译关键字正则表达式模式"""
        self.keyword_patterns = []

        for keyword, category, weight in self.keywords:
            pattern = self._compile_one(keyword)
            if pattern is not None:
                self.keyword_patterns.append((pattern, keyword, category, weight))

    def _compile_one(self, keyword: str):
        """
        把单个关键字编译成正则。

        含字母/数字的 ASCII 字面规则加标识符边界，避免 sex 命中 Middlesex。
        纯数字关键字不能嵌在更长的数字或 ASCII 标识符里，避免 64 命中图片
        时间戳、订单号或哈希。不用 \b，以保留中文紧邻数字时的正常匹配。
        中文关键字直接转义匹配；显式正则保留规则作者定义的语义。
        单条正则语法错误时降级为字面匹配，不让整个关键字表加载失败。
        """
        if not keyword:
            return None
        if self._is_regex_pattern(keyword):
            try:
                return re.compile(keyword, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"关键字 '{keyword}' 正则语法错误，降级为字面匹配: {e}")
        if re.fullmatch(r'[0-9]+', keyword):
            return re.compile(r'(?<![\dA-Za-z_])' + re.escape(keyword) + r'(?![\dA-Za-z_])')
        if keyword.isascii() and re.search(r'[A-Za-z0-9]', keyword):
            return re.compile(r'(?<![A-Za-z0-9_])' + re.escape(keyword) + r'(?![A-Za-z0-9_])', re.IGNORECASE)
        return re.compile(re.escape(keyword), re.IGNORECASE)
    
    def detect(self, content: str, source: str, content_type: str = '') -> List[Dict]:
        """分字段匹配后评估证据；关键词命中不等于确认存在安全问题。"""
        if not self.keywords:
            self._load_default_keywords()
        try:
            results = _keyword_detector_match_keywords(self, content, source, content_type=content_type)
            priorities = set(getattr(self.config, 'keyword_stop_categories', ['porn']))
            for result in results:
                result['primary_category'] = result['category_key'] in priorities
            results.sort(key=lambda item: (item['primary_category'], item['weight']), reverse=True)
            return results
        except Exception as e:
            logger.error(f"关键字检测失败: {str(e)}", exc_info=True)
            report_detection_error(self.config, 'keyword', source, e)
            return []

    @staticmethod
    def _fields(content, source, content_type=''):
        parser = _KeywordFields(content)
        extension = os.path.splitext(urlsplit(source).path)[1].lower()
        kind = content_type.lower()
        if 'javascript' in kind or extension in {'.js', '.jsx', '.ts', '.tsx'}:
            parser.code(content, 0)
        elif 'css' in kind or extension in {'.css', '.scss', '.less', '.sass'}:
            parser.code(content, 0, css=True)
        elif 'html' in kind or re.search(r'<(?:[A-Za-z][\w:-]*\b|!--)', content):
            parser.feed(content)
            parser.close()
        else:
            parser.add(content, 0, 'text')
        return parser.fields

    def _weak_keyword(self, keyword):
        # 所有低信息量词统一处理，不针对某一个数字写排除名单。
        if self._numeric_rule(keyword):
            return True
        ambiguous = self._AMBIGUOUS_TERMS | set(getattr(self.config, 'keyword_ambiguous_terms', []))
        # 显式正则也可能是业务歧义短语，不能因使用正则就绕过待复核策略。
        if keyword.casefold() in {term.casefold() for term in ambiguous}:
            return True
        if self._is_regex_pattern(keyword):
            return False
        return (keyword.isdecimal() or len(keyword) == 1
                or bool(re.fullmatch(r'[A-Za-z]{1,2}', keyword)))

    @staticmethod
    def _numeric_rule(keyword):
        """数字及仅由数字/分隔符组成的正则，没有类别语义锚点。"""
        literal = re.sub(r'\\[dbBAZz]|\\[^A-Za-z0-9]', '', keyword)
        return bool(re.search(r'\d|\\d', keyword)) and not re.search(r'[^\W\d_]', literal)

    @staticmethod
    def _numeric_boundary(text, start, end):
        def identifier(char):
            return char.isdecimal() or (char.isascii() and (char.isalpha() or char == '_'))
        return not ((start and identifier(text[start - 1]))
                    or (end < len(text) and identifier(text[end])))
    
    def _get_category_name(self, category: str) -> str:
        """获取类别的中文名称"""
        category_names = {
            'gambling': '博彩',
            'porn': '色情',
            'malware': '恶意软件',
            'phishing': '钓鱼',
            'political': '政治敏感',
            'other': '其他'
        }
        
        return category_names.get(category, '其他')
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """获取匹配内容的上下文"""
        start_context = max(0, start - context_size)
        end_context = min(len(content), end + context_size)
        
        context = content[start_context:end_context]
        context = context.replace('\n', ' ').replace('\r', ' ')
        
        # 截断过长的上下文
        if len(context) > 200:
            context = context[:100] + '...' + context[-100:]
        
        return context
    
    @staticmethod
    def _dedup_key(result: Dict):
        """
        判重键：关键字 + 来源 + 位置分桶（每 10 字符一桶）。

        原实现对每条新结果线性遍历全部已有结果，大页面 + 上千关键字时是
        O(n^2)；改为 set 查表后是 O(1)。位置用整除分桶来近似原来的
        「位置差 < 10」语义。
        """
        return (result['keyword'], result['source'], result['match_position'] // 10)

    def _is_duplicate_match(self, existing_results, new_result: Dict) -> bool:
        """兼容旧签名：existing_results 可以是结果列表，也可以是已有的键集合。"""
        key = self._dedup_key(new_result)
        if isinstance(existing_results, set):
            return key in existing_results
        return any(self._dedup_key(r) == key for r in existing_results)
    
    def get_keyword_statistics(self) -> Dict:
        """获取关键字统计信息"""
        stats = {
            'total_keywords': len(self.keywords),
            'by_category': {}
        }
        
        # 按类别统计
        for _, category, _ in self.keywords:
            category_name = self._get_category_name(category)
            if category_name not in stats['by_category']:
                stats['by_category'][category_name] = 0
            stats['by_category'][category_name] += 1
        
        return stats
    
    def add_keyword(self, keyword: str, category: str = 'other', weight: int = 5):
        """动态添加关键字"""
        # 验证参数
        if not keyword or not keyword.strip():
            logger.warning("尝试添加空关键字，跳过")
            return False
        
        weight = max(1, min(10, weight))  # 限制在1-10范围内
        
        valid_categories = ['gambling', 'porn', 'malware', 'phishing', 'political', 'other']
        if category not in valid_categories:
            category = 'other'
        
        # 检查是否已存在
        for existing_keyword, _, _ in self.keywords:
            if existing_keyword == keyword:
                logger.warning(f"关键字 '{keyword}' 已存在")
                return False
        
        # 添加关键字
        self.keywords.append((keyword, category, weight))
        
        # 编译新的模式（复用 _compile_one，保证与加载路径行为一致）
        pattern = self._compile_one(keyword)
        if pattern is not None:
            self.keyword_patterns.append((pattern, keyword, category, weight))
        
        logger.info(f"成功添加关键字: {keyword} (类别: {category}, 权重: {weight})")
        return True
    
    def clear_keywords(self):
        """清空所有关键字"""
        self.keywords = []
        self.keyword_patterns = []
        logger.info("已清空所有关键字")
        

def _keyword_detector_match_keywords(self, content: str, source: str, include_categories=None, exclude_categories=None, content_type='') -> List[Dict]:
    results = []
    seen = set()
    include_categories = set(include_categories or [])
    exclude_categories = set(exclude_categories or [])

    fields = self._fields(content, source, content_type)
    rules = [(pattern, keyword, category, weight, self._weak_keyword(keyword), self._numeric_rule(keyword))
             for pattern, keyword, category, weight in self.keyword_patterns
             if (not include_categories or category in include_categories) and category not in exclude_categories]
    for field in fields:
        candidates = []
        for pattern, original_keyword, category, weight, weak, numeric_rule in rules:
            # URL 的数字是路径/端口/参数，不作为自然语言类别证据。
            if field['kind'] == 'url' and numeric_rule:
                continue
            for match in pattern.finditer(field['text']):
                if match.start() == match.end():
                    continue
                # 显式正则可能有数字分支，按实际命中值判定，不能借正则绕过弱证据限制。
                numeric_match = bool(re.search(r'\d', match.group())) and not re.search(r'[^\W\d_]', match.group())
                if numeric_rule or numeric_match:
                    if field['kind'] == 'url' or not self._numeric_boundary(field['text'], match.start(), match.end()):
                        continue
                candidates.append((match, original_keyword, category, weight, weak or self._weak_keyword(match.group())))

        for match, keyword, category, weight, weak in candidates:
            # 佐证本身必须达到关键词高危门槛；中性权重（如导入词的 5 分）
            # 不能把正常业务弱词抬为高危。自身重复、重叠及其他弱词也不算。
            anchors = [other_keyword for other, other_keyword, other_category, other_weight, other_weak in candidates
                       if weak and not other_weak and other_weight >= 7 and other_category == category
                       and (other.end() <= match.start() or match.end() <= other.start())
                       and max(other.start() - match.end(), match.start() - other.end(), 0) <= 80]
            review = weak and not anchors
            start = field['offsets'][match.start()]
            end = field['ends'][match.end() - 1]
            result = {
                'keyword': keyword,
                'category': self._get_category_name(category),
                'category_key': category,
                'weight': min(weight, 3) if review else weight,
                'rule_weight': weight,
                'source': source,
                'match_position': start,
                'match_end': end,
                'matched_text': match.group(),
                'match_field': field['kind'],
                'assessment': 'needs_review' if review else 'context_supported' if weak else 'keyword_match',
                'reason': ('低信息量关键词，缺少同类别独立佐证，需人工复核' if review
                           else '附近同类别关键词佐证：' + '、'.join(sorted(set(anchors))) if weak
                           else '内容字段关键词命中，仍需结合上下文复核'),
                'context': self._get_context(content, start, end)
            }
            key = self._dedup_key(result)
            if key not in seen:
                seen.add(key)
                results.append(result)
    return results
