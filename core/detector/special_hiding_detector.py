# -*- coding: utf-8 -*-

"""
特殊隐藏技术检测器模块
"""

import re
from utils.detection_errors import report_detection_error
import logging
from bs4 import BeautifulSoup
from utils.js_evidence import script_blocks
from typing import List, Dict

logger = logging.getLogger('LinkRecon.detector.special_hiding')

class SpecialHidingDetector:
    """特殊隐藏技术检测器"""

    # 单条规则最多上报多少条明细，超出部分只计数。
    # 不封顶的话，大页面上 display:none 这类规则能产出上万条带上下文的 dict。
    MAX_FINDINGS_PER_RULE = 50

    # 隐藏样式所在范围内出现这些东西，才认为"藏了实质内容"而不是普通交互样式
    _PAYLOAD_RE = re.compile(r'href\s*=|src\s*=|url\s*\(|https?://|[一-鿿]{4,}',
                             re.IGNORECASE)

    def __init__(self, config):
        self.config = config
        self._init_patterns()

    @staticmethod
    def _tight_scope(content: str, start: int, end: int) -> str:
        """
        取「隐藏样式所属的最小语法范围」，而不是简单的前后 N 个字符。

        为什么不能用宽窗口：`<style>.modal{display:none}</style>` 后面紧跟着
        body 里的正常 `<a href=...>`，用 ±150 字符的窗口会把那个 href 也捞进来，
        于是每个站点的下拉菜单/模态框都会被判成"藏了链接"。

        区分两种情形：
          - 位于 CSS 规则内   -> 取最近的 { ... } 之间
          - 位于内联 style 属性 -> 取所在标签 <...> 及其后的一小段内容
        """
        if not content:
            return ''
        brace = content.rfind('{', 0, start)
        angle = content.rfind('<', 0, start)

        if brace > angle:  # CSS 规则内
            close = content.find('}', end)
            close = close if close != -1 else min(len(content), end + 200)
            # 连同选择器一起，选择器里可能有 .seo-links 这类线索
            sel_start = max(content.rfind('}', 0, brace), content.rfind('{', 0, brace)) + 1
            return content[max(0, sel_start):close + 1]

        if angle != -1:  # 内联 style 属性
            tag_end = content.find('>', end)
            if tag_end == -1:
                return content[angle:min(len(content), end + 200)]
            # Only this DOM subtree. A fixed post-tag window incorrectly borrows
            # href/src/text from a following visible sibling.
            element = BeautifulSoup(content[angle:min(len(content), tag_end + 4096)], 'html.parser').find()
            return str(element) if element else content[angle:tag_end + 1]

        return content[max(0, start - 100):min(len(content), end + 100)]

    def _context_carries_payload(self, content: str, start: int, end: int) -> bool:
        """
        判断这一处隐藏样式是否确实夹带了内容。

        纯交互样式（.modal{display:none}、.dropdown-menu{display:none}）不算；
        隐藏范围内带 href / src / url() / 连续 4 个以上汉字才算。
        """
        scope = self._tight_scope(content, start, end)
        return bool(scope) and bool(self._PAYLOAD_RE.search(scope))


    def _init_patterns(self):
        """初始化正则表达式模式"""
        # 零宽字符模式
        self.zero_width_chars = [
            '\u200B',  # 零宽空格
            '\u200C',  # 零宽不连字
            '\u200D',  # 零宽连字
            '\u2060',  # 字连接符
            '\uFEFF',  # 字节顺序标记
        ]
        self.zero_width_pattern = re.compile('|'.join(re.escape(c) for c in self.zero_width_chars))
        
        # 空白字符堆积。
        # 原来写成 (\s|\t|\r|\n){10,}，捕获组在重复量词内，group(1) 只保留
        # 最后一次重复 -> 长度恒为 1，输出永远是"空白字符堆积 (1个字符)"。
        # 改为整体匹配，并把门槛提高到 40，避免正常缩进误报。
        self.whitespace_pattern = re.compile(r'[ \t\r\n\u00A0\u2000-\u200A\u3000]{40,}')
        
        # 颜色隐藏（颜色接近背景色）
        self.color_pattern = re.compile(
            r'(?<![\w-])color\s*:\s*(#[0-9a-f]{3,6}|rgba?\([^)]+\)|black\b|white\b)',
            re.IGNORECASE
        )
        self.background_color_pattern = re.compile(
            r'(?<![\w-])background-color\s*:\s*(#[0-9a-f]{3,6}|rgba?\([^)]+\)|black\b|white\b)',
            re.IGNORECASE
        )
        
        # 绝对定位隐藏（离屏元素）
        # 绝对定位隐藏（离屏元素）。
        # 原来带 re.DOTALL 且 .*? 无上界：每个没有跟方向属性的 position:absolute
        # 都会让引擎一路回溯扫到文件末尾，1MB CSS + 数百处 absolute 就是数亿次
        # 字符扫描。这里把搜索范围限制在同一条规则内（不跨 {}）。
        self.absolute_position_pattern = re.compile(
            r'position\s*:\s*absolute[^{}]{0,300}?\b(left|top|bottom|right)\s*:\s*'
            r'(-?\d+(?:\.\d+)?(?:px|em|rem|%)?)',
            re.IGNORECASE
        )
        
        # 字体大小隐藏。
        # 原来写成 (0|0\.\d+)：交替里 0 排在前面，对 '0.875rem' 会先匹配到
        # 前导的 0 就成功返回，于是 Bootstrap/Tailwind 的默认小字号
        # font-size:0.875rem 全部被判成"字体大小隐藏"。
        # 这里要求整个数值确实是 0 或 0px/0em，或者小于等于 2px 的极小值。
        self.font_size_pattern = re.compile(
            r'font-size\s*:\s*(0(?:\.0+)?(?:px|em|rem|pt)?|[0-2]px)\s*(?=[;}"\'\s]|$)',
            re.IGNORECASE
        )
        
        # 文本缩进隐藏
        self.text_indent_pattern = re.compile(
            r'text-indent\s*:\s*(-\d+(?:\.\d+)?(?:px|em|%))',
            re.IGNORECASE
        )
        
        # 透明度隐藏。同 font_size：只有 0 / 0.00x 这种"实际不可见"的值才算，
        # opacity:0.85 之类的悬浮效果不是隐藏。
        self.opacity_pattern = re.compile(
            r'opacity\s*:\s*(0(?:\.0{1,3})?|\.0{1,3})\s*(?=[;}"\'\s]|$)',
            re.IGNORECASE
        )
        self.visibility_pattern = re.compile(
            r'visibility\s*:\s*hidden',
            re.IGNORECASE
        )
        self.display_none_pattern = re.compile(
            r'display\s*:\s*none',
            re.IGNORECASE
        )
        
        # 多层嵌套隐藏。
        # 原来是 <div><div><div> —— 任何页面都能匹配上千次，一律标"中"风险，
        # 没有任何区分度，纯噪声。改为要求 5 层以上且最内层带 href。
        self.nested_elements_pattern = re.compile(
            r'(?:<(?:div|span|p)[^>]*>\s*){5,}<a[^>]+href=',
            re.IGNORECASE
        )
        
        # HTML实体编码隐藏
        self.html_entity_pattern = re.compile(r'&#(\d+);|&#x([0-9a-f]+);')
        
        # 可疑的编码混合
        self.mixed_encoding_pattern = re.compile(
            r'https?://(?:[\w\-._~:/?#[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+',
            re.IGNORECASE
        )
    
    def detect(self, content: str, source: str) -> List[Dict]:
        """检测特殊隐藏技术"""
        results = []
        # Static hiding rules must not treat JS literal markup or comments as DOM.
        content = script_blocks(content, mask_only=True)
        
        try:
            # 检测零宽字符
            zero_width_results = self._detect_zero_width_chars(content, source)
            results.extend(zero_width_results)
            
            # 检测空白字符堆积
            whitespace_results = self._detect_whitespace(content, source)
            results.extend(whitespace_results)
            
            # 检测颜色隐藏
            color_results = self._detect_color_hiding(content, source)
            results.extend(color_results)
            
            # 检测绝对定位隐藏
            position_results = self._detect_position_hiding(content, source)
            results.extend(position_results)
            
            # 检测字体大小隐藏
            font_size_results = self._detect_font_size_hiding(content, source)
            results.extend(font_size_results)
            
            # 检测文本缩进隐藏
            indent_results = self._detect_text_indent_hiding(content, source)
            results.extend(indent_results)
            
            # 检测透明度隐藏
            opacity_results = self._detect_opacity_hiding(content, source)
            results.extend(opacity_results)
            
            # 检测多层嵌套隐藏
            nested_results = self._detect_nested_elements(content, source)
            results.extend(nested_results)
            
            # 检测HTML实体编码隐藏
            entity_results = self._detect_html_entities(content, source)
            results.extend(entity_results)
            
        except Exception as e:
            logger.error(f"特殊隐藏技术检测失败: {str(e)}", exc_info=True)
            report_detection_error(self.config, 'special_hiding', source, e)
        
        return results
    
    def _detect_zero_width_chars(self, content: str, source: str) -> List[Dict]:
        """检测零宽字符"""
        results = []
        
        matches = list(self.zero_width_pattern.finditer(content))
        if matches:
            # 收集所有零宽字符的上下文
            context = self._get_context(content, matches[0].start(), matches[-1].end(), 100)
            
            # 解码隐藏内容（如果可能）
            hidden_content = self._extract_hidden_content(content, self.zero_width_chars)
            
            results.append({
                'link': f'零宽字符隐藏 ({len(matches)}个字符)',
                'source': source,
                'type': 'zero_width_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': context,
                'hidden_content': hidden_content if hidden_content else None
            })
        
        return results
    
    def _detect_whitespace(self, content: str, source: str) -> List[Dict]:
        """检测空白字符堆积"""
        results = []
        
        for match in self.whitespace_pattern.finditer(content):
            # 检查是否在HTML标签之间或注释中
            context = self._get_context(content, match.start(), match.end(), 50)
            
            # 只有在标签之间大量空白才认为可疑
            if '<' not in context and '>' not in context:
                results.append({
                    'link': f'空白字符堆积 ({len(match.group(1))}个字符)',
                    'source': source,
                    'type': 'whitespace_hiding',
                    'detection_method': 'regex',
                    'risk_level': '中',
                    'context': context
                })
        
        return results
    
    @staticmethod
    def _color_properties(style):
        # Mask comments and string values first: content:"color:..." is not a declaration.
        masked = re.sub(r"""/\*.*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""",
                        lambda match: ' ' * len(match.group()), style, flags=re.S)
        properties = {}
        for match in re.finditer(r'(?:^|(?<=[;{]))\s*(color|background-color)\s*:\s*([^;}]+)', masked, re.I):
            value = match.group(2).strip()
            important = bool(re.search(r'!\s*important\s*$', value, re.I))
            value = re.sub(r'!\s*important\s*$', '', value, flags=re.I).strip()
            name = match.group(1).lower()
            if name not in properties or important or not properties[name][1]:
                properties[name] = (value, important)
        # Unresolved variables/inheritance and translucent colors are not proof of
        # matching effective colors. Keep only the opaque literal forms we compare.
        literal = re.compile(r'(?:#[0-9a-f]{3}(?:[0-9a-f]{3})?|black|white|'
                             r'rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}'
                             r'(?:\s*,\s*1(?:\.0+)?)?\s*\))', re.I)
        return {name: pair[0] for name, pair in properties.items() if literal.fullmatch(pair[0])}

    def _detect_color_hiding(self, content: str, source: str) -> List[Dict]:
        """检测颜色隐藏"""
        results = []
        seen = set()
        
        # 找到所有颜色定义
        for color_match in self.color_pattern.finditer(content):
            # 在同一段落中查找背景颜色
            segment = self._tight_scope(content, color_match.start(), color_match.end())
            brace = content.rfind('{', 0, color_match.start())
            angle = content.rfind('<', 0, color_match.start())
            scope = max(brace, angle)
            if scope in seen:
                continue
            seen.add(scope)
            if angle > brace:
                element = BeautifulSoup(segment, 'html.parser').find()
                # Compare only this element's declarations, not a descendant's background.
                segment = element.get('style', '') if element else ''
            properties = self._color_properties(segment)
            color, bg_color = properties.get('color'), properties.get('background-color')
            if color and bg_color:
                
                # 如果颜色非常接近背景色，标记为可疑
                if self._colors_are_similar(color, bg_color):
                    results.append({
                        'link': f'颜色隐藏 (文字:{color}, 背景:{bg_color})',
                        'source': source,
                        'type': 'color_hiding',
                        'detection_method': 'regex',
                        'risk_level': '高',
                        'context': self._get_context(content, color_match.start(), color_match.end())
                    })
        
        return results
    
    def _detect_position_hiding(self, content: str, source: str) -> List[Dict]:
        """检测绝对定位隐藏"""
        results = []
        
        for match in self.absolute_position_pattern.finditer(content):
            direction = match.group(1).lower()
            value = match.group(2)
            
            # 提取数值部分
            num_value = float(re.search(r'([-\d.]+)', value).group(1))
            
            # 如果位置在屏幕外（非常大的负值或正值）
            if abs(num_value) > 1000:
                results.append({
                    'link': f'绝对定位隐藏 ({direction}:{value})',
                    'source': source,
                    'type': 'position_hiding',
                    'detection_method': 'regex',
                    'risk_level': '高',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return results
    
    def _detect_font_size_hiding(self, content: str, source: str) -> List[Dict]:
        """检测字体大小隐藏"""
        results = []
        
        for match in self.font_size_pattern.finditer(content):
            size = match.group(1)
            
            results.append({
                'link': f'字体大小隐藏 (size:{size})',
                'source': source,
                'type': 'font_size_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return results
    
    def _detect_text_indent_hiding(self, content: str, source: str) -> List[Dict]:
        """检测文本缩进隐藏"""
        results = []
        
        for match in self.text_indent_pattern.finditer(content):
            indent = match.group(1)
            
            # 提取数值部分
            num_value = float(re.search(r'([-\d.]+)', indent).group(1))
            
            # 如果缩进很大（负值），可能是隐藏文本
            if num_value < -50:
                results.append({
                    'link': f'文本缩进隐藏 (indent:{indent})',
                    'source': source,
                    'type': 'text_indent_hiding',
                    'detection_method': 'regex',
                    'risk_level': '高',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return results
    
    def _detect_opacity_hiding(self, content: str, source: str) -> List[Dict]:
        """检测透明度隐藏"""
        results = []
        
        # 检测opacity
        for match in self.opacity_pattern.finditer(content):
            opacity = match.group(1)
            results.append({
                'link': f'透明度隐藏 (opacity:{opacity})',
                'source': source,
                'type': 'opacity_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        # 检测 visibility:hidden / display:none。
        #
        # 这两条原本逐次出现逐条上报、且一律"高"风险。但任何现代站点都有
        # 几十上百处 display:none（下拉菜单、模态框、响应式断点、.sr-only），
        # 全报出来只会把真正的问题淹没。
        # 现在只有「这一处附近确实夹带了链接或实质文本」才上报明细，
        # 其余聚合成一条低风险统计项。
        for pattern, type_name, label in (
            (self.visibility_pattern, 'visibility_hiding', '可见性隐藏 (visibility:hidden)'),
            (self.display_none_pattern, 'display_hiding', '显示隐藏 (display:none)'),
        ):
            aggregated = 0
            reported = 0
            for match in pattern.finditer(content):
                if (not self._context_carries_payload(content, match.start(), match.end())
                        or reported >= self.MAX_FINDINGS_PER_RULE):
                    aggregated += 1
                    continue
                reported += 1
                results.append({
                    'link': label,
                    'source': source,
                    'type': type_name,
                    'detection_method': 'regex',
                    'risk_level': 4,
                    'context': self._get_context(content, match.start(), match.end(), 150)
                })
            if aggregated:
                results.append({
                    'link': f'{label} × {aggregated}（未发现夹带链接，已聚合）',
                    'source': source,
                    'type': f'{type_name}_summary',
                    'detection_method': 'regex',
                    'risk_level': 1,
                    'context': ''
                })

        return results
    
    def _detect_nested_elements(self, content: str, source: str) -> List[Dict]:
        """检测多层嵌套隐藏"""
        results = []
        
        for match in self.nested_elements_pattern.finditer(content):
            results.append({
                'link': '多层嵌套隐藏',
                'source': source,
                'type': 'nested_hiding',
                'detection_method': 'regex',
                'risk_level': '中',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return results
    
    def _detect_html_entities(self, content: str, source: str) -> List[Dict]:
        """检测HTML实体编码隐藏"""
        results = []
        
        # 计算HTML实体的密度
        entity_matches = list(self.html_entity_pattern.finditer(content))
        
        # 如果在较短的文本中有大量实体编码，可能是隐藏内容
        if len(entity_matches) > 10:
            # 尝试解码一些实体看看是否包含可疑内容
            sample = content[max(0, entity_matches[0].start() - 20):entity_matches[min(5, len(entity_matches)-1)].end() + 20]
            
            results.append({
                'link': f'HTML实体编码隐藏 ({len(entity_matches)}个实体)',
                'source': source,
                'type': 'entity_hiding',
                'detection_method': 'regex',
                'risk_level': '中',
                'context': sample
            })
        
        return results
    
    def _colors_are_similar(self, color1: str, color2: str) -> bool:
        """检查两个颜色是否相似"""
        # 这是一个简化的实现，实际应用中可能需要更复杂的颜色比较
        # 在这里我们只是检查是否完全相同或都是深色/浅色
        
        # 转换为小写以便比较
        color1 = color1.lower()
        color2 = color2.lower()
        
        # 如果完全相同，肯定是相似的
        if color1 == color2:
            return True
        
        # 检查是否都是深色（简化判断）
        dark_colors = ['#000', '#000000', 'black', 'rgb(0,0,0)']
        if color1 in dark_colors and color2 in dark_colors:
            return True
        
        # 检查是否都是白色
        white_colors = ['#fff', '#ffffff', 'white', 'rgb(255,255,255)']
        if color1 in white_colors and color2 in white_colors:
            return True
        
        return False
    
    def _extract_hidden_content(self, content: str, markers: List[str]) -> str:
        """从内容中提取使用特定标记隐藏的内容"""
        # 这个方法可以进一步扩展来提取使用零宽字符编码的隐藏内容
        # 目前只是一个简单的实现
        
        # 移除所有标记字符，看看是否有剩余的有意义内容
        clean_content = content
        for marker in markers:
            clean_content = clean_content.replace(marker, '')
        
        # 如果清理后的内容与原内容不同，返回清理后的内容（限制长度）
        if clean_content != content:
            return clean_content.strip()[:200]
        
        return None
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """获取匹配内容的上下文"""
        start_context = max(0, start - context_size)
        end_context = min(len(content), end + context_size)
        
        context = content[start_context:end_context]
        context = context.replace('\n', ' ').replace('\r', ' ')
        
        # 移除零宽字符以便显示
        for char in self.zero_width_chars:
            context = context.replace(char, '')
        
        return context

