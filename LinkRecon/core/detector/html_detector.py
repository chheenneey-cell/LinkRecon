# -*- coding: utf-8 -*-

"""
HTML检测器模块
"""

import re
from utils.detection_errors import report_detection_error
from typing import List, Dict, Any
from urllib.parse import urlparse
from utils.js_evidence import calls, script_blocks, javascript_url_code
from utils.link_utils import extract_link_inventory

from utils.html_utils import (
    extract_script_tags,
    extract_link_tags,
    extract_meta_tags,
    extract_iframe_tags,
    find_hidden_elements,
    get_dom_structure,
    extract_comments
)
from utils.network_utils import (
    extract_urls,
    is_external_link,
    extract_domain
)
from utils.common_utils import (
    extract_text_between_markers,
    get_context,
    get_context_range,
    calculate_entropy
)

# 常见英文词根/词缀。域名标签由这些拼成时，即使很长也不是随机串。
_COMMON_DOMAIN_WORDS = (
    'wiki', 'pedia', 'company', 'group', 'tech', 'shop', 'store', 'news', 'blog',
    'cloud', 'data', 'soft', 'net', 'web', 'site', 'online', 'service', 'support',
    'center', 'global', 'digital', 'media', 'studio', 'design', 'market', 'bank',
    'health', 'travel', 'school', 'university', 'gov', 'admin', 'portal', 'forum',
    'google', 'micro', 'apple', 'amazon', 'alibaba', 'tencent', 'baidu', 'huawei',
)


def _looks_random_domain(host: str) -> bool:
    """
    判断域名的可注册标签是否像随机生成（DGA 域名的典型特征）。

    原实现的规则是「长度 >= 8 且不含数字」就算随机，实测把
    www.wikipedia.org、mycompany.com 全都标记了。
    这里改用「长度 + 元音比例 + 字符熵 + 常见词根」联合判断：
    随机串的熵高、元音少、不含任何常见英文词根。
    """
    if not host:
        return False
    parts = host.split('.')
    if len(parts) < 2:
        return False
    label = parts[-2].lower()
    if len(label) < 10 or '-' in label:
        return False
    if any(w in label for w in _COMMON_DOMAIN_WORDS):
        return False
    letters = [c for c in label if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(c in 'aeiou' for c in letters) / len(letters)
    # 正常英文单词的元音占比大致在 0.3-0.5；随机串通常明显偏低
    return vowel_ratio < 0.25 and calculate_entropy(label) > 3.2


class HTMLDetector:
    """
    HTML内容检测器，用于检测HTML文件中的可疑链接和隐藏元素
    """
    
    def __init__(self, config):
        """
        初始化HTML检测器
        
        Args:
            config: 扫描配置对象
        """
        self.config = config
        self.logger = config.logger
        
        # 可疑HTML模式
        self.suspicious_patterns = {
            'suspicious_attributes': re.compile(r'\bon\w+\s*=\s*["\']?javascript:', re.IGNORECASE),
            'eval_inline': re.compile(r'\beval\s*\(', re.IGNORECASE),
            'document_write': re.compile(r'\bdocument\.write\s*\(', re.IGNORECASE),
            'base64_decode': re.compile(r'\batob\s*\(|\bfromCharCode\s*\(', re.IGNORECASE),
            'data_uri': re.compile(r'data:[^;]+;base64,', re.IGNORECASE),
            'remote_iframe': re.compile(r'<iframe[^>]+src=["\']?https?://', re.IGNORECASE),
            'hidden_divs': re.compile(r'<(div|span|p|section|article)[^>]+style=["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\']', re.IGNORECASE),
            'obfuscated_attributes': re.compile(r'\b(data-|on)[a-z0-9_-]+\s*=\s*["\']?[^"\']*(\\\\x[0-9a-f]{2}|\\\\u[0-9a-f]{4})[^"\']*["\']?', re.IGNORECASE),
        }
        
        # 可疑域名后缀。
        # 原列表里包含 cn / cc / pro / online —— cn 意味着「所有中国站点的域名
        # 一律 +2 分」，对一个面向国内的暗链扫描工具是致命的基线误报，已移除。
        # 保留的是实际被暗链产业大量滥用的免费/廉价 TLD。
        self.suspicious_tld_re = re.compile(
            r'\.(?:tk|ml|ga|cf|gq|xyz|pw|top|loan|win|bid|club|vip|icu|buzz|rest|cyou)$',
            re.IGNORECASE)
        # 域名里直接带博彩词根
        self.gambling_domain_re = re.compile(
            r'\b(?:bet|casino|poker|gamble|lottery|baccarat)\b', re.IGNORECASE)
        
    def detect(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML内容中的可疑元素
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            检测结果列表
        """
        results = []

        # 逐个子检测独立 try/except。
        # 原来是一个大 try 包住全部 5 步，任何一步抛异常（历史上就有 3 处
        # 签名/键名不匹配的 TypeError）都会让整个 detect() 返回空，
        # 在生产中表现为"扫描成功，未发现问题"——最难查的一类故障。
        sub_detectors = (
            ('suspicious_urls', self._detect_suspicious_urls),
            ('base_hijack', self._detect_base_hijack),
            ('suspicious_patterns', self._detect_suspicious_patterns),
            ('hidden_elements', self._detect_hidden_elements),
            ('suspicious_comments', self._detect_suspicious_comments),
            ('suspicious_meta', self._detect_suspicious_meta),
        )
        for name, fn in sub_detectors:
            try:
                results.extend(fn(file_path, content) or [])
            except Exception as e:
                report_detection_error(self.config, 'HTML.' + name, file_path, e)
                self.logger.error(
                    f"HTML子检测 [{name}] 失败: {str(e)}", exc_info=True)

        return results

    # <base href="..."> 提取
    _BASE_TAG_RE = re.compile(
        r'<base\b[^>]*\bhref\s*=\s*(["\']?)([^"\'>\s]+)\1[^>]*>', re.IGNORECASE)

    def _detect_base_hijack(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测 <base href> 劫持。

        注入一个 <base href="http://evil.cn/"> 会让页面上所有相对链接都指向
        攻击者的站点，是暗链/流量劫持的常用手法，而且不会在页面上留下任何
        可见痕迹。合法站点极少使用 <base>，指向外域的更是几乎可以确定是注入。
        """
        results = []
        source_domain = extract_domain(file_path) if str(file_path).startswith(('http://', 'https://')) else ''

        for match in self._BASE_TAG_RE.finditer(content):
            href = (match.group(2) or '').strip()
            if not href:
                continue
            is_absolute = href.lower().startswith(('http://', 'https://', '//'))
            if is_absolute:
                risk_level = 5
                reason = '页面注入了指向外域的 <base href>，所有相对链接都会被劫持到该域名'
            else:
                risk_level = 3
                reason = '页面使用了 <base href>，会改变所有相对链接的解析基准'

            if is_absolute and source_domain and not is_external_link(href, source_domain):
                # 指向自己域名的 base 通常是正常配置
                continue

            results.append({
                'type': 'suspicious_url',
                'file_path': file_path,
                'url': href,
                'link': href,
                'source': file_path,
                'risk_level': risk_level,
                'detection_method': 'base_tag',
                'context_type': 'base_tag',
                'context': get_context_range(content, match.start(), match.end(), 80),
                'position': (match.start(), match.end()),
                'risk_reason': reason,
                'description': reason,
            })

        return results
    
    def _detect_suspicious_urls(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑URL
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑URL检测结果
        """
        results = []
        
        # 仅实际 HTML 属性是页面链接，脚本字符串/注释由独立检测器分析。
        urls = [item for item in extract_link_inventory(content, source=file_path)
                if item.get('context_type') in ('html_attr', 'base_tag', 'meta_refresh')]
        
        for url_obj in urls:
            url = url_obj['url']
            context = url_obj['context']
            if javascript_url_code(url) is not None:
                # 协议前缀和隐藏属性都不能证明这里有危险操作。
                # 实际属性代码由 Scanner 的 JS 证据流程统一分析，避免重复计数。
                continue
            
            # 计算风险等级
            try:
                risk_level, reason = self._calculate_url_risk(url, context, file_path)
            except ValueError:
                # One malformed port/URL must not suppress every other URL.
                risk_level, reason = 1, '地址格式无效，需复核'
            if url_obj.get('hidden'):
                risk_level = max(4, risk_level)
                reason += ', 链接所在元素或祖先具有视觉隐藏属性'
            
            if risk_level > 0:
                result = {
                    'type': 'suspicious_url',
                    'file_path': file_path,
                    'url': url,
                    'risk_level': risk_level,
                    'reason': reason,
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _calculate_url_risk(self, url: str, context: str, source: str) -> tuple:
        """
        计算URL的风险等级
        
        Args:
            url: 要评估的URL
            context: URL的上下文
            
        Returns:
            (风险等级, 原因)
        """
        risk_level = 0
        reason = []
        if javascript_url_code(url) is not None:
            return 0, 'JavaScript 属性由实际操作证据判断，协议前缀本身不计风险'
        
        # 外部/内部链接判断
        source_domain = None
        try:
            if isinstance(source, str) and source.startswith(('http://', 'https://')):
                source_domain = extract_domain(source)
        except Exception:
            source_domain = None
        is_abs = url.lower().startswith(('http://', 'https://'))
        if is_abs:
            # 仅对跨域外部链接提高基础风险
            try:
                link_domain = extract_domain(url)
            except Exception:
                link_domain = None
            from utils.network_utils import is_external_link
            trusted_domains = {
                # JS/CSS 通用CDN
                'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'code.jquery.com', 'ajax.googleapis.com',
                'fonts.googleapis.com', 'fonts.gstatic.com', 'unpkg.com', 'www.unpkg.com',
                'lib.baomitu.com', 'cdn.staticfile.org', 'staticfile.org', 'stackpath.bootstrapcdn.com',
                'maxcdn.bootstrapcdn.com', 'bootcss.com', 'cdn.bootcss.com', 'bootcdn.net', 'cdn.bootcdn.net',
                # 常见站点/资源域（降低误报）
                'hm.baidu.com', 'www.googletagmanager.com', 'busuanzi.ibruce.info',
                'seccdn.libravatar.org', 'registry.npmmirror.com', 'icp.gov.moe',
                'www.bilibili.com', 'hexo.io'
            }
            def _is_trusted(domain: str) -> bool:
                if not domain:
                    return False
                for td in trusted_domains:
                    if domain == td or domain.endswith('.' + td):
                        return True
                return False
            if _is_trusted(link_domain):
                return 0, '可信CDN域名'
            elif is_external_link(url, source_domain):
                risk_level += 2
                reason.append('外部链接')
            
            # 检测可疑域名后缀（跨域时才计入）
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            # TLD is evaluated once below, not added twice for the same signal.
            
            # 随机域名判定放到下面统一用 _looks_random_domain 处理。
            # 原来的规则是"二级标签长度 >= 8 且不含数字"就 +2 分，
            # www.wikipedia.org（wikipedia，9 字符）、mycompany.com 全部中招。
        
        # 检查是否使用了可疑端口
        parsed_url = urlparse(url)
        if parsed_url.port and parsed_url.port not in [80, 443, 8080, 8443]:
            risk_level += 2
            reason.append('使用非标准端口')
        
        # 检查是否包含可疑查询参数
        suspicious_params = ['redirect', 'proxy', 'referer', 'origin', 'callback']
        if parsed_url.query:
            for param in suspicious_params:
                if param in parsed_url.query.lower():
                    risk_level += 1
                    reason.append(f'包含可疑参数: {param}')
                    break
        
        # 检查是否使用了短链接服务
        short_link_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'adf.ly']
        domain = extract_domain(url)
        if domain in short_link_domains:
            risk_level += 3
            reason.append('使用短链接服务')
        
        # 检查域名本身是否可疑。
        # 关键：只对 hostname 匹配，不要对整个 URL 匹配 —— 原实现用
        # pattern.search(url)，导致 https://example.com/somelongword.html
        # 这样的正常路径也被判成"可疑域名模式"。
        host = (parsed_url.hostname or '').lower()
        same_site = is_abs and source_domain and not is_external_link(url, source_domain)
        if host and not same_site:
            if self.suspicious_tld_re.search(host):
                risk_level += 2
                reason.append('高风险域名后缀')
            elif self.gambling_domain_re.search(host):
                risk_level += 3
                reason.append('域名含博彩词根')
            elif _looks_random_domain(host):
                risk_level += 2
                reason.append('可能为随机生成的域名')
        
        # Hiding is evaluated from the actual element/ancestors by the caller,
        # not from a title, documentation string or adjacent element.
        
        # 对相对路径与同域资源降低风险
        if not is_abs:
            if url.startswith('/'):
                # 同域相对路径，不计风险
                return 0, ''
            # 非协议/非根路径的文本片段，不计风险
            if not url.lower().startswith(('javascript:', 'data:')):
                return 0, ''

        return risk_level, ', '.join(reason)
    
    def _detect_suspicious_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑模式
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑模式检测结果
        """
        results = []
        
        markup_content = script_blocks(content, mask_only=True)
        for pattern_name, pattern in self.suspicious_patterns.items():
            if pattern_name in ('eval_inline', 'document_write', 'base64_decode'):
                continue  # 不在 HTML 全文中用正则推断 JS 的执行语义。
            for match in pattern.finditer(markup_content):
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(content), match.end() + 50)
                context = get_context(content, match.start(), 50)
                
                # 计算风险等级
                risk_level = self._get_pattern_risk_level(pattern_name)
                
                result = {
                    'type': 'suspicious_pattern',
                    'file_path': file_path,
                    'pattern': pattern_name,
                    'matched_content': match.group(0),
                    'risk_level': risk_level,
                    'description': self._get_pattern_description(pattern_name),
                    'context': context
                }
                results.append(result)
        
        for script_text, offset, source_tag in script_blocks(content):
            for name, _, position in calls(script_text):
                pattern_name = {'eval': 'eval_inline', 'document.write': 'document_write',
                                'atob': 'base64_decode', 'String.fromCharCode': 'base64_decode'}.get(name)
                if pattern_name:
                    results.append({'type': 'suspicious_pattern', 'file_path': file_path,
                                    'pattern': pattern_name, 'assessment': 'informational',
                                    'risk_level': 1, 'source_tag': source_tag,
                                    'position': (offset + position[0], offset + position[1]),
                                    'matched_content': script_text[position[0]:position[1]],
                                    'description': '脚本结构提示，行为风险由 JS 证据分析判定',
                                    'context': script_text[max(0, position[0] - 50):position[1] + 50]})

        # 检测内联脚本
        script_tags = extract_script_tags(content)
        for script in script_tags:
            is_inline = script.get('inline') if 'inline' in script else (not script.get('src') and bool(script.get('content')))
            if is_inline:
                script_text = script.get('content', '') or ''
                script_length = len(script_text)
                # 计算位置，避免缺少start_pos/end_pos导致异常
                pos = 0
                try:
                    original = script.get('original_tag', '') or ''
                    if original:
                        idx = content.find(original)
                        if idx >= 0:
                            pos = idx
                        else:
                            # 回退使用脚本内容定位
                            cidx = content.find(script_text[:50]) if script_text else -1
                            pos = cidx if cidx >= 0 else 0
                    else:
                        # 使用src或部分内容定位
                        src = script.get('src', '') or ''
                        if src:
                            import re as _re
                            m = _re.search(r'<script[^>]*src=["\']' + _re.escape(src) + r'["\']', content, _re.IGNORECASE)
                            pos = m.start() if m else 0
                        else:
                            cidx = content.find(script_text[:50]) if script_text else -1
                            pos = cidx if cidx >= 0 else 0
                except Exception:
                    pos = 0
                # 检测复杂内联脚本
                if script_length > 1000:
                    context = get_context(content, pos, 100)
                    result = {
                        'type': 'suspicious_pattern',
                        'file_path': file_path,
                        'pattern': 'large_inline_script',
                        'matched_content': script_text[:200] + '...',
                        'risk_level': 2,
                        'description': '大型内联脚本',
                        'context': context
                    }
                    results.append(result)
        
        return results
    
    def _get_pattern_risk_level(self, pattern_name: str) -> int:
        """
        获取模式的风险等级
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            风险等级
        """
        risk_levels = {
            'suspicious_attributes': 3,
            'eval_inline': 4,
            'document_write': 3,
            'base64_decode': 2,
            'data_uri': 2,
            'remote_iframe': 3,
            'hidden_divs': 2,
            'obfuscated_attributes': 3
        }
        
        return risk_levels.get(pattern_name, 1)
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """
        获取模式的描述
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            描述文本
        """
        descriptions = {
            'suspicious_attributes': '可疑的事件属性',
            'eval_inline': '内联eval函数',
            'document_write': 'document.write调用',
            'base64_decode': 'Base64解码操作',
            'data_uri': 'Data URI',
            'remote_iframe': '远程iframe',
            'hidden_divs': '隐藏的div元素',
            'obfuscated_attributes': '混淆的属性'
        }
        
        return descriptions.get(pattern_name, pattern_name)
    
    def _detect_hidden_elements(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的隐藏元素
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            隐藏元素检测结果
        """
        results = []
        
        hidden_elements = find_hidden_elements(content)
        
        for element in hidden_elements:
            # find_hidden_elements 返回的键是 tag/style/reason/content/original_tag，
            # 这里必须按这组键取值。此前按 type/method/context 取，三个键一个都不存在，
            # 结果全部降级为「unknown 元素 / unknown 技术 / 风险 1」，
            # 而报告的展示门槛是风险 >= 4，等于所有隐藏元素都被静默丢弃。
            element_type = element.get('tag', 'unknown')
            hiding_method = element.get('style') or element.get('reason') or 'unknown'
            context = element.get('original_tag') or element.get('content') or ''

            # 计算风险等级
            risk_level = self._calculate_hidden_element_risk(element)

            if risk_level > 0:
                result = {
                    'type': 'hidden_element',
                    'file_path': file_path,
                    'element_type': element_type,
                    'hiding_method': hiding_method,
                    'risk_level': risk_level,
                    'context': context[:500],
                    'description': f"隐藏的{element_type}元素，使用{hiding_method}技术"
                }
                results.append(result)

        return results

    def _calculate_hidden_element_risk(self, element: Dict[str, Any]) -> int:
        """
        计算隐藏元素的风险等级（1-5）

        Args:
            element: find_hidden_elements 产出的元素信息
                     （键：tag / style / reason / content / original_tag）

        Returns:
            风险等级
        """
        # 基础风险
        risk_level = 1

        method = (element.get('style') or '') + ' ' + (element.get('reason') or '')
        context = element.get('original_tag') or element.get('content') or ''

        # 高风险隐藏手法
        high_risk_methods = ('position:absolute', 'opacity:0', 'clip-path',
                             'text-indent', 'transform', 'font-size:0')
        if any(m in method.replace(' ', '') for m in high_risk_methods):
            risk_level += 1

        # 隐藏的内容很长，说明藏的是实质内容而不是交互占位
        if len(context) > 100:
            risk_level += 1

        # 隐藏元素里带链接 —— 这正是「暗链」的定义，单这一条就应达到
        # 报告的展示门槛（>=4），不能因为凑不满分而被过滤掉
        links = extract_link_inventory(context, source='')
        if any(item.get('context_type') == 'html_attr'
               and javascript_url_code(item.get('url', '')) is None for item in links):
            risk_level += 3

        return min(5, risk_level)
    
    def _detect_suspicious_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑注释
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑注释检测结果
        """
        results = []
        
        comments = extract_comments(content)
        
        # 可疑注释模式。
        # 注意：extract_comments 返回的 content 是 <!-- --> 之间的「内容」
        # （标记已被 strip 掉），所以这里必须对内容匹配。原实现的 4 个正则都
        # 要求文本以字面 <!-- 开头、--> 结尾，search 恒为 False，
        # 注释里藏的 base64 payload / password 字样 / 超长注释全部漏报。
        suspicious_comment_patterns = {
            'hidden_content': re.compile(r'(?:password|passwd|secret|private|admin|backdoor)', re.IGNORECASE),
            'encoded_content': re.compile(r'(?:base64|atob|unescape|decodeURI|fromCharCode|eval\s*\()', re.IGNORECASE),
            'conditional_comments': re.compile(r'^\s*\[if\b', re.IGNORECASE),
            'large_comment': re.compile(r'[\s\S]{500,}')
        }

        for c in comments:
            if isinstance(c, dict):
                text = c.get('content') or ''
                pos = c.get('position')
            else:
                text = c if isinstance(c, str) else ''
                pos = None
            if not text:
                continue

            # 位置优先用 extract_comments 给的 position；没有再退回 find。
            # 直接 content.find(text) 每次都是全文扫描，而且同一段注释重复
            # 出现时定位会错到第一次出现的位置。
            if isinstance(pos, (list, tuple)) and len(pos) == 2:
                start, end = pos
            else:
                start = content.find(text)
                end = start + len(text) if start >= 0 else 0
                start = max(0, start)

            for pattern_name, pattern in suspicious_comment_patterns.items():
                if pattern.search(text):
                    # 计算风险等级
                    risk_level = self._get_comment_risk_level(pattern_name)

                    result = {
                        'type': 'suspicious_comment',
                        'file_path': file_path,
                        'pattern': pattern_name,
                        'comment': text[:200] + ('...' if len(text) > 200 else ''),
                        'risk_level': risk_level,
                        'description': self._get_comment_description(pattern_name),
                        'context': get_context_range(content, start, end, 50)
                    }
                    results.append(result)
        
        # 检测注释中的链接
        link_pattern = re.compile(r'href=["\'](https?://[^"\']+)')
        for c in comments:
            text = c['content'] if isinstance(c, dict) else (c if isinstance(c, str) else '')
            if not text:
                continue
            for match in link_pattern.finditer(text):
                url = match.group(1)
                result = {
                    'type': 'suspicious_url',
                    'file_path': file_path,
                    'url': url,
                    'risk_level': 3,
                    'reason': '链接位于HTML注释中',
                    'context': text[:200] + ('...' if len(text) > 200 else '')
                }
                results.append(result)
        
        return results
    
    def _get_comment_risk_level(self, pattern_name: str) -> int:
        """
        获取注释模式的风险等级
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            风险等级
        """
        risk_levels = {
            'hidden_content': 3,
            'encoded_content': 3,
            'conditional_comments': 1,
            'large_comment': 2
        }
        
        return risk_levels.get(pattern_name, 1)
    
    def _get_comment_description(self, pattern_name: str) -> str:
        """
        获取注释模式的描述
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            描述文本
        """
        descriptions = {
            'hidden_content': '包含敏感信息的注释',
            'encoded_content': '包含编码内容的注释',
            'conditional_comments': '条件注释',
            'large_comment': '大型注释'
        }
        
        return descriptions.get(pattern_name, pattern_name)
    
    def _detect_suspicious_meta(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑Meta标签
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑Meta标签检测结果
        """
        results = []
        
        meta_tags = extract_meta_tags(content)
        
        # 检测可疑的refresh或redirect Meta标签
        for meta in meta_tags:
            http_equiv = meta.get('http-equiv', '').lower()
            content_attr = meta.get('content', '').lower()
            
            if http_equiv in ['refresh', 'redirect'] and 'url=' in content_attr:
                # 提取URL
                url_match = re.search(r'url=(\S+)', content_attr)
                if url_match:
                    url = url_match.group(1)
                    result = {
                        'type': 'suspicious_url',
                        'file_path': file_path,
                        'url': url,
                        'risk_level': 3,
                        'reason': '通过Meta标签重定向',
                        'context': meta.get('raw', '')
                    }
                    results.append(result)
        
        # 检测包含可疑内容的Meta标签
        suspicious_meta_keywords = ['bot', 'spider', 'crawler', 'nofollow', 'noindex']
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content_attr = meta.get('content', '').lower()
            
            if name in ['robots', 'keywords', 'description']:
                for keyword in suspicious_meta_keywords:
                    if keyword in content_attr:
                        result = {
                            'type': 'suspicious_meta',
                            'file_path': file_path,
                            'meta_name': name,
                            'suspicious_keyword': keyword,
                            'risk_level': 1,
                            'description': f"包含可疑关键词'{keyword}'的Meta标签",
                            'context': meta.get('raw', '')
                        }
                        results.append(result)
        
        return results
        
