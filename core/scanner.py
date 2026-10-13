# -*- coding: utf-8 -*-

"""
扫描引擎模块
"""

import os
import re
import time
import threading
import concurrent.futures
import json
import fnmatch
from urllib.parse import urlparse, urldefrag
from typing import Dict, List, Set, Tuple, Any

# 注意：re 和 urlparse 模块已在此处导入，用于支持URL解析和正则表达式匹配功能

from core.config import Config
from core.detector.html_detector import HTMLDetector
from core.detector.js_detector import JSDetector
from core.detector.css_detector import CSSDetector
from core.detector.special_hiding_detector import SpecialHidingDetector
from core.detector.keyword_detector import KeywordDetector

from utils.file_utils import (
    read_file,
    get_file_list,
    is_binary_file,
    get_file_info

)
from utils.network_utils import (
    is_url,
    is_valid_url,
    fetch_url_content,
    normalize_url,
    extract_domain,
    is_external_link,
    url_origin,
)
from utils.common_utils import normalize_risk
from utils.finding_policy import is_reportable, issue_count
from utils.js_evidence import script_blocks, finding_id, mark_script_finding
from utils.request_profiles import request_profiles
from utils.link_utils import extract_link_inventory, summarize_link_inventory
from utils.logging_utils import (
    log_scan_result,
    log_keyword_match,
    log_suspicious_url,
    log_hidden_technique,
    log_file_skipped
)

# 进入报告 / 计入问题总数的风险门槛（归一化后的 1-5 量纲）
RISK_REPORT_THRESHOLD = 4


class Scanner:
    """
    扫描器主类
    """
    def __init__(self, config: Config):
        """
        初始化扫描器
        
        Args:
            config (Config): 扫描配置
        """
        self.config = config
        self.logger = config.logger
        self.threads = config.threads
        self.timeout = config.timeout
        self.proxy = config.proxy
        self.depth = config.depth
        self.mode = config.mode
        self.lock = threading.RLock()
        self._initial_errors = []
        config.record_detection_error = self._record_detection_error
        
        # 初始化检测器
        self.html_detector = HTMLDetector(config)
        self.js_detector = JSDetector(config)
        self.css_detector = CSSDetector(config)
        self.special_hiding_detector = SpecialHidingDetector(config)
        self.keyword_detector = KeywordDetector(config)
        # 关键字文件解析：
        #   1) Config 的正式字段是 keywords_file（带 s），同时兼容历史上的 keyword_file；
        #   2) 未指定时回退到「项目根目录」而不是 os.getcwd()，
        #      否则从项目目录以外启动会静默地一个关键字都加载不到。
        try:
            kw_path = (getattr(config, 'keywords_file', None)
                       or getattr(config, 'keyword_file', None))
            if not kw_path:
                proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                cand = os.path.join(proj_root, 'keywords_example.txt')
                kw_path = cand if os.path.exists(cand) else None
            if not kw_path:
                self.logger.warning("未找到关键字文件，关键字检测未启用")
            elif not os.path.exists(kw_path):
                self.logger.warning(f"关键字文件不存在，关键字检测未启用: {kw_path}")
            elif self.keyword_detector.load_keywords(kw_path):
                self.logger.info(
                    f"已加载关键字文件 {kw_path}"
                    f"（{len(self.keyword_detector.keywords)} 个关键字）")
            else:
                self.logger.warning(f"关键字文件加载失败，关键字检测将不生效: {kw_path}")
        except Exception as e:
            self.logger.error(f"初始化关键字检测器失败: {str(e)}", exc_info=True)
        
        # 初始化无头浏览器检测器（如果启用）
        self.headless_browser_detector = None
        if hasattr(config, 'use_headless_browser') and config.use_headless_browser:
            try:
                from core.detector.headless_browser_detector import HeadlessBrowserDetector
                self.headless_browser_detector = HeadlessBrowserDetector(config)
                self.logger.info("无头浏览器检测器已初始化")
            except Exception as e:
                self.logger.error(f"初始化无头浏览器检测器失败: {str(e)}")
                self._record_detection_error(f"无头浏览器初始化失败: {e}")
                self.logger.warning("将继续扫描，但不使用无头浏览器功能")
        
        # 用于跟踪已扫描的文件和URL，避免重复扫描
        self.scanned_items = set()
        self._crawl_origins = set()
        self._crawl_limit_reported = False
        
        # 用于存储响应头信息
        self.response_headers = {}
        
        # 用于收集扫描结果
        self.results = {
            'total_files': 0,
            'scanned_files': 0,
            'scanned_urls': 0,
            'total_issues': 0,
            'suspicious_links': [],
            'link_inventory': [],
            'link_stats': {
                'link_total': 0,
                'unique_links': 0,
                'hidden_links': 0,
                'suspicious_unique_links': 0,
                'suspicious_hits': 0
            },
            'hidden_elements': [],
            'keyword_matches': [],
            'js_issues': [],
            'css_issues': [],
            'ua_comparisons': [],
            'scan_time': 0,
            # scan() 内部会捕获并吞掉异常，只靠"有没有抛异常"无法判断成败。
            # 把错误记在这里，调用方（CLI 退出码、Web 任务状态）才能区分
            # "扫干净了"和"压根没扫成"。
            'errors': list(self._initial_errors)
        }
    
    def _record_detection_error(self, message):
        with self.lock:
            errors = self.results['errors'] if hasattr(self, 'results') else self._initial_errors
            if str(message) not in errors:
                errors.append(str(message))

    def _detect(self, detector, *args):
        try:
            return detector.detect(*args)
        except Exception as error:
            self._record_detection_error(f"{self.config.target} [{type(detector).__name__}]: {error}")
            return []

    def scan(self) -> Dict[str, Any]:
        """
        开始扫描
        
        Returns:
            Dict[str, Any]: 扫描结果
        """
        start_time = time.time()
        
        try:
            target = self.config.target
            
            # 根据目标类型选择不同的扫描策略
            if hasattr(self.config, 'target_type'):
                target_type = self.config.target_type
                
                if target_type in ['internal_url', 'external_url']:
                    # URL扫描 - 区分内网和外网
                    # 超时选择：内网/公网各有独立超时，但没设置时必须回退到全局
                    # config.timeout。原来用 hasattr 判断，而 Config.__init__ 恒定义了
                    # internal_timeout=60 / external_timeout=30，判断永远为真，
                    # 于是 --timeout 对所有 URL 目标完全无效。
                    if target_type == 'internal_url':
                        self.logger.info(f"开始扫描内网URL: {target}")
                        self.timeout = getattr(self.config, 'internal_timeout', None) or self.timeout
                    else:
                        self.logger.info(f"开始扫描公网URL: {target}")
                        self.timeout = getattr(self.config, 'external_timeout', None) or self.timeout
                    self.logger.debug(f"本次请求超时设置为 {self.timeout} 秒")
                    
                    self._scan_url(target)
                elif target_type == 'local_file':
                    # 本地文件扫描
                    self.logger.info(f"开始扫描本地文件: {target}")
                    self.results['total_files'] += 1
                    self._scan_file(target)
                elif target_type == 'local_directory':
                    # 本地目录扫描
                    self.logger.info(f"开始扫描本地目录: {target}")
                    self._scan_directory(target)
                else:
                    # 未知类型，使用原始逻辑尝试识别
                    self.logger.warning(f"未知目标类型: {target_type}，尝试自动识别")
                    self._auto_detect_and_scan(target)
            else:
                # 向后兼容：如果配置中没有target_type属性，使用原始逻辑
                self._auto_detect_and_scan(target)
                
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {str(e)}", exc_info=True)
            self.results['errors'].append(f"{self.config.target}: {e}")
        finally:
            # 计算扫描时间
            self.results['scan_time'] = time.time() - start_time
            
            # 确保关闭无头浏览器
            if hasattr(self, 'headless_browser_detector') and self.headless_browser_detector:
                try:
                    self.headless_browser_detector.close()
                    self.logger.info("无头浏览器已关闭")
                except Exception as e:
                    self.logger.error(f"关闭无头浏览器时出错: {str(e)}")
            self._refresh_link_stats()
            self.results['scan_status'] = 'incomplete' if self.results['errors'] else 'complete'

        return self.results

    def _record_link_inventory(self, content: str, source: str, content_type: str = 'html') -> None:
        try:
            links = extract_link_inventory(content, source=source, content_type=content_type)
            if not links:
                return
            with self.lock:
                self.results['link_inventory'].extend(links)
            self.logger.info(f"Link inventory collected {len(links)} entries from {source}")
        except Exception as e:
            self.logger.error(f"Link inventory extraction failed for {source}: {str(e)}")

    # 内联 <script> / <style> 块的提取正则（模块级预编译，避免每个文件重复编译）
    _INLINE_SCRIPT_RE = re.compile(
        r'<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>', re.IGNORECASE | re.DOTALL)
    _INLINE_STYLE_RE = re.compile(
        r'<style\b[^>]*>(.*?)</style\s*>', re.IGNORECASE | re.DOTALL)

    def _scan_inline_blocks(self, source: str, content: str, file_results: Dict,
                            aggregate: bool = True, javascript_urls_only: bool = False) -> None:
        """
        对 HTML 中的内联 <script> / <style> 块运行 JS / CSS 检测器。

        Args:
            source: 文件路径或URL，用于结果标注
            content: HTML 全文
            file_results: 本文件的结果字典，会被就地补充
        """
        blocks = [(text, offset, tag, 'js_issues', self.js_detector)
                  for text, offset, tag in script_blocks(content) if self.config.scan_js
                  and (not javascript_urls_only or tag == 'javascript_attribute')]
        if self.config.scan_css and not javascript_urls_only:
            blocks.extend((m.group(1), m.start(1), 'inline_style', 'css_issues', self.css_detector)
                          for m in self._INLINE_STYLE_RE.finditer(script_blocks(content, mask_only=True)))
        occurrences = {}
        for index, (text, offset, tag, key, detector) in enumerate(blocks):
            if not text.strip():
                continue
            try:
                issues = detector.detect(source, text)
            except Exception as e:
                self.logger.error(f"内联检测失败: {source}", exc_info=True)
                with self.lock:
                    self.results['errors'].append(f"{source} {tag}[{index}]: {e}")
                continue
            identity = (tag, text)
            occurrence = occurrences.get(identity, 0)
            occurrences[identity] = occurrence + 1
            for item in issues:
                item['source_tag'], item['block_index'] = tag, index
                if key == 'js_issues':
                    mark_script_finding(item, text, tag, occurrence)
                position = item.get('position')
                if isinstance(position, (list, tuple)) and len(position) == 2:
                    item['position'] = (offset + position[0], offset + position[1])
                if item.get('finding_id'):
                    item['finding_id'] = finding_id(item)
            file_results.setdefault(key, []).extend(issues)
            if aggregate:
                with self.lock:
                    self.results[key].extend(issues)
                    self.results['suspicious_links'].extend(
                        item for item in issues if item.get('url') and is_reportable(item))

    def _refresh_link_stats(self) -> None:
        with self.lock:
            self.results['total_issues'] = issue_count(self.results)
            self.results['link_stats'] = summarize_link_inventory(
                self.results.get('link_inventory', []),
                self.results.get('suspicious_links', [])
            )

    def _auto_detect_and_scan(self, target: str) -> None:
        """
        自动检测目标类型并扫描（向后兼容）
        
        Args:
            target (str): 扫描目标
        """
        if is_url(target):
            # 扫描URL
            self.logger.info(f"扫描URL: {target}")
            self.results['total_files'] += 1
            self._scan_url(target)
        elif os.path.isfile(target):
            # 扫描单个文件
            self.logger.info(f"扫描单个文件: {target}")
            self.results['total_files'] += 1
            self._scan_file(target)
        elif os.path.isdir(target):
            # 扫描目录
            self.logger.info(f"扫描目录: {target}")
            self._scan_directory(target)
        else:
            self.logger.error(f"无效的扫描目标: {target}")
    
    def _scan_directory(self, directory: str) -> None:
        """
        扫描目录
        
        Args:
            directory (str): 目录路径
        """
        # 获取文件列表
        file_list = get_file_list(
            directory,
            recursive=True,
            depth=self.depth,
            extensions=self.config.file_extensions,
            exclude=self.config.exclude
        )
        
        self.results['total_files'] = len(file_list)
        self.logger.info(f"开始扫描目录 {directory}，共 {len(file_list)} 个文件")
        
        # 使用线程池扫描文件
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有扫描任务
            future_to_file = {executor.submit(self._scan_file, file_path): file_path 
                             for file_path in file_list}
            
            # 处理结果
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"扫描文件 {file_path} 时出错: {str(e)}", exc_info=True)
                    with self.lock:
                        self.results['errors'].append(f"{file_path}: {e}")
    
    def _scan_file(self, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        扫描单个文件
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: 文件扫描结果
        """
        # 检查文件是否已扫描
        with self.lock:
            if file_path in self.scanned_items:
                return {}
            self.scanned_items.add(file_path)
        
        # 检查是否为二进制文件
        if is_binary_file(file_path):
            log_file_skipped(self.logger, file_path, "二进制文件")
            return {}
        
        # 获取文件信息
        file_info = get_file_info(file_path)
        
        # 检查文件大小限制
        if hasattr(self.config, 'max_file_size') and file_info['size'] > self.config.max_file_size:
            log_file_skipped(self.logger, file_path, f"文件大小超过限制 ({file_info['size']} > {self.config.max_file_size})")
            return {}
        
        try:
            # 读取文件内容
            content = read_file(file_path)
            if not content:
                log_file_skipped(self.logger, file_path, "文件为空或无法读取")
                return {}
            
            # 根据文件扩展名选择检测器
            file_ext = os.path.splitext(file_path)[1].lower()
            file_results = {}
            inventory_type = 'html' if file_ext in ['.html', '.htm', '.shtml', '.xhtml', '.php', '.asp', '.aspx', '.jsp'] else file_ext.lstrip('.') or 'text'
            self._record_link_inventory(content, file_path, inventory_type)
            
            # 基础扫描模式 - 所有模式都包含
            if self.config.scan_keywords and self.mode in ['fast', 'standard', 'deep']:
                # 关键字检测
                keyword_results = self.keyword_detector.detect(content, file_path, inventory_type)
                if keyword_results:
                    file_results['keyword_matches'] = keyword_results
                    
                    # 记录到全局结果
                    with self.lock:
                        self.results['keyword_matches'].extend(keyword_results)
                        for match in keyword_results:
                            log_keyword_match(
                                self.logger,
                                file_path,
                                match['keyword'],
                                match['category'],
                                match['weight'],
                                match['context']
                            )
            
            # HTML文件检测
            self.logger.info(f"文件扩展名: {file_ext}, self.mode: {self.mode}")
            if file_ext in ['.html', '.htm', '.shtml', '.xhtml', '.php', '.asp', '.aspx', '.jsp']:
                self.logger.info(f"开始处理HTML文件: {file_path}")
                # 检查模式
                if self.config.scan_html and self.mode in ['fast', 'standard', 'deep']:
                    self.logger.info(f"调用HTML检测器，扫描模式: {self.mode}")
                    # HTML检测器
                    html_results = self.html_detector.detect(file_path, content)
                    self.logger.info(f"HTML检测器返回结果数量: {len(html_results)}")
                    if html_results:
                        file_results['html_issues'] = html_results
                        
                        # 记录可疑链接
                        with self.lock:
                            for issue in html_results:
                                if issue['type'] == 'suspicious_url':
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
                                else:
                                    self.results['hidden_elements'].append(issue)
                else:
                    self.logger.warning(f"扫描模式不匹配: {self.mode}")
                
            # 高级模式（对应 standard 与 deep）
                if self.mode in ['standard', 'deep']:
                    # 特殊隐藏技术检测（修正参数顺序）
                    hiding_results = (self._detect(self.special_hiding_detector, content, file_path)
                                      if self.config.scan_special_hiding else [])
                    if hiding_results:
                        file_results['hiding_techniques'] = hiding_results

                        # 记录到全局结果
                        with self.lock:
                            self.results['hidden_elements'].extend(hiding_results)
                            for issue in hiding_results:
                                log_hidden_technique(
                                    self.logger,
                                    file_path,
                                    issue.get('type', 'hidden_element'),
                                    issue.get('risk_level', 2),
                                    issue.get('context', '')
                                )

                    # HTML 页面里的内联 <script> / <style> 同样要过 JS/CSS 检测器。
                    # 此前 JS/CSS 检测只挂在 .js/.css 扩展名的 elif 分支上，
                    # 于是本地 HTML 文件里内联的 eval(atob(...))、
                    # .seo{position:absolute;left:-9999px} 完全没有被分析
                    # （URL 扫描路径是做了的，两条路径能力不一致）。
                    self._scan_inline_blocks(file_path, content, file_results)
                elif self.config.scan_js:
                    self._scan_inline_blocks(file_path, content, file_results, javascript_urls_only=True)


            # JavaScript文件检测
            elif file_ext in ['.js', '.jsx', '.ts', '.tsx']:
                # 高级模式（对应 standard 与 deep）
                if self.config.scan_js and self.mode in ['standard', 'deep']:
                    js_results = self.js_detector.detect(file_path, content)
                    if js_results:
                        file_results['js_issues'] = js_results
                        
                        # 记录可疑链接
                        with self.lock:
                            self.results['js_issues'].extend(js_results)
                            for issue in js_results:
                                if issue.get('url') and is_reportable(issue):
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
            
            # CSS文件检测
            elif file_ext in ['.css', '.less', '.scss', '.sass']:
                # 高级模式（对应 standard 与 deep）
                if self.config.scan_css and self.mode in ['standard', 'deep']:
                    css_results = self.css_detector.detect(file_path, content)
                    if css_results:
                        file_results['css_issues'] = css_results
                        
                        # 记录可疑链接
                        with self.lock:
                            self.results['css_issues'].extend(css_results)
                            for issue in css_results:
                                if issue.get('url') and is_reportable(issue):
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
            
            # 更新计数器
            with self.lock:
                self.results['scanned_files'] += 1
                
                # 计算总问题数（按风险阈值过滤）。
                # 必须走 normalize_risk：直接 int() 遇到 '高'/'中' 会抛异常并记 0 分，
                # 导致 SpecialHidingDetector 的全部发现对 total_issues 贡献为零
                # （表现为「报出 N 条可疑链接，但问题总数对不上」）。
                total_issues = issue_count(file_results | {
                    'hidden_elements': file_results.get('html_issues', []) + file_results.get('hiding_techniques', [])})
                
                if total_issues > 0:
                    self.results['total_issues'] = issue_count(self.results)
                    # 构建问题列表用于日志记录
                    issues_list = []
                    if 'keyword_matches' in file_results:
                        issues_list.extend([f"关键字: {m['keyword']}" for m in file_results['keyword_matches']])
                    if 'html_issues' in file_results:
                        issues_list.extend([f"HTML问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['html_issues'] if normalize_risk(m.get('risk_level')) >= RISK_REPORT_THRESHOLD])
                    if 'js_issues' in file_results:
                        issues_list.extend([f"JS问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['js_issues'] if normalize_risk(m.get('risk_level')) >= RISK_REPORT_THRESHOLD])
                    if 'css_issues' in file_results:
                        issues_list.extend([f"CSS问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['css_issues'] if normalize_risk(m.get('risk_level')) >= RISK_REPORT_THRESHOLD])
                    if 'hiding_techniques' in file_results:
                        issues_list.extend(["隐藏技术: " + str(m.get('type', 'unknown')) for m in file_results['hiding_techniques'] if normalize_risk(m.get('risk_level')) >= RISK_REPORT_THRESHOLD])
                    
                    log_scan_result(self.logger, file_path, issues_list)
            
            return file_results
            
        except Exception as e:
            # 这里必须把错误记进 results：本方法用一个大 try 包住了全部检测步骤，
            # 任何一处签名/键名不匹配的异常都会让整个文件的结果静默丢失，
            # 表现为"扫描成功，未发现问题"——本项目历史上最难查的一类故障。
            self.logger.error(f"处理文件 {file_path} 时出错: {str(e)}", exc_info=True)
            with self.lock:
                self.results['errors'].append(f"{file_path}: {e}")
            return {}
    
    def _scan_url(self, url: str, current_depth: int = 0) -> None:
        """同一 URL 使用隔离的 UA 会话抓取；相同响应只检测一次，差异本身不算风险。"""
        if current_depth > self.depth:
            return
        url = urldefrag(url)[0]
        if os.path.isfile(url):
            self._scan_file(url)
            return
        if not url.startswith(('http://', 'https://')) or not is_valid_url(url):
            self.results['errors'].append(f"{url}: 无效 URL")
            return
        with self.lock:
            if url in self.scanned_items:
                return
            if not self._crawl_origins:
                self._crawl_origins.add(url_origin(url))
            if current_depth and url_origin(url) not in self._crawl_origins:
                return
            if len(self.scanned_items) >= getattr(self.config, 'max_pages', 200):
                if not self._crawl_limit_reported:
                    self.results['errors'].append('达到同站爬取页面数量上限，扫描不完整')
                    self._crawl_limit_reported = True
                return
            self.scanned_items.add(url)

        from core.runner import is_internal_host
        internal = (self.config.target_type == 'internal_url'
                    or is_internal_host(urlparse(url).hostname))
        timeout = (getattr(self.config, 'internal_timeout', None) if internal
                   else getattr(self.config, 'external_timeout', None)) or self.timeout
        snapshots, profile_results, analyzed = [], {}, {}
        try:
            profiles = request_profiles(getattr(self.config, 'ua_mode', 'dual'))
            for profile in profiles:
                self.logger.info(f"获取 URL: {url}，请求身份: {profile}")
                fetch_errors = []
                # 每个身份独立建/关会话，防止响应 Cookie 把另一视角污染。
                snapshot = fetch_url_content(
                    url, allow_internal=internal, profile=profile,
                    browser_user_agent=getattr(self.config, 'browser_user_agent', None),
                    timeout=timeout, proxies=self.config.get_proxy_dict(),
                    return_metadata=True, allow_http_errors=True,
                    allowed_origins=self._crawl_origins if current_depth else None,
                    allow_proxy_fake_ip=getattr(self.config, 'allow_proxy_fake_ip', False),
                    error_callback=fetch_errors.append)
                if snapshot is None:
                    error = fetch_errors[-1] if fetch_errors else {'code': 'request_failed', 'message': '请求失败，未获得响应'}
                    snapshots.append({'profile': profile, 'error': error['message'], 'error_code': error['code']})
                    self._record_detection_error(f"{url} [{profile}]: {error['message']}")
                    profile_results[profile] = {}
                    continue
                snapshot['profile'] = profile
                snapshots.append(snapshot)
                self.logger.debug(f"UA {profile}: HTTP {snapshot['status_code']}, "
                                  f"最终地址 {snapshot['final_url']}, {snapshot['body_bytes']} 字节")
                content_type = snapshot.get('content_type', '').lower()
                identity = (snapshot['body_sha256'], snapshot['final_url'], content_type)
                if identity not in analyzed:
                    try:
                        error_count = len(self.results['errors'])
                        analyzed[identity] = self._analyze_response(snapshot)
                        if len(self.results['errors']) > error_count:
                            snapshot['error'] = '子检测失败，响应分析不完整'
                    except Exception as exc:
                        snapshot['error'] = '响应检测失败：' + str(exc)
                        self.results['errors'].append(f"{url} [{profile}]: {snapshot['error']}")
                        profile_results[profile] = {}
                        continue
                profile_results[profile] = analyzed[identity]
                if snapshot['status_code'] >= 400:
                    self._record_detection_error(f"{url} [{profile}]: HTTP {snapshot['status_code']}")
                if snapshot.get('body_truncated'):
                    self._record_detection_error(f"{url} [{profile}]: 响应体被截断，分析不完整")

            with self.lock:
                comparison = self._compare_responses(url, snapshots, profile_results)
                self.results['ua_comparisons'].append(comparison)
                self.logger.info(f"UA 对照: {url}: {comparison['assessment']}")
                self._merge_profile_findings(url, profile_results)
                if not any(200 <= item.get('status_code', 0) < 400 for item in snapshots):
                    self.results['errors'].append(f"{url}: 所有 UA 请求均失败或返回 HTTP 错误")
                good = next((item for item in snapshots if 200 <= item.get('status_code', 0) < 400), None)
                if good:
                    self.response_headers[url] = good['headers']
                    if current_depth == 0:
                        self._crawl_origins.add(url_origin(good['final_url']))

            # 浏览器渲染仍只执行一次，不把 HTTP 请求头模拟误称为真实爬虫渲染。
            if self.headless_browser_detector and good:
                content_type = good.get('content_type', '').lower()
                if 'html' in content_type:
                    headless = self._detect(self.headless_browser_detector, good['final_url'], good['content'])
                    findings = {'link_inventory': [], 'suspicious_links': [], 'hidden_elements': []}
                    for issue in headless or []:
                        if issue.get('type') == 'link_inventory':
                            findings['link_inventory'].append(issue)
                        elif issue.get('url'):
                            findings['suspicious_links'].append(issue)
                        else:
                            findings['hidden_elements'].append(issue)
                    self._merge_profile_findings(url, {'rendered_browser': findings})
        except Exception as exc:
            self.logger.error(f"扫描 URL 失败: {url}: {exc}", exc_info=True)
            with self.lock:
                self.results['errors'].append(f"{url}: {exc}")
        finally:
            with self.lock:
                # URL 数是目标数，不是 UA 请求数。
                self.results['scanned_urls'] += 1

        if current_depth < self.depth:
            candidates = set()
            for findings in profile_results.values():
                for item in findings.get('link_inventory', []):
                    candidate = urldefrag(item.get('url') or '')[0]
                    try:
                        parsed = urlparse(candidate)
                        origin = url_origin(candidate)
                    except ValueError:
                        self._record_detection_error(f"无效的子页面地址: {candidate}")
                        continue
                    if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
                        continue
                    if origin not in self._crawl_origins:
                        continue
                    tag, attr = item.get('source_tag'), item.get('source_attr')
                    navigation = tag in ('a', 'area', 'iframe') and attr in ('href', 'src')
                    resource = tag in ('script', 'link') and attr in ('src', 'href')
                    code_resource = os.path.splitext(parsed.path)[1].lower() in ('.js', '.mjs', '.cjs', '.css')
                    if not (navigation or resource or code_resource):
                        continue
                    if tag == 'link' and not code_resource:
                        continue  # 不下载图片、字体、图标等非代码资源
                    excluded = any(fnmatch.fnmatch(candidate, pattern) or
                                   fnmatch.fnmatch(parsed.path, pattern) or
                                   (pattern.endswith('/') and pattern in parsed.path)
                                   for pattern in self.config.exclude)
                    if not excluded:
                        candidates.add(candidate)
            for candidate in sorted(candidates):
                self._scan_url(candidate, current_depth + 1)

    def _analyze_response(self, snapshot: Dict) -> Dict:
        """每个不同响应都走同样的检测流程，基于最终地址解析相对链接。"""
        source, content = snapshot['final_url'], snapshot['content']
        content_type = snapshot.get('content_type', '').lower()
        if not content_type:
            extension = os.path.splitext(urlparse(source).path)[1].lower()
            content_type = ('text/css' if extension == '.css' else 'application/javascript'
                            if extension in self.config.js_extensions else
                            'text/html' if re.search(r'<[a-zA-Z!]', content) else 'text/plain')
        findings = {key: [] for key in ('link_inventory', 'suspicious_links', 'hidden_elements',
                                        'keyword_matches', 'js_issues', 'css_issues')}
        findings['link_inventory'] = extract_link_inventory(content, source=source, content_type=content_type)
        if self.config.scan_keywords:
            findings['keyword_matches'] = self._detect(self.keyword_detector, content, source, content_type)
        if 'html' in content_type:
            if self.config.scan_html:
                for issue in self._detect(self.html_detector, source, content):
                    if issue.get('type') == 'suspicious_url' or issue.get('url'):
                        if issue.get('url'):
                            issue['url'] = normalize_url(issue['url'], source)
                            issue['link'] = issue['url']
                        findings['suspicious_links'].append(issue)
                    else:
                        findings['hidden_elements'].append(issue)
            if self.mode in ('standard', 'deep'):
                if self.config.scan_special_hiding:
                    findings['hidden_elements'].extend(self._detect(self.special_hiding_detector, content, source))
                self._scan_inline_blocks(source, content, findings, aggregate=False)
            elif self.config.scan_js:
                self._scan_inline_blocks(source, content, findings, aggregate=False, javascript_urls_only=True)
        elif 'javascript' in content_type and self.config.scan_js and self.mode in ('standard', 'deep'):
            findings['js_issues'] = self._detect(self.js_detector, source, content)
        elif 'css' in content_type and self.config.scan_css and self.mode in ('standard', 'deep'):
            findings['css_issues'] = self._detect(self.css_detector, source, content)
        for key in ('js_issues', 'css_issues'):
            findings['suspicious_links'].extend(
                issue for issue in findings[key] if issue.get('url') and is_reportable(issue))
        return findings

    def _merge_profile_findings(self, requested_url: str, by_profile: Dict) -> None:
        """跨 UA 合并同一证据，但保留视角归属；不同上下文不会因关键词相同被吞掉。"""
        with self.lock:
            for key in ('link_inventory', 'suspicious_links', 'hidden_elements',
                        'keyword_matches', 'js_issues', 'css_issues'):
                seen = {}
                for profile, findings in by_profile.items():
                    for original in findings.get(key, []):
                        identity = json.dumps(original, sort_keys=True, ensure_ascii=False, default=str)
                        if identity in seen:
                            if profile not in seen[identity]['request_profiles']:
                                seen[identity]['request_profiles'].append(profile)
                            continue
                        item = dict(original)
                        item.setdefault('source', original.get('file_path') or requested_url)
                        item['requested_url'] = requested_url
                        item['request_profiles'] = [profile]
                        seen[identity] = item
                self.results[key].extend(seen.values())
            self.results['total_issues'] = issue_count(self.results)

    @staticmethod
    def _compare_responses(source: str, snapshots: List[Dict], by_profile: Dict) -> Dict:
        views = []
        for item in snapshots:
            profile = item['profile']
            findings = by_profile.get(profile, {})
            views.append({
                'profile': profile, 'status_code': item.get('status_code'),
                'final_url': item.get('final_url', ''), 'body_sha256': item.get('body_sha256', ''),
                'content_type': item.get('content_type', ''),
                'body_truncated': item.get('body_truncated', False),
                'body_bytes': item.get('body_bytes', 0), 'error': item.get('error', ''),
                'error_code': item.get('error_code', ''), 'proxy_dns': item.get('proxy_dns', False),
                'link_count': len(findings.get('link_inventory', [])),
                'keyword_count': len(findings.get('keyword_matches', [])),
            })
        successful = [view for view in views if view['status_code'] is not None and 200 <= view['status_code'] < 400
                      and not view['error'] and not view['body_truncated']]
        if len(views) == 1:
            assessment = 'single_profile' if successful else 'comparison_incomplete'
        elif len(successful) != len(views):
            assessment = 'comparison_incomplete'
        else:
            same = len({(view['body_sha256'], view['final_url'], view['status_code'], view['content_type']) for view in views}) == 1
            assessment = 'same_response' if same else 'response_differs'
        def values(profile, key, value):
            return {item.get(value) for item in by_profile.get(profile, {}).get(key, []) if item.get(value)}
        browser_links, baidu_links = values('browser', 'link_inventory', 'url'), values('baidu', 'link_inventory', 'url')
        browser_words, baidu_words = values('browser', 'keyword_matches', 'keyword'), values('baidu', 'keyword_matches', 'keyword')
        comparable = len(views) == 2 and len(successful) == 2
        return {
            'source': source, 'assessment': assessment, 'profiles': views,
            'browser_only_links': sorted(browser_links - baidu_links) if comparable else [],
            'baidu_only_links': sorted(baidu_links - browser_links) if comparable else [],
            'browser_only_keywords': sorted(browser_words - baidu_words) if comparable else [],
            'baidu_only_keywords': sorted(baidu_words - browser_words) if comparable else [],
            'note': 'UA 响应差异仅供复核，不等于确认暗链；模拟 UA 不具有搜索爬虫 IP 身份。',
        }

# 扫描器主要功能:
# 1. 支持文件、目录和URL三种扫描模式
# 2. 基于文件类型选择不同的检测器
# 3. 多线程并发扫描提高效率
# 4. 避免重复扫描相同的文件或URL
# 5. 收集和汇总所有扫描结果
# 6. 支持不同的扫描深度和模式
# 7. 详细的日志记录
