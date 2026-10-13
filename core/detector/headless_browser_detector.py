"""无头浏览器检测器模块

用于通过Chrome无头浏览器检测动态生成的暗链和隐藏内容。
支持检测JavaScript动态生成的内容、DOM操作、iframe内容等。
"""
import time
import logging
from typing import List, Dict, Any
from core.config import Config
from utils.common_utils import normalize_risk
from utils.network_utils import analyze_url_risk


class HeadlessBrowserDetector:
    """无头浏览器检测器类"""
    
    def __init__(self, config: Config):
        """初始化无头浏览器检测器
        
        Args:
            config: 配置对象
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.driver = None
        self._initialize_driver()
        if self.driver is None:
            self._report_error('无头浏览器初始化失败，JS 渲染未执行')

    def _report_error(self, error):
        from utils.detection_errors import report_detection_error
        report_detection_error(self.config, 'headless', getattr(self, '_current_url', ''), error)

    def _javascript_url_findings(self, url, source, occurrences):
        from utils.js_evidence import javascript_url_code, mark_script_finding
        code = javascript_url_code(url)
        if code is None:
            return None
        if not self.config.scan_js:
            return []
        from core.detector.js_detector import JSDetector
        occurrence = occurrences.get(code, 0)
        occurrences[code] = occurrence + 1
        findings = JSDetector(self.config).detect(source, code)
        for issue in findings:
            issue.update(detection_method='headless_browser', source_tag='javascript_attribute')
            mark_script_finding(issue, code, 'javascript_attribute', occurrence)
        return findings
    
    def _initialize_driver(self):
        """初始化Chrome无头浏览器驱动"""
        try:
            # 动态导入，避免在不使用时产生依赖问题
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            import os
            driver_path = getattr(self.config, 'headless_driver_path', None)
            binary_path = getattr(self.config, 'headless_binary', None)
            
            # 创建Chrome选项
            chrome_options = Options()
            if binary_path:
                chrome_options.binary_location = binary_path
            chrome_options.add_argument('--headless')  # 无头模式
            chrome_options.add_argument('--disable-gpu')  # 禁用GPU加速
            chrome_options.add_argument('--no-sandbox')  # 禁用沙箱
            chrome_options.add_argument('--disable-dev-shm-usage')  # 解决内存问题
            chrome_options.add_argument('--window-size=1920,1080')  # 设置窗口大小
            chrome_options.add_argument('--log-level=3')  # 减少日志输出
            
            # 选择驱动来源：优先本地路径；否则在允许时自动下载
            if driver_path and os.path.exists(driver_path):
                service = Service(driver_path)
            else:
                if getattr(self.config, 'headless_auto_download', False):
                    from webdriver_manager.chrome import ChromeDriverManager
                    service = Service(ChromeDriverManager().install())
                else:
                    self.logger.error("未提供本地驱动路径且未启用自动下载，跳过无头浏览器初始化")
                    return
            
            # 创建浏览器驱动。
            # 先用局部变量持有，超时设置成功后才赋给 self.driver：
            # 否则 set_page_load_timeout 抛异常（driver 版本不兼容等）会被外层
            # except 吞掉，而 self.driver 已经指向一个「没有超时限制」的驱动，
            # 后续遇到卡死的目标站会让整个扫描无限期挂起。
            driver = webdriver.Chrome(service=service, options=chrome_options)
            try:
                timeout = getattr(self.config, 'headless_timeout', 60) or 60
                driver.set_page_load_timeout(timeout)
                driver.set_script_timeout(timeout)
            except Exception:
                try:
                    driver.quit()
                except Exception:
                    pass
                raise
            self.driver = driver

            self.logger.info("Chrome无头浏览器初始化成功")

        except ImportError as e:
            self.logger.error(f"缺少无头浏览器相关依赖: {str(e)}")
            self.logger.error("请安装依赖: pip install selenium webdriver-manager")
        except Exception as e:
            self.logger.error(f"无头浏览器初始化失败: {str(e)}", exc_info=True)

    def _wait_for_dom_settled(self, max_wait: int, poll: float = 0.5) -> None:
        """
        等到 DOM 稳定（节点数连续两次不变）或超时，用于捕获延迟注入的暗链。

        Args:
            max_wait: 最长等待秒数
            poll: 轮询间隔秒数
        """
        try:
            max_wait = max(0, int(max_wait or 0))
        except (TypeError, ValueError):
            max_wait = 3
        deadline = time.monotonic() + max_wait
        prev = -1
        waited = 0.0
        try:
            while time.monotonic() < deadline:
                cur = self.driver.execute_script(
                    "return document.getElementsByTagName('*').length")
                prev = cur
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                interval = min(poll, remaining)
                time.sleep(interval)
                waited += interval
        except Exception as e:
            self.logger.debug(f"等待DOM稳定时出错（忽略）: {str(e)}")
            self._report_error(e)
        self.logger.info(f"已观察完整 DOM 时间窗口，实际等待 {waited:.1f}s（配置 {max_wait}s）")

    def detect(self, url: str, content: str = None) -> List[Dict[str, Any]]:
        """使用无头浏览器检测暗链
        
        Args:
            url: 要检测的URL
            content: 可选，页面内容（如果已获取）
            
        Returns:
            检测结果列表
        """
        results = []
        
        if not self.driver:
            self.logger.error("无头浏览器未初始化，跳过检测")
            self._report_error('无头浏览器未初始化，检测不完整')
            return results
        
        try:
            from selenium.webdriver.support.ui import WebDriverWait
            # 加载页面
            self.logger.info(f"无头浏览器正在加载页面: {url}")
            self.driver.get(url)
            self._current_url = self.driver.current_url or url
            
            # 等待JavaScript执行完成。
            # 原实现只等 document.readyState，而 driver.get() 返回时它通常已经是
            # complete，until 第一次求值就通过 -> 实际等待≈0，
            # 而无头检测的全部价值正是捕获 setTimeout 延迟注入的暗链。
            # 这里改用「DOM 节点数连续两次不变」作为注入完成的信号。
            self._wait_for_dom_settled(self.config.js_wait_time)
            
            # 执行各项检测
            self.logger.info("开始执行动态链接检测")
            dynamic_links = self._detect_dynamic_links() if self.config.scan_html else []
            results.extend(dynamic_links)
            
            self.logger.info("开始执行DOM操作检测")
            dom_operations = self._detect_dom_manipulations() if self.config.scan_js else []
            results.extend(dom_operations)
            
            self.logger.info("开始执行iframe内容检测")
            iframe_content = self._detect_iframe_content() if self.config.scan_html and self.config.scan_iframe else []
            results.extend(iframe_content)
            
            self.logger.info("开始执行隐藏元素检测")
            hidden_elements = self._detect_hidden_elements() if self.config.scan_html and self.config.scan_dom else []
            results.extend(hidden_elements)
            
            self.logger.info(f"无头浏览器检测完成，发现 {len(results)} 个可疑项")
            
        except Exception as e:
            self.logger.error(f"无头浏览器检测过程中出错: {str(e)}")
            self._report_error(e)
        
        return results
    
    def _detect_dom_manipulations(self) -> List[Dict[str, Any]]:
        """检测可疑的DOM操作
        
        Returns:
            检测到的可疑DOM操作列表
        """
        results = []
        
        # 注入JavaScript以检测可疑的DOM操作
        # 注意首行的 return：Selenium 的 execute_script 把脚本当作匿名函数体执行，
        # 只有「顶层 return」才能取到返回值。原来写成 `(function(){...})();`，
        # return 在 IIFE 内部，顶层只是一条表达式语句 -> execute_script 返回 None
        # -> 后面 result['suspiciousPatterns'] 抛 TypeError 被吞掉 -> 本方法恒返回 []。
        # 浏览器只负责收集渲染后内容；判定仍由同一 JS 证据分析器完成。
        # 不把任意 innerHTML、字符转换或长脚本当作最高风险，也不执行收集到的代码。
        monitor_script = """
        return Array.from(document.querySelectorAll('script'))
            .filter(script => !script.hasAttribute('src') &&
                ['', 'module', 'text/javascript', 'application/javascript',
                 'text/ecmascript', 'application/ecmascript']
                 .includes((script.type || '').toLowerCase().split(';')[0].trim()))
            .map(script => script.textContent || '');
        """
        
        try:
            result = self.driver.execute_script(monitor_script) or []
            if not isinstance(result, list):
                self.logger.warning(f"DOM监控脚本返回了非预期类型: {type(result)}")
                return results

            from core.detector.js_detector import JSDetector
            detector = JSDetector(self.config)
            source = getattr(self, '_current_url', '') or str(self.driver.current_url)
            occurrences = {}
            for index, script in enumerate(result):
                if not isinstance(script, str):
                    raise ValueError('浏览器返回了无效脚本内容')
                occurrence = occurrences.get(script, 0)
                occurrences[script] = occurrence + 1
                for issue in detector.detect(source, script):
                    issue.update(detection_method='headless_browser', source_tag='rendered_inline_script',
                                 block_index=index)
                    # 相同内容的两个脚本仍是不同发生位置。
                    from utils.js_evidence import mark_script_finding
                    mark_script_finding(issue, script, 'inline_script', occurrence)
                    results.append(issue)
        except Exception as e:
            self.logger.error(f"检测DOM操作时出错: {str(e)}", exc_info=True)
            self._report_error(e)
        
        return results
    
    def _detect_iframe_content(self) -> List[Dict[str, Any]]:
        """检测iframe中的内容
        
        Returns:
            检测到的iframe中的可疑内容列表
        """
        results = []
        
        try:
            from selenium.webdriver.common.by import By
            # 获取所有iframe
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            self.logger.info(f"发现 {len(iframes)} 个iframe元素")
            
            for index, iframe in enumerate(iframes):
                try:
                    javascript_occurrences = {}
                    iframe_src = iframe.get_attribute('src')
                    self.logger.info(f"处理iframe {index + 1}/{len(iframes)}: {iframe_src or '无src属性'}")
                    
                    # 分析iframe的src属性
                    if iframe_src:
                        js = self._javascript_url_findings(iframe_src,
                            getattr(self, '_current_url', '') or self.driver.current_url, javascript_occurrences)
                        if js is not None:
                            results.extend(js)
                        risk_info = analyze_url_risk(iframe_src) if js is None else {'risk_level': 0}
                        
                        if risk_info['risk_level'] > 0:
                            results.append({
                                'type': 'suspicious_iframe',
                                'url': iframe_src,
                                'risk_level': risk_info['risk_level'],
                                'context': f"iframe中的可疑链接",
                                'detection_method': 'headless_browser',
                                'risk_reason': risk_info.get('reason', '可疑iframe源')
                            })
                    
                    # 尝试切换到iframe上下文分析内容
                    try:
                        self.driver.switch_to.frame(iframe)
                        
                        # 获取iframe中的链接
                        iframe_links = self.driver.find_elements(By.TAG_NAME, 'a')
                        for link in iframe_links:
                            href = link.get_attribute('href')
                            if href:
                                js = self._javascript_url_findings(href, iframe_src or self.driver.current_url,
                                                                   javascript_occurrences)
                                if js is not None:
                                    results.extend(js)
                                    continue
                                risk_info = analyze_url_risk(href)
                                
                                if risk_info['risk_level'] > 0:
                                    results.append({
                                        'type': 'suspicious_url',
                                        'url': href,
                                        'risk_level': risk_info['risk_level'],
                                        'context': f"iframe内部的可疑链接",
                                        'detection_method': 'headless_browser',
                                        'risk_reason': risk_info.get('reason', 'iframe内部链接风险')
                                    })
                    except Exception as iframe_e:
                        self.logger.error(f"分析iframe内容时出错: {str(iframe_e)}")
                        self._report_error(f"iframe[{index}] 内容分析失败: {iframe_e}")
                    finally:
                        # 确保切回主文档
                        self.driver.switch_to.default_content()
                
                except Exception as e:
                    self.logger.error(f"处理iframe时出错: {str(e)}")
                    self._report_error(f"iframe[{index}] 处理失败: {e}")
        
        except Exception as e:
            self.logger.error(f"获取iframe元素时出错: {str(e)}")
            self._report_error(e)
        
        return results
    
    def _detect_hidden_elements(self) -> List[Dict[str, Any]]:
        """检测视觉上隐藏的元素
        
        Returns:
            检测到的隐藏元素列表
        """
        results = []
        
        # 注入JavaScript获取隐藏元素
        # 同上：必须是顶层 return，否则 execute_script 返回 None，
        # len(hidden_elements) 抛 TypeError 被吞掉，隐藏元素检测恒为空。
        hidden_elements_script = """
        return (function() {
            const hiddenElements = [];
            
            // 获取所有元素
            const allElements = document.querySelectorAll('*');
            
            allElements.forEach(element => {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                
                // 检查各种隐藏技术
                const isHidden = 
                    style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    style.opacity === '0' ||
                    (style.display !== 'contents' && style.overflow === 'hidden' &&
                     rect.width <= 1 && rect.height <= 1) ||
                    parseInt(style.fontSize) <= 0;
                
                // 检查绝对定位隐藏
                const isAbsPosHidden = 
                    style.position === 'absolute' &&
                    (parseInt(style.left) < -1000 || parseInt(style.top) < -1000 ||
                     parseInt(style.right) < -1000 || parseInt(style.bottom) < -1000);
                
                // 检查文本颜色与背景色相同
                const textColor = style.color;
                const bgColor = style.backgroundColor || style.background;
                const isSameColor = textColor === bgColor && textColor !== 'rgba(0, 0, 0, 0)';
                
                // 检查是否包含链接或文本
                const hasLinks = element.querySelector('a') !== null;
                const hasText = element.textContent.trim().length > 0;
                const hasContent = hasLinks || hasText;
                
                if ((isHidden || isAbsPosHidden || isSameColor) && hasContent) {
                    // 获取元素中的链接（如果有）
                    const links = [];
                    if (hasLinks) {
                        const linkElements = element.querySelectorAll('a');
                        linkElements.forEach(link => {
                            const href = link.getAttribute('href');
                            if (href) links.push(href);
                        });
                    }
                    
                    hiddenElements.push({
                        tagName: element.tagName,
                        id: element.id || '无ID',
                        classes: element.className || '无类名',
                        hiddenBy: isSameColor ? 'color_matching' : 
                                  isAbsPosHidden ? 'absolute_position' : 'visibility',
                        content: element.textContent.trim().substring(0, 200) + '...',
                        hasLinks: hasLinks,
                        links: links,
                        textColor: textColor,
                        bgColor: bgColor
                    });
                }
            });
            
            return hiddenElements;
        })();
        """
        
        try:
            hidden_elements = self.driver.execute_script(hidden_elements_script) or []
            self.logger.info(f"发现 {len(hidden_elements)} 个隐藏元素")

            for elem in hidden_elements:
                # 统一 1-5 量纲：隐藏且带链接=4（暗链），仅隐藏=3
                risk_level = 4 if elem.get('hasLinks') else 3
                
                # 构建风险描述
                context = f"隐藏元素 ({elem['tagName']}): {elem['content']}"
                if elem['hasLinks']:
                    context += f" 包含 {len(elem['links'])} 个链接"
                
                result_item = {
                    'type': 'hidden_element',
                    'technique': elem['hiddenBy'],
                    'risk_level': risk_level,
                    'context': context,
                    'detection_method': 'headless_browser',
                    'risk_reason': '视觉上隐藏的元素可能包含暗链'
                }
                
                # 如果有链接，添加链接信息
                if elem['hasLinks'] and elem['links']:
                    result_item['hidden_links'] = elem['links']
                
                results.append(result_item)
                
                # 对于包含链接的隐藏元素，分别记录每个链接
                if elem['hasLinks'] and elem['links']:
                    for link in elem['links']:
                        risk_info = analyze_url_risk(link)
                        results.append({
                            'type': 'suspicious_url',
                            'url': link,
                            'risk_level': max(risk_level, risk_info['risk_level']),
                            'context': f"隐藏元素中的链接: {link}",
                            'detection_method': 'headless_browser',
                            'risk_reason': f"隐藏在{elem['hiddenBy']}类型的{elem['tagName']}元素中"
                        })
        
        except Exception as e:
            self.logger.error(f"检测隐藏元素时出错: {str(e)}", exc_info=True)
            self._report_error(e)
        
        return results
    
    def close(self):
        """关闭无头浏览器驱动
        
        清理资源，避免内存泄漏
        """
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("无头浏览器已关闭")
            except Exception as e:
                self.logger.error(f"关闭无头浏览器时出错: {str(e)}")
            finally:
                self.driver = None

    def _detect_dynamic_links(self) -> List[Dict[str, Any]]:
        """Collect dynamic link-like references and flag risky/hidden ones."""
        results = []
        try:
            collect_script = r"""
            const attrs = ['href','src','action','formaction','poster','data','cite','longdesc','manifest','background','data-href','data-src','data-url','data-link','data-target','data-redirect','data-location'];
            const cssUrlRe = /url\(\s*['"]?([^'")]+)['"]?\s*\)/ig;
            const out = [];
            function add(el, attr, value, contextType) {
                if (!value || value === '#' || value === 'about:blank') return;
                let raw = String(value).trim();
                if (!raw) return;
                let url = raw;
                try {
                    if (!/^(javascript:|data:|mailto:|tel:)/i.test(raw)) {
                        url = new URL(raw, document.baseURI).href;
                    }
                } catch (e) {}
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                const hidden = style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' ||
                    (style.display !== 'contents' && style.overflow === 'hidden' &&
                     rect.width <= 1 && rect.height <= 1) || el.hidden ||
                    ((style.position === 'absolute' || style.position === 'fixed') &&
                     (parseInt(style.left || '0') < -500 || parseInt(style.top || '0') < -500)) ||
                    parseInt(style.textIndent || '0') < -500;
                out.push({
                    type: 'link_inventory',
                    url,
                    raw,
                    source: document.location.href,
                    source_tag: el.tagName.toLowerCase(),
                    source_attr: attr,
                    context_type: contextType || 'dynamic_dom',
                    context: (el.outerHTML || '').slice(0, 300),
                    hidden
                });
            }
            document.querySelectorAll('*').forEach(el => {
                attrs.forEach(attr => {
                    const v = el.getAttribute(attr);
                    if (v) add(el, attr, v, 'dynamic_attr');
                });
                const srcset = el.getAttribute('srcset');
                if (srcset) {
                    srcset.split(',').forEach(part => {
                        const v = part.trim().split(/\s+/)[0];
                        if (v) add(el, 'srcset', v, 'dynamic_srcset');
                    });
                }
                const styleAttr = el.getAttribute('style') || '';
                let m;
                while ((m = cssUrlRe.exec(styleAttr)) !== null) add(el, 'style', m[1], 'dynamic_css');
            });
            return out;
            """
            dynamic_items = self.driver.execute_script(collect_script) or []
            self.logger.info(f"Dynamic link inventory found {len(dynamic_items)} link-like entries")
            seen = set()
            javascript_occurrences = {}
            for item in dynamic_items:
                try:
                    href = item.get('url')
                    if not href:
                        continue
                    inv_key = (href, item.get('source_tag'), item.get('source_attr'), item.get('hidden'))
                    if inv_key not in seen:
                        seen.add(inv_key)
                        results.append(item)
                    from utils.js_evidence import javascript_url_code
                    if javascript_url_code(href) is not None:
                        if item.get('source_attr') in ('href', 'src'):
                            results.extend(self._javascript_url_findings(href, item.get('source') or self.driver.current_url,
                                                                        javascript_occurrences))
                        continue
                    risk_info = analyze_url_risk(href)
                    if risk_info['risk_level'] > 0 or item.get('hidden'):
                        results.append({
                            'type': 'suspicious_url',
                            'url': href,
                            'risk_level': max(risk_info['risk_level'], 4 if item.get('hidden') else 0),
                            'context': item.get('context', ''),
                            'detection_method': 'headless_browser',
                            'element': item.get('source_tag', 'unknown'),
                            'source_tag': item.get('source_tag', 'unknown'),
                            'source_attr': item.get('source_attr', 'unknown'),
                            'context_type': item.get('context_type', 'dynamic_dom'),
                            'risk_reason': risk_info.get('reason', 'unknown risk')
                        })
                except Exception as e:
                    self.logger.error(f"Error analyzing dynamic link: {str(e)}")
                    self._report_error(e)
        except Exception as e:
            self.logger.error(f"Error collecting dynamic links: {str(e)}")
            self._report_error(e)
        return results
    
    def __del__(self):
        """析构函数，确保资源被释放"""
        self.close()
