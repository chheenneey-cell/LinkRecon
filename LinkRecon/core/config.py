# -*- coding: utf-8 -*-

"""
配置管理模块
"""

class Config:
    """扫描配置类"""
    
    def __init__(self):
        # 扫描目标配置
        self.target_type = None  # 'local_file', 'local_directory', 'internal_url', 'external_url'
        self.target = None
        self.crawl_depth = 1
        self.max_pages = 200  # 同站爬取预算；到达上限时标记扫描不完整

        # 扫描模式配置。
        # 这里直接写 self.scan_mode（绕过 mode setter），是为了让
        # _set_mode_config() 在 __init__ 末尾统一跑一次。
        self.scan_mode = 'standard'  # 'fast', 'standard', 'deep'
        self.threads = 4
        self.timeout = 30
        self.internal_timeout = None  # 未显式覆盖时使用全局 timeout
        self.external_timeout = None
        self.proxy = None
        self.allow_proxy_fake_ip = False  # 仅显式受信任的本地代理可处理域名 Fake-IP
        self.exclude = []
        # 双 UA 抓取用于发现按 User-Agent 返回不同内容的页面；不是搜索爬虫 IP。
        self.ua_mode = 'dual'  # 'dual', 'browser', 'baidu'
        self.browser_user_agent = None  # 留空使用固定、可复现的浏览器 UA
        
        # 关键字配置
        self.keywords_file = None
        self.keyword_ambiguous_terms = []  # 业务歧义词：无同类别独立佐证时仅作待复核候选
        
        # 报告配置
        self.report_type = 'txt'
        self.report_file = None
        
        # 调试模式
        self.debug = False
        # 调试日志读取参数
        self.debug_log_wait_ms = 1500
        self.debug_log_checks = 3
        self.debug_log_interval_ms = 500
        
        # 日志器
        import logging
        self.logger = logging.getLogger('LinkRecon')
        
        # 无头浏览器配置
        self.use_headless_browser = False  # 是否启用无头浏览器
        self.headless_browser = 'chrome'  # 无头浏览器类型
        self.js_wait_time = 3  # JavaScript执行等待时间（秒）
        self.headless_timeout = 60  # 无头浏览器超时时间（秒）
        self.headless_auto_download = False  # 是否自动下载驱动
        self.headless_driver_path = None  # 本地驱动路径
        
        # 文件类型配置
        self.html_extensions = ['.html', '.htm', '.shtml', '.xhtml', '.php', '.asp', '.aspx', '.jsp']
        self.css_extensions = ['.css', '.less', '.scss', '.sass']
        self.js_extensions = ['.js', '.jsx', '.ts', '.tsx']
        self.image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp']
        
        # 扫描配置项
        self.scan_html = True
        self.scan_js = True
        self.scan_css = True
        self.scan_comments = True
        self.scan_meta = True
        self.scan_iframe = True
        self.scan_dom = True
        self.scan_encoding = True
        self.scan_steganography = True
        self.scan_special_hiding = True
        self.scan_keywords = True
        
        # 根据扫描模式调整配置
        self._set_mode_config()
        # 计算当前模式下需要扫描的扩展名
        self.file_extensions = self.get_file_extensions_to_scan()

    # ------------------------------------------------------------------
    # 兼容别名。
    # 原实现写的是 `self.depth = self.crawl_depth`，那是一次性拷贝而不是别名：
    # 之后改 crawl_depth 不会同步 depth，而 Scanner 读的恰恰是 depth；
    # update_mode() 同理只改 scan_mode 不改 mode。
    # 四个入口层都靠"手动两个都赋值"绕过，但 update_mode() 那条路径是漏的。
    # 改成 property 后二者永远一致。
    # ------------------------------------------------------------------
    @property
    def depth(self):
        return self.crawl_depth

    @depth.setter
    def depth(self, value):
        self.crawl_depth = value

    @property
    def mode(self):
        return self.scan_mode

    @mode.setter
    def mode(self, value):
        self.scan_mode = value
        self._set_mode_config()

    def _set_mode_config(self):
        """根据扫描模式设置相应的配置"""
        if self.scan_mode == 'fast':
            # 快速模式：只进行基础扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = False
            self.scan_dom = False
            self.scan_encoding = False
            self.scan_steganography = False
            self.scan_special_hiding = False
            self.scan_keywords = True
        
        elif self.scan_mode == 'standard':
            # 标准模式：进行大部分扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = True
            self.scan_dom = True
            self.scan_encoding = True
            self.scan_steganography = False
            self.scan_special_hiding = True
            self.scan_keywords = True
        
        elif self.scan_mode == 'deep':
            # 深度模式：进行所有扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = True
            self.scan_dom = True
            self.scan_encoding = True
            self.scan_steganography = True
            self.scan_special_hiding = True
            self.scan_keywords = True
        # 同步更新扩展名列表
        self.file_extensions = self.get_file_extensions_to_scan()
    
    def update_mode(self, mode):
        """更新扫描模式"""
        self.scan_mode = mode
        self._set_mode_config()
    
    def get_file_extensions_to_scan(self):
        """获取需要扫描的文件扩展名列表"""
        extensions = []
        
        if self.scan_html:
            extensions.extend(self.html_extensions)
        
        if self.scan_js:
            extensions.extend(self.js_extensions)
        
        if self.scan_css:
            extensions.extend(self.css_extensions)
        
        return list(set(extensions))  # 去重
    
    def get_proxy_dict(self):
        """将代理字符串转换为requests使用的代理字典格式"""
        if not self.proxy:
            return None
        
        proxies = {
            'http': self.proxy,
            'https': self.proxy
        }
        return proxies
    
    def __str__(self):
        """返回配置的字符串表示"""
        return (
            f"Config(" 
            f"target_type={self.target_type}, "
            f"target={self.target}, "
            f"scan_mode={self.scan_mode}, "
            f"threads={self.threads}, "
            f"timeout={self.timeout}, "
            f"internal_timeout={self.internal_timeout}, "
            f"external_timeout={self.external_timeout}, "
            f"report_type={self.report_type}, "
            f"report_file={self.report_file})"
        )
    
    def get_config_dict(self):
        """返回配置的字典表示，用于日志记录"""
        return {
            'target_type': self.target_type,
            'target': self.target,
            'crawl_depth': self.crawl_depth,
            'scan_mode': self.scan_mode,
            'threads': self.threads,
            'timeout': self.timeout,
            'internal_timeout': self.internal_timeout,
            'external_timeout': self.external_timeout,
            'proxy': '***' if self.proxy else None,
            'ua_mode': self.ua_mode,
            'browser_user_agent': self.browser_user_agent,
            'keywords_file': self.keywords_file,
            'keyword_ambiguous_terms': list(self.keyword_ambiguous_terms),
            'report_type': self.report_type,
            'report_file': self.report_file,
            'debug': self.debug
        }
        
