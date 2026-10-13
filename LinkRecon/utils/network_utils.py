# -*- coding: utf-8 -*-

"""
网络处理工具模块
"""

import os
import re
import socket
import logging
import ipaddress
import requests
import ssl
from requests.utils import get_encoding_from_headers, get_encodings_from_content
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin
from utils.request_profiles import build_request_headers
from utils.network_policy import AddressBlocked, check_target_address

logger = logging.getLogger('LinkRecon.utils.network')

# 常见URL模式正则表达式
URL_PATTERNS = [
    # 标准URL
    re.compile(r'https?://[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 协议相对URL
    re.compile(r'//[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 仅域名
    re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?', re.IGNORECASE),
    # IP地址形式
    re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?::\d{1,5})?', re.IGNORECASE),
    # JavaScript伪协议
    re.compile(r'javascript:[^\s"\'>]+', re.IGNORECASE),
    # data URI
    re.compile(r'data:[^;]+;base64,[^\s"\'>]+', re.IGNORECASE),
    # 相对路径
    re.compile(r'/[^\s"\'>]+', re.IGNORECASE),
]


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """
    规范化URL
    
    Args:
        url: 原始URL
        base_url: 基础URL，用于解析相对路径
    
    Returns:
        规范化后的URL
    """
    try:
        # 处理双斜杠开头的URL：优先https，或继承base_url协议
        if url.startswith('//'):
            if base_url:
                base_parsed = urlparse(base_url)
                scheme = base_parsed.scheme or 'https'
                return f'{scheme}:{url}'
            return f'https:{url}'
        
        # 处理相对路径
        if base_url and not (url.startswith('http://') or url.startswith('https://')):
            return urljoin(base_url, url)
        
        # 对于纯域名，默认添加https://
        parsed = urlparse(url)
        if not parsed.scheme:
            return f'https://{url}'
        
        return url
        
    except Exception as e:
        logger.error(f"规范化URL失败: {url}, 错误: {str(e)}")
        return url

def get_url_type(url: str) -> str:
    """
    获取URL类型
    
    Args:
        url: URL字符串
    
    Returns:
        URL类型
    """
    if url.startswith('http://') or url.startswith('https://'):
        return 'absolute'
    elif url.startswith('//'):
        return 'protocol-relative'
    elif url.startswith('/'):
        return 'root-relative'
    else:
        return 'relative'

def check_url_reachability(url: str, timeout: int = 5, headers: Optional[Dict] = None) -> Tuple[bool, Optional[str]]:
    """
    检查URL是否可达
    
    Args:
        url: 要检查的URL
        timeout: 超时时间（秒）
        headers: 请求头
    
    Returns:
        (是否可达, 状态码或错误信息)
    """
    try:
        if headers is None:
            headers = build_request_headers()
        
        response = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)
        return response.status_code < 400, str(response.status_code)
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"URL检查失败: {url}, 错误: {str(e)}")
        return False, str(e)

def validate_url(url: str) -> bool:
    """
    验证URL格式是否有效
    
    Args:
        url: 要验证的URL
    
    Returns:
        URL是否有效
    """
    try:
        result = urlparse(url)
        
        # 对于绝对URL，需要有scheme和netloc
        if url.startswith('http://') or url.startswith('https://'):
            return all([result.scheme, result.netloc])
        
        # 对于相对URL，返回True
        return True
        
    except Exception as e:
        logger.error(f"URL验证失败: {url}, 错误: {str(e)}")
        return False

def get_domain(url: str) -> Optional[str]:
    """
    从URL中提取域名
    
    Args:
        url: URL字符串
    
    Returns:
        域名
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception as e:
        logger.error(f"提取域名失败: {url}, 错误: {str(e)}")
        return None

def is_external_link(url: str, base_domain: Optional[str] = None) -> bool:
    """
    判断是否为外部链接
    
    Args:
        url: 要检查的URL
        base_domain: 基础域名
    
    Returns:
        是否为外部链接
    """
    url_domain = get_domain(url)
    if not url_domain:
        return False
    if not base_domain:
        # 未提供基础域名时，尽量避免误报：只有显式协议的绝对链接视为外部
        return url.startswith(('http://', 'https://'))
    # 检查是否为同一域名或子域名
    # 同域或子域视为内部，其余为外部
    return not (url_domain == base_domain or url_domain.endswith(f'.{base_domain}'))

# 兼容性函数，用于判断字符串是否为URL
def is_url(text: str) -> bool:
    """
    判断字符串是否为URL
    
    Args:
        text: 要检查的文本
    
    Returns:
        是否为URL
    """
    try:
        # 首先检查是否为本地文件，如果是，直接返回False
        if os.path.isfile(text) or os.path.isdir(text):
            logger.debug(f"{text} 是本地文件或目录，不视为URL")
            return False
        
        # 检查是否以http://或https://开头
        if text.startswith(('http://', 'https://')):
            return True
        
        # 过滤典型代码符号，避免误判为URL
        if re.search(r"^(document|window|parent|this)\.[A-Za-z_]", text):
            return False
        if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(", text):
            if not re.search(r"https?://", text):
                # 若函数调用前缀，但内容中存在引号包裹的URL片段，视为URL
                quoted = re.findall(r'"([^"]*)"|\'([^\']*)\'', text)
                candidates = [q[0] or q[1] for q in quoted]
                # 原来写的是 (p.search(seg) for seg in URL_PATTERNS for seg in candidates)：
                # p 从未定义，且循环变量 seg 写了两遍（本意是 for p in URL_PATTERNS）。
                # NameError 被吞掉直接返回 False —— 形如 setTimeout("//evil.cn/x")
                # 的协议相对 URL 暗链 100% 漏报。
                if not any(p.search(seg) for p in URL_PATTERNS for seg in candidates):
                    return False
        
        # 检查是否通过URL格式验证
        if not validate_url(text):
            return False
        
        # 检查是否匹配至少一个URL模式
        for pattern in URL_PATTERNS:
            if pattern.search(text):
                return True
        
        return False
    except Exception as e:
        logger.error(f"URL检查失败: {text}, 错误: {str(e)}")
        return False

# 兼容性函数，validate_url的别名
def is_valid_url(url: str) -> bool:
    """
    验证URL格式是否有效（validate_url的别名）
    
    Args:
        url: 要验证的URL
    
    Returns:
        URL是否有效
    """
    return validate_url(url)

def get_url_context(text: str, position: Tuple[int, int], context_length: int = 50) -> str:
    """
    获取URL在文本中的上下文
    
    Args:
        text: 原始文本
        position: URL在文本中的位置 (start, end)
        context_length: 上下文长度
    
    Returns:
        包含上下文的文本
    """
    start_pos, end_pos = position
    
    # 计算上下文的起始和结束位置
    context_start = max(0, start_pos - context_length)
    context_end = min(len(text), end_pos + context_length)
    
    # 提取上下文
    context = text[context_start:context_end]
    
    # 添加省略号
    prefix = '...' if context_start > 0 else ''
    suffix = '...' if context_end < len(text) else ''
    
    return f"{prefix}{context}{suffix}"

def build_request_session(proxy: Optional[str] = None, timeout: int = 10,
                          profile: str = 'browser', browser_user_agent=None) -> requests.Session:
    """
    构建请求会话
    
    Args:
        proxy: 代理设置
        timeout: 超时时间
    
    Returns:
        请求会话对象
    """
    session = requests.Session()
    
    # 设置默认请求头
    session.headers.update(build_request_headers(profile, browser_user_agent))
    
    # 设置代理
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        session.proxies.update(proxies)
        logger.info("已设置显式代理")
    
    # 配置HTTPS适配器，启用兼容旧式TLS重协商
    class TLSAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.create_default_context()
            try:
                ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
            except Exception:
                pass
            kwargs['ssl_context'] = ctx
            return super().init_poolmanager(*args, **kwargs)
        def proxy_manager_for(self, *args, **kwargs):
            ctx = ssl.create_default_context()
            try:
                ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
            except Exception:
                pass
            kwargs['ssl_context'] = ctx
            return super().proxy_manager_for(*args, **kwargs)
    # http:// 与 https:// 必须挂同样的重试策略。
    # 原来只给 https 挂了 max_retries=3，http 走默认的 Retry(0)；
    # 而且 Retry.from_int(3) 的 backoff_factor=0 意味着无退避立即重连，
    # 对目标站点不友好也容易被限流。
    try:
        from urllib3.util.retry import Retry
        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=frozenset(['GET', 'HEAD']))
    except Exception:
        retry = 3
    try:
        session.mount('https://', TLSAdapter(max_retries=retry))
    except Exception:
        pass
    try:
        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retry))
    except Exception:
        pass
    # 注意：requests 不支持在 Session 上设置默认超时，必须在每次请求时传。
    # timeout 形参保留只为兼容旧调用方，这里不使用它。

    return session

# 单个响应最多读取多少字节。
# 扫描器请求的 URL 全部来自被扫页面本身（不可信输入），一个指向大文件
# 或慢速无限流的链接就能把进程内存打爆。
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# 最大重定向跳数。默认不限会让 302 链把扫描拖死。
MAX_REDIRECTS = 5


def _resolve_host_ips(host: str):
    """解析主机名到 IP 列表；解析失败返回空列表。"""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except Exception:
        return []


def url_origin(url):
    parsed = urlparse(url)
    return (parsed.scheme.lower(), (parsed.hostname or '').lower(),
            parsed.port or (443 if parsed.scheme == 'https' else 80))


def is_internal_address(host: str) -> bool:
    """
    判断主机是否解析到内网/保留地址（用于 SSRF 防护）。

    扫描器的输入正是攻击者可控的页面内链接，如果不拦，
    http://127.0.0.1:6379/ 和 http://169.254.169.254/latest/meta-data/
    这类地址会被照单全收地请求 —— 典型的 SSRF 面。
    解析不出来的主机一律当作不安全，宁可不发请求。
    """
    if not host:
        return True
    host = host.strip('[]').lower()
    if host in ('localhost', 'localhost.localdomain'):
        return True

    candidates = []
    try:
        candidates.append(ipaddress.ip_address(host))
    except ValueError:
        for raw in _resolve_host_ips(host):
            try:
                candidates.append(ipaddress.ip_address(raw))
            except ValueError:
                continue
        if not candidates:
            return True  # 解析不了就不要发请求

    for ip in candidates:
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            m = ip.ipv4_mapped
            if m.is_private or m.is_loopback or m.is_link_local:
                return True
    return False


def _read_body_capped(response, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:
    """流式读取响应体并封顶，避免超大响应把内存打爆。"""
    declared = response.headers.get('Content-Length')
    if declared:
        try:
            if int(declared) > max_bytes:
                logger.warning(
                    f"响应体声明长度 {declared} 超过上限 {max_bytes}，仅读取前 {max_bytes} 字节")
        except ValueError:
            pass
    buf = bytearray()
    for chunk in response.iter_content(8192):
        if not chunk:
            continue
        buf.extend(chunk)
        if len(buf) >= max_bytes:
            logger.warning(f"响应体超过上限 {max_bytes} 字节，已截断: {response.url}")
            break
    return bytes(buf)


def _pick_encoding(response, raw: bytes) -> str:
    """
    选择解码用的编码。

    优先级必须是「HTTP 头显式声明 > HTML meta charset > chardet 猜测」。
    原实现把 apparent_encoding（chardet 猜测）排在最前面，页面以 ASCII 为主、
    只夹杂少量中文时（正是暗链页的典型形态）会误判 —— 服务器明明声明了 gbk，
    chardet 猜成 iso8859-2，中文全部变成乱码，关键字检测再也匹配不到。
    """
    declared = get_encoding_from_headers(response.headers)
    # requests 在无 charset 的 text/* 上会填 ISO-8859-1，这属于"未声明"
    if declared and declared.lower() in ('iso-8859-1', 'latin-1', 'latin1'):
        declared = None
    if not declared:
        try:
            metas = get_encodings_from_content(raw[:4096].decode('ascii', 'ignore'))
            declared = metas[0] if metas else None
        except Exception:
            declared = None
    if declared:
        return declared
    # 流式读取后 response.content 已被消费，apparent_encoding 会再次读取它并
    # 抛 RuntimeError。只对已经封顶的原始字节猜编码，不重读响应流。
    try:
        from requests.compat import chardet
        guessed = chardet.detect(raw).get('encoding') if chardet else None
    except Exception:
        guessed = None
    return guessed or 'utf-8'


def fetch_url_content(url: str, session: Optional[requests.Session] = None,
                      allow_internal: bool = False, profile: str = 'browser',
                      browser_user_agent=None, return_metadata: bool = False,
                      allow_http_errors: bool = False, allowed_origins=None,
                      allow_proxy_fake_ip: bool = False, error_callback=None, **kwargs):
    """
    获取URL内容或本地文件内容

    Args:
        url: 要获取的URL或本地文件路径
        session: 请求会话对象
        allow_internal: 是否允许请求内网地址（扫描内网目标时由调用方显式开启）
        profile: browser 或 baidu 请求身份；传入会话/显式 headers 可覆盖默认头
        return_metadata: 返回含状态码、最终地址、内容指纹的快照，默认仍返回二元组
        allow_http_errors: 是否读取 HTTP 错误页用于对照（调用方须记录失败状态）
        allow_proxy_fake_ip: 显式允许受信任回环代理处理域名的 Fake-IP 解析，默认关闭
        error_callback: 可选，接收含 code/message/url 的失败信息；旧调用方仍得到 None
        **kwargs: 其他请求参数（timeout 支持标量或 (connect, read) 元组）

    Returns:
        元组 (内容字符串, 头部信息字典)，失败时返回None
    """
    own_session = None
    def report_error(code, message):
        # 异常可能含带认证的代理 URL，不能把口令放进任务日志或报告。
        def redact(text):
            return re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@', r'\1***@', str(text))
        detail = {'code': code, 'message': redact(message), 'url': redact(url)}
        logger.warning('%s: %s', detail['url'], detail['message'])
        if error_callback:
            try:
                error_callback(detail)
            except Exception as callback_error:
                logger.warning('请求错误回调失败：%s', type(callback_error).__name__)
    try:
        # 检查是否为本地文件路径
        if not url.startswith(('http://', 'https://')):
            # 尝试作为本地文件读取
            if os.path.isfile(url):
                logger.info(f"读取本地文件: {url}")
                with open(url, 'r', encoding='utf-8') as f:
                    content = f.read()
                # 返回内容和模拟的头部信息
                return content, {'Content-Type': 'text/html'}
            else:
                report_error('file_not_found', '本地文件不存在')
                return None
        
        # 所有入口使用同一份身份配置；调用方传入的 UA 优先于会话和默认值。
        default_headers = build_request_headers(profile, browser_user_agent)
        if session is not None:
            default_headers.update(session.headers)
        
        # 合并默认请求头和传入的请求头
        headers = default_headers.copy()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # timeout 必须用 pop 而不是 get —— 用 get 的话 timeout 既作为显式关键字
        # 传了一次，又留在 **kwargs 里传了第二次，直接
        # TypeError: get() got multiple values for keyword argument 'timeout'，
        # 而异常被下面的 except 吞掉，调用方只看到"获取失败"。
        timeout = kwargs.pop('timeout', (5, 10))
        # 单个标量只限制单次 connect/read，不限制总耗时；拆成元组更可控
        if isinstance(timeout, (int, float)):
            timeout = (min(float(timeout), 10.0), float(timeout))

        if session is None:
            session = build_request_session(profile=profile, browser_user_agent=browser_user_agent)
            own_session = session
        session.max_redirects = MAX_REDIRECTS

        # 禁止 requests 自动跟随重定向：落点检查必须发生在发送下一跳之前。
        # 每一跳（包括中间跳及同主机名的重新解析）都重新检查，拒绝非 HTTP 协议。
        kwargs.pop('allow_redirects', None)
        current_url = url
        response = None
        proxy_dns = False
        for hop in range(MAX_REDIRECTS + 1):
            if allowed_origins is not None and url_origin(current_url) not in allowed_origins:
                raise AddressBlocked('crawl_scope', f'重定向超出同站爬取范围：{current_url}')
            # 只信任显式传入的代理，不把环境变量/系统代理等同于用户授权。
            proxies = dict(session.proxies or {})
            proxies.update(kwargs.get('proxies') or {})
            selected_proxy = requests.utils.select_proxy(current_url, proxies)
            uses_proxy_dns = check_target_address(current_url, _resolve_host_ips, allow_internal,
                                                  allow_proxy_fake_ip, selected_proxy)
            if uses_proxy_dns:
                # 将代理钉在此次请求：防止环境代理覆盖或代理失效时静默回退直连。
                proxies[urlparse(current_url).scheme] = selected_proxy
                kwargs['proxies'] = proxies
                proxy_dns = True
            response = session.get(current_url, timeout=timeout, stream=True,
                                   allow_redirects=False, **kwargs)
            if response.status_code not in (301, 302, 303, 307, 308) or not response.headers.get('Location'):
                break
            if hop == MAX_REDIRECTS:
                response.close()
                raise requests.exceptions.TooManyRedirects(f"超过重定向上限 {MAX_REDIRECTS}")
            from urllib.parse import urljoin
            next_url = urljoin(response.url, response.headers['Location'])
            if session.should_strip_auth(response.url, next_url):
                # 显式凭据不能随跨域跳转泄漏；会话 Cookie 仍由域名作用域控制。
                kwargs['headers'] = {k: v for k, v in kwargs['headers'].items()
                                     if k.lower() not in ('authorization', 'cookie', 'host')}
                kwargs['headers'].update({'Authorization': None, 'Cookie': None, 'Host': None})
                kwargs['auth'] = ()  # overrides a borrowed Session.auth as well
            response.close()
            current_url = next_url
        try:
            if not allow_http_errors:
                response.raise_for_status()

            # requests 的实际响应地址应与已校验的当前跳一致；仍复核异常适配器的落点。
            if response.url != current_url:
                if allowed_origins is not None and url_origin(response.url) not in allowed_origins:
                    raise AddressBlocked('crawl_scope', '最终响应地址超出同站爬取范围')
                check_target_address(response.url, _resolve_host_ips, allow_internal,
                                     allow_proxy_fake_ip, selected_proxy)

            raw = _read_body_capped(response)
            enc = _pick_encoding(response, raw)
            try:
                text = raw.decode(enc, errors='replace')
            except LookupError:
                text = raw.decode('utf-8', errors='replace')

            if return_metadata:
                import hashlib
                return {
                    'content': text, 'headers': dict(response.headers),
                    'content_type': response.headers.get('Content-Type', ''),
                    'status_code': response.status_code, 'final_url': response.url,
                    'body_sha256': hashlib.sha256(raw).hexdigest(),
                    'body_bytes': len(raw),
                    'body_truncated': len(raw) >= MAX_RESPONSE_BYTES,
                    'proxy_dns': proxy_dns,
                }
            return text, dict(response.headers)
        finally:
            response.close()

    except AddressBlocked as e:
        report_error(e.code, str(e))
        return None
    except requests.exceptions.ProxyError as e:
        report_error('proxy_error', f'代理连接失败（不会回退直连）：{e}')
        return None
    except requests.exceptions.Timeout as e:
        report_error('timeout', f'请求超时：{e}')
        return None
    except requests.exceptions.SSLError as e:
        report_error('tls_error', f'TLS 证书验证或握手失败：{e}')
        return None
    except requests.exceptions.RequestException as e:
        report_error('request_error', f'网络请求失败：{e}')
        return None
    except Exception as e:
        report_error('content_error', f'请求配置或响应读取失败：{e}')
        return None
    finally:
        # 自己建的临时会话必须关闭，否则连接池随调用次数无限累积
        if own_session is not None:
            try:
                own_session.close()
            except Exception:
                pass

# 兼容性函数，为了支持html_detector.py中的导入
def extract_domain(url: str) -> Optional[str]:
    """
    从URL中提取域名（get_domain的别名）
    
    Args:
        url: URL字符串
    
    Returns:
        域名
    """
    return get_domain(url)

def analyze_url_risk(url: str) -> Dict[str, Any]:
    """
    评估URL风险等级
    Returns: {risk_level: int, reason: str}
    """
    try:
        risk = 0
        reasons = []
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()
        # 协议风险
        if scheme == 'javascript':
            risk += 5
            reasons.append('JavaScript协议')
        elif scheme == 'data':
            risk += 4
            reasons.append('Data URI')
        elif scheme in ('http', 'https'):
            risk += 1
        # 端口风险
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            risk += 2
            reasons.append('非标准端口')
        # 可疑后缀与短链服务
        suspicious_tlds = ['pro', 'xyz', 'pw', 'top', 'loan', 'win', 'bid', 'online']
        short_link_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'adf.ly']
        if any(domain.endswith('.' + tld) for tld in suspicious_tlds):
            risk += 2
            reasons.append('高风险域名后缀')
        if any(domain.endswith(sl) or domain == sl for sl in short_link_domains):
            risk += 3
            reasons.append('短链接服务')
        # 路径随机性
        if re.search(r'/[a-zA-Z0-9]{8,}\.(?:js|php)$', parsed.path):
            risk += 1
            reasons.append('可疑随机路径')
        return {'risk_level': min(risk, 10), 'reason': ', '.join(reasons) or '普通URL'}
    except Exception as e:
        logger.error(f"URL风险评估失败: {url}, 错误: {str(e)}")
        return {'risk_level': 0, 'reason': '评估失败'}

def extract_urls(text: str, context_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    从文本中提取所有URL
    
    Args:
        text: 要提取URL的文本
    
    Returns:
        包含URL和上下文的字典列表
    """
    results = []
    urls_set = set()  # 用于去重
    
    # 增加URL模式匹配
    url_patterns = [
        re.compile(r'(https?://[\w._~:/?#[\]@!$&\'()*+,-;=]+)', re.IGNORECASE),
        re.compile(r'(/[-\w./?%&=]+)', re.IGNORECASE),
        re.compile(r'([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?)', re.IGNORECASE),
        re.compile(r'(javascript:[\w./?%&=;(),\'"`-]+)', re.IGNORECASE),
        re.compile(r'(data:[^;]+;base64,[^\s<>"]+)', re.IGNORECASE),
    ]
    
    logger.info(f"开始提取URL，文本长度: {len(text)}")
    
    for i, pattern in enumerate(url_patterns):
        matches = pattern.finditer(text)
        match_count = 0
        
        for match in matches:
            match_count += 1
            url = match.group(1)
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            
            # 清理URL
            url = url.strip('"\'')
            
            # 跳过空URL
            if not url or len(url) < 3:
                continue
            
            # 跳过纯数字或不包含有效字符的URL
            if re.match(r'^\d+$', url):
                continue
            
            # 基本过滤：非http且非根相对路径、非伪协议时需校验TLD
            if not url.lower().startswith(('http://','https://','javascript:','data:')) and not url.startswith('/'):
                domain_part = url.split('/', 1)[0]
                tld = domain_part.rsplit('.', 1)[-1].lower() if '.' in domain_part else ''
                allowed_tlds = {
                    'com','org','net','cn','cc','io','me','xyz','tk','ga','gq','ml','cf','edu','gov','mil','biz','info'
                }
                if tld not in allowed_tlds:
                    continue
            # 去重
            if url not in urls_set:
                urls_set.add(url)
                results.append({
                    'url': url,
                    'context': context,
                    'position': (match.start(), match.end()),
                    'context_type': context_type or 'unknown'
                })
        
        logger.debug(f"模式 {i} 匹配到 {match_count} 个URL")
    
    logger.debug(f"共提取到 {len(results)} 个唯一URL")
    return results
EXTRA_PATTERNS = [
    # 扩展的HTTP/HTTPS URL
    re.compile(r'https?://[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 没有协议的域名
    re.compile(r'\b[\w\-\.]+(?:\.[\w\-]+)+\b(?::\d{1,5})?/[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]*', re.IGNORECASE),
    # JavaScript伪协议
    re.compile(r'javascript:[^\s"\'>]+', re.IGNORECASE),
    # data URI
    re.compile(r'data:[^;]+;base64,[^\s"\'>]+', re.IGNORECASE),
    # 相对路径
    re.compile(r'\/[^\s"\'>]+', re.IGNORECASE),
]
# 模式去重：基于正则字符串与flags，避免重复匹配与性能开销
_unique_patterns = []
_seen = set()
for _pat in URL_PATTERNS:
    _key = (_pat.pattern, _pat.flags)
    if _key not in _seen:
        _seen.add(_key)
        _unique_patterns.append(_pat)
URL_PATTERNS = _unique_patterns
