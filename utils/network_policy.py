"""Address checks with an explicit, narrowly scoped local Fake-IP proxy opt-in."""
import ipaddress
from urllib.parse import urlparse

FAKE_IP_NETWORK = ipaddress.ip_network('198.18.0.0/15')


class AddressBlocked(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def trusted_local_proxy(proxy):
    """Require a literal loopback proxy and a protocol that resolves targets remotely."""
    try:
        parsed = urlparse(proxy or '')
        address = ipaddress.ip_address(parsed.hostname or '')
        loopback = address.is_loopback or bool(address.version == 6 and address.ipv4_mapped
                                               and address.ipv4_mapped.is_loopback)
        return bool(loopback and parsed.scheme in ('http', 'https', 'socks5h')
                    and parsed.port and 1 <= parsed.port <= 65535
                    and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
    except (ValueError, TypeError):
        return False


def validate_fake_ip_proxy(proxy):
    if not trusted_local_proxy(proxy):
        raise ValueError('Fake-IP 兼容需要显式配置受信任的本地代理，例如 '
                         'http://127.0.0.1:7897（支持 http、https、socks5h；不能使用远程代理或 socks5）')


def check_target_address(url, resolver, allow_internal=False, allow_proxy_fake_ip=False, proxy=None):
    """Return whether this hop must use proxy DNS; never exempt a literal target IP."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise AddressBlocked('invalid_url', '地址或重定向协议无效，仅支持 HTTP/HTTPS')
    host = parsed.hostname.rstrip('.').lower()
    if allow_internal:
        return False
    if host in ('localhost', 'localhost.localdomain') or host.endswith(('.local', '.internal', '.lan', '.intranet')):
        raise AddressBlocked('private_address', f'地址检查拒绝本地/内网主机：{host}')
    literal = True
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        literal = False
        try:
            addresses = [ipaddress.ip_address(raw) for raw in resolver(host)]
        except (ValueError, OSError):
            addresses = []
    if not addresses:
        raise AddressBlocked('dns_resolution_failed', f'DNS 解析失败，未发送请求：{host}')
    def public(address):
        return address.is_global and not address.is_multicast
    def fake(address):
        return address.version == 4 and address in FAKE_IP_NETWORK
    # Fake-IP 只作为域名的解析结果处理。混有真实内网、回环或链路本地地址时仍拒绝。
    if not literal and any(fake(address) for address in addresses) and all(
            public(address) or fake(address) for address in addresses):
        if allow_proxy_fake_ip is True and trusted_local_proxy(proxy):
            return True
        ips = ', '.join(sorted({str(address) for address in addresses}))
        raise AddressBlocked('fake_ip_proxy_required', f'DNS 返回疑似代理 Fake-IP（{ips}）：{host}；'
                             '请在引擎配置中填写受信任的本地代理并启用 Fake-IP 兼容，或关闭代理的 Fake-IP 模式')
    blocked = [str(address) for address in addresses if not public(address)]
    if blocked:
        raise AddressBlocked('private_address', f'地址检查拒绝非公网/内网地址：{host} → {", ".join(blocked)}')
    return False
