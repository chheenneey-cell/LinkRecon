# -*- coding: utf-8 -*-
"""统一请求身份；固定身份方便复现，不随机轮换 UA 或伪造 Referer。"""

import requests


# 可通过 Config.browser_user_agent / CLI 覆盖；不是对实际浏览器版本的探测。
BROWSER_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)
# 百度官方 PC UA 格式：https://ziyuan.baidu.com/college/articleinfo/?id=551
# 仅模拟请求头，不具有百度爬虫的 IP 身份或完整浏览器行为。
BAIDU_USER_AGENT = 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'
UA_MODES = ('dual', 'browser', 'baidu')
PROFILE_LABELS = {'browser': '普通浏览器 UA', 'baidu': '百度爬虫 UA'}


def request_profiles(mode='dual'):
    if mode not in UA_MODES:
        raise ValueError('无效 UA 模式：' + str(mode))
    return ('browser', 'baidu') if mode == 'dual' else (mode,)


def build_request_headers(profile='browser', browser_user_agent=None):
    if profile not in PROFILE_LABELS:
        raise ValueError('无效请求身份：' + str(profile))
    user_agent = BAIDU_USER_AGENT if profile == 'baidu' else (browser_user_agent or BROWSER_USER_AGENT)
    if '\r' in user_agent or '\n' in user_agent:
        raise ValueError('User-Agent 不允许包含换行')
    return {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.5',
        # 由 requests 根据已安装解码器声明，避免无 Brotli 支持时仍声明 br。
        'Accept-Encoding': requests.utils.default_headers()['Accept-Encoding'],
        'Cache-Control': 'no-cache',
    }
