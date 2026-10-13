# -*- coding: utf-8 -*-

"""
扫描调度公共层。

背景：LinkRecon.py / app.py / web.py / gui.py 四个入口层各自手写了一遍
「目标类型识别 + Config 组装 + 扫描调度 + 结果聚合」，内网 IP 判定正则在
项目里出现了 5 份、Config 组装 4 份、批量聚合 3 份。
后果是每加一个配置项都要改 4 处，漏一处就是一个静默失效的参数
（--timeout 只在两处补过、CLI 批量聚合漏了 link_inventory 等都是这么来的）。

本模块把这几件事收敛到一处，入口层只负责「收集参数 -> 调用 -> 渲染」。
"""

import os
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger('LinkRecon.runner')

# 扫描结果里所有「列表型」字段，聚合时逐个 extend。
# 与 Scanner.results 的结构保持同源，避免像原来那样漏掉 link_inventory。
LIST_KEYS = (
    'suspicious_links',
    'link_inventory',
    'hidden_elements',
    'keyword_matches',
    'js_issues',
    'css_issues',
    'ua_comparisons',
)

# 「计数型」字段，聚合时相加
COUNTER_KEYS = (
    'total_files',
    'scanned_files',
    'scanned_urls',
    'total_issues',
)


def is_internal_host(host: str) -> bool:
    """
    判断主机名/IP 是否属于内网。

    用 ipaddress 模块而不是手写正则：原来的 5 份正则副本都只覆盖
    127.0.0.1 / localhost / 10.x / 172.16-31.x / 192.168.x，
    漏掉了 IPv6 回环 [::1]、链路本地 169.254.x（云元数据地址）、
    以及 0.0.0.0 等写法。
    """
    if not host:
        return False
    host = host.strip().lower()
    # 去掉端口；IPv6 字面量形如 [::1]:8080
    if host.startswith('['):
        end = host.find(']')
        if end != -1:
            host = host[1:end]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]

    if host in ('localhost', 'localhost.localdomain', ''):
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # 不是字面量 IP，按域名处理：只有明确的本地后缀才算内网
        return host.endswith(('.local', '.internal', '.lan', '.intranet'))

    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_unspecified):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        m = ip.ipv4_mapped
        return m.is_private or m.is_loopback or m.is_link_local
    return False


def detect_target_type(target: Optional[str]) -> str:
    """
    识别扫描目标类型。

    Returns:
        'internal_url' | 'external_url' | 'local_file' | 'local_directory' | 'unknown'
    """
    if not target or not str(target).strip():
        return 'unknown'
    target = str(target).strip()

    if target.startswith(('http://', 'https://')):
        try:
            host = urlparse(target).hostname or ''
        except ValueError:
            return 'unknown'
        return 'internal_url' if is_internal_host(host) else 'external_url'

    try:
        if os.path.isfile(target):
            return 'local_file'
        if os.path.isdir(target):
            return 'local_directory'
    except (OSError, ValueError):
        return 'unknown'
    return 'unknown'


def normalize_target(target: Optional[str]) -> Optional[str]:
    """把本地路径规范成绝对路径；URL 原样返回。"""
    if not target:
        return target
    target = str(target).strip().strip('"').strip("'")
    if target.startswith(('http://', 'https://')):
        return target
    try:
        if os.path.exists(target):
            return os.path.abspath(target)
    except (OSError, ValueError):
        pass
    return target


def read_target_list(path: str) -> Tuple[List[str], Optional[str]]:
    """
    读取批量目标列表文件（每行一个目标，支持 # 注释行）。

    Returns:
        (targets, error)；error 为 None 表示成功
    """
    encodings = ('utf-8-sig', 'utf-8', 'gb18030')
    last_err = None
    for enc in encodings:
        try:
            with open(path, 'r', encoding=enc) as f:
                targets = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
                return targets, None
        except UnicodeDecodeError as e:
            last_err = e
            continue
        except OSError as e:
            return [], str(e)
    return [], f"无法解码文件（尝试过 {', '.join(encodings)}）: {last_err}"


def new_aggregate() -> Dict[str, Any]:
    """构造一个空的聚合结果。字段与 Scanner.results 同源。"""
    agg: Dict[str, Any] = {k: 0 for k in COUNTER_KEYS}
    agg.update({k: [] for k in LIST_KEYS})
    agg['link_stats'] = {}
    agg['scan_time'] = 0.0
    # 扫描过程中的错误与被跳过的目标 —— Scanner 会吞掉异常并照常返回空结果，
    # 没有这两个字段，调用方无法区分「扫干净了」和「压根没扫成」。
    agg['errors'] = []
    agg['skipped_targets'] = []
    return agg


def merge_result(agg: Dict[str, Any], result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """把一次 Scanner.scan() 的结果并入聚合结果。"""
    if not result:
        return agg
    for k in COUNTER_KEYS:
        agg[k] = agg.get(k, 0) + (result.get(k) or 0)
    for k in LIST_KEYS:
        agg.setdefault(k, []).extend(result.get(k) or [])
    agg['scan_time'] = agg.get('scan_time', 0.0) + (result.get('scan_time') or 0.0)
    agg['errors'].extend(result.get('errors') or [])
    return agg


def finalize_aggregate(agg: Dict[str, Any]) -> Dict[str, Any]:
    """聚合完成后重算链接统计（批量扫描时各次结果的 link_stats 不能直接相加）。"""
    try:
        from utils.finding_policy import issue_count
        from utils.link_utils import summarize_link_inventory
        agg['total_issues'] = issue_count(agg)
        agg['link_stats'] = summarize_link_inventory(
            agg.get('link_inventory', []), agg.get('suspicious_links', []))
    except Exception as e:
        logger.error(f"汇总链接统计失败: {str(e)}")
    return agg


def run_target(config) -> Dict[str, Any]:
    """
    对 config.target 执行一次扫描。

    异常在这里捕获并记入 result['errors']，让调用方能判断成败，
    而不是像原来那样只看到一个空结果。
    """
    from core.scanner import Scanner
    try:
        return Scanner(config).scan()
    except Exception as e:
        logger.error(f"扫描目标失败 {config.target}: {str(e)}", exc_info=True)
        result = new_aggregate()
        result['errors'].append(f"{config.target}: {e}")
        return result


def run_targets(targets: List[str], config, on_progress=None) -> Dict[str, Any]:
    """
    批量扫描多个目标并返回聚合结果。

    Args:
        targets: 目标列表
        config: 已经组装好的 Config（target / target_type 会被逐个覆盖）
        on_progress: 可选回调 (index, total, target) -> None
    """
    agg = new_aggregate()
    total = len(targets)
    for i, tgt in enumerate(targets, 1):
        if on_progress:
            try:
                on_progress(i, total, tgt)
            except Exception:
                pass
        target_type = detect_target_type(tgt)
        if target_type == 'unknown':
            logger.warning(f"无法识别的扫描目标，已跳过：{tgt}")
            agg['skipped_targets'].append(tgt)
            continue
        config.target = tgt
        config.target_type = target_type
        merge_result(agg, run_target(config))
    return finalize_aggregate(agg)
