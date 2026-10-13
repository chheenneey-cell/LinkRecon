#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LinkRecon - 暗链扫描工具 (Streamlit Web 界面)
将核心扫描引擎、检测器、报告系统完整集成到 Web 平台。

########################################################################
# ⚠️ 安全警告：请务必绑定到本地回环地址启动！
#
#     streamlit run web.py --server.address 127.0.0.1
#
# 原因：
#   1) Streamlit 默认监听 0.0.0.0，即局域网/公网上任何人都能访问本页面；
#   2) 本工具的「扫描目标」「关键词文件路径」「报告预览」等入口都能读取
#      运行机器上的**任意本地文件与目录**（local_file / local_directory
#      模式），并把内容渲染回页面；
#   3) 工具还能对内网地址发起请求（internal_url），等价于一个 SSRF 跳板。
#   合起来：一旦对外暴露，就是一个无鉴权的任意文件读取 + 内网探测服务。
########################################################################
"""

import os
from utils.report_paths import new_report_path
import sys
import json
import logging
import tempfile
import csv as csv_mod
from datetime import datetime
from html import escape          # 修复存储型 XSS：所有拼进 HTML 的值统一转义
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Add local site-packages for dependencies installed in project directory
_local_sp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'site-packages')
if os.path.isdir(_local_sp):
    sys.path.insert(0, _local_sp)

import streamlit as st

from core import auth
from core.config import Config
from core.reporter import Reporter
from core.detector.keyword_detector import KeywordDetector
# 目标识别 / 内网判定 / 扫描调度 / 批量聚合统一走 core.runner。
# 原来 web.py 自己手写了一份内网 IP 正则（漏 IPv6 回环、169.254 云元数据段）
# 和一份批量聚合逻辑（漏了 link_inventory，导致批量报告的链接统计不全）。
from core.runner import (
    detect_target_type,
    normalize_target,
    new_aggregate,
    merge_result,
    finalize_aggregate,
    run_target,
)
from utils.file_utils import read_file

# ==================== 页面配置 ====================
st.set_page_config(
    page_title="LinkRecon 智能内容安全检测平台",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==================== 全局 CSS ====================
st.markdown("""
<style>
.block-container { padding: 1.2rem 2rem !important; max-width: 96% !important; }
[data-testid="stSidebar"] { background-color: #152033 !important; width: 260px !important; }
[data-testid="stSidebar"] .st-radio label { font-size: 14px; padding: 4px 0; }
[data-testid="stSidebar"] * { color: #f0f2f5 !important; }
.top-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    border: 1px solid #1e3a5f; border-radius: 10px;
    padding: 24px 28px; box-shadow: 0 4px 15px rgba(0,0,0,0.15); margin-bottom: 20px;
}
.top-card h1 { color: #e0e7ef !important; }
.top-card span { color: #94a3b8 !important; }
.func-card {
    background: #fff; border: 1px solid #e4e7ed; border-radius: 8px;
    padding: 24px 28px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); margin-bottom: 16px;
}
.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 10px; padding: 20px; color: white; text-align: center;
    box-shadow: 0 4px 12px rgba(102,126,234,0.4);
}
.stat-card-green { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); box-shadow: 0 4px 12px rgba(17,153,142,0.4); }
.stat-card-orange { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); box-shadow: 0 4px 12px rgba(245,87,108,0.4); }
.stat-card-blue { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); box-shadow: 0 4px 12px rgba(79,172,254,0.4); }
.stat-card h3 { margin: 0; font-size: 2rem; color: white; }
.stat-card p { margin: 4px 0 0 0; font-size: 0.9rem; color: rgba(255,255,255,0.85); }
.stTextArea textarea { border: 1px solid #dcdfe6 !important; border-radius: 6px !important; padding: 10px !important; font-size: 14px; }
.stTextInput input { border: 1px solid #dcdfe6 !important; border-radius: 6px !important; padding: 8px !important; }
.stButton > button { background: #165DFF !important; color: #fff !important; border: none !important; border-radius: 6px !important; height: 42px; font-size: 14px; font-weight: 500; }
.stButton > button:hover { background: #0e4fd4 !important; }
hr { border-color: #ebeef5 !important; }
.risk-badge-high { background: #fef2f2; color: #dc2626; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
.risk-badge-medium { background: #fffbeb; color: #d97706; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
.risk-badge-low { background: #eff6ff; color: #2563eb; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
.result-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.result-table th { background: #f8fafc; color: #475569; font-weight: 600; padding: 10px 12px; border-bottom: 2px solid #e2e8f0; text-align: left; }
.result-table td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.result-table tr:hover td { background: #f8fafc; }
</style>
""", unsafe_allow_html=True)

# ==================== 登录门禁 ====================
# 与 app.py 共用 core.auth 的账号库（data/users.json），账号、口令、角色三处一致。
#
# 关于会话：Streamlit 的 st.session_state 是服务端状态，按浏览器会话隔离，
# 不会把身份信息放进前端。但要注意它绑定的是 websocket 连接 ——
# 强制刷新页面可能会新建会话从而需要重新登录，这是 Streamlit 的固有行为，
# 不是这里的实现缺陷。若需要"刷新不掉线"，请改用 app.py（Flask + Cookie）。


def _client_ip_st() -> str:
    """尽力取来源 IP，用于登录失败锁定的计数维度。取不到就退化为全局计数。"""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        from streamlit.runtime import get_instance
        ctx = get_script_run_ctx()
        if ctx is not None:
            info = get_instance()._session_mgr.get_session_info(ctx.session_id)
            if info is not None:
                return info.client.request.remote_ip or "-"
    except Exception:
        pass
    return "-"


def _render_login() -> None:
    """渲染登录表单。未通过时调用方必须 st.stop()，不能让后面的页面渲染出来。"""
    st.markdown(
        "<div class='top-card'><div style='font-size:22px;font-weight:700;'>"
        "🔬 LinkRecon · 智能内容安全检测平台</div>"
        "<span style='font-size:14px;'>请登录后使用</span></div>",
        unsafe_allow_html=True,
    )
    col_left, col_mid, col_right = st.columns([1, 1.2, 1])
    with col_mid:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("用户名", key="login_username", max_chars=64)
            password = st.text_input("口令", type="password", key="login_password", max_chars=256)
            submitted = st.form_submit_button("登 录", use_container_width=True)
        if submitted:
            try:
                user = auth.authenticate(username, password, ip=_client_ip_st())
            except auth.AuthError as exc:
                st.error(str(exc))
            else:
                st.session_state["auth_user"] = user
                # 登录成功后立刻重跑脚本，让门禁放行并渲染真正的页面
                st.rerun()
        st.caption(
            "忘记口令？在服务器上执行 `python -m core.auth passwd <用户名>` 重置；"
            "首次使用执行 `python -m core.auth init` 创建管理员。"
        )


def require_login() -> dict:
    """
    门禁：未登录只渲染登录表单并终止脚本，已登录返回用户信息。

    每次脚本重跑都重新读一次磁盘上的账号状态 —— 否则管理员把某个账号停用
    或降级后，对方在会话过期前还能继续操作。
    """
    user = st.session_state.get("auth_user")
    if user:
        stored = auth.load_users().get(user.get("username"))
        if not stored or stored.get("disabled"):
            st.session_state.pop("auth_user", None)
            st.error("账号已停用或不存在，请重新登录")
            user = None
        else:
            # 角色以磁盘为准，管理员改角色后立即生效
            user["role"] = stored.get("role", auth.ROLE_VIEWER)
            st.session_state["auth_user"] = user

    if not user:
        # 一个账号都没有时给出明确的初始化指引，而不是让人对着登录框猜
        if not auth.load_users():
            st.error(
                "尚未创建任何账号。请在服务器上执行 "
                "`python -m core.auth init` 生成初始管理员后再登录。"
            )
        _render_login()
        st.stop()
    return user


def _require_admin(action: str = "该操作") -> bool:
    """
    写操作前的角色检查。返回 False 时调用方应当拒绝执行。

    扫描器能读本机任意文件、能对内网发请求，只读账号必须挡在这些能力之外；
    界面上隐藏按钮只是减少误触，真正的拦截必须在执行前这一步。
    """
    if CURRENT_USER.get("role") == auth.ROLE_ADMIN:
        return True
    st.error(f"{action}需要管理员权限，当前账号为只读（viewer）。")
    return False


CURRENT_USER = require_login()
IS_ADMIN = CURRENT_USER.get("role") == auth.ROLE_ADMIN


# ==================== 辅助函数 ====================
# 报告目录必须锚定到脚本所在目录，而不是 os.getcwd()。
# 原来用 os.getcwd()：在别的目录下 `streamlit run /path/to/web.py` 启动时，
# 报告会写到当前 shell 所在目录，而「报告查看与管理」页面读的又是同一个变量，
# 换个目录重启就"历史报告全没了"。app.py 用的是 BASE_DIR，这里保持一致。
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ---------------------- HTML 转义 / 安全链接 ----------------------
# 背景（P1-22 存储型 XSS）：本页面大量使用 unsafe_allow_html=True 渲染扫描结果，
# 而扫描结果里的 url / source / keyword / category / context 全部来自**被扫描的
# 不可信站点**。原实现把它们裸拼进 f-string，其中 href="{url}" 连引号都没转义，
# 攻击者只需在自己网站里埋一个
#     <a href='" onmouseover=alert(document.cookie) x="'>
# 分析人员打开扫描结果页就会被反打（且报告是持久化的，属于存储型 XSS）。
# core/reporter.py 早就有正确实现（_escape_html 覆盖 & < > " '），web.py 漏用了。

_SAFE_LINK_SCHEMES = {"http", "https"}


def _esc(value) -> str:
    """任何要进入 HTML 的值都先过这里。quote=True 才会转义 " 和 '，属性上下文必需。"""
    if value is None:
        return ""
    return escape(str(value), quote=True)


_MD_SPECIALS = "\\`*_{}[]()#+-.!|<>"


def _md(value) -> str:
    """
    用于 st.markdown() 的转义。st.markdown(unsafe_allow_html=False) 会挡住裸 HTML，
    但 Markdown 自身的链接语法（如 [点我](javascript:...)）和强调符号仍能被注入，
    扫描结果里的 type/description/source 同样来自不可信页面，先转义再拼。
    """
    if value is None:
        return ""
    out = str(value)
    for ch in _MD_SPECIALS:
        out = out.replace(ch, "\\" + ch)
    return out


def _safe_href(url) -> str:
    """
    返回可安全放进 href 属性的值；协议不在白名单内时返回空串。
    调用方拿到空串就应降级为纯文本展示，避免 javascript: / data: / vbscript:
    这类伪协议在分析人员点击时执行。
    """
    try:
        scheme = (urlparse(str(url)).scheme or "").lower()
    except Exception:
        # urlparse 对畸形 URL（如非法 IPv6 字面量）会抛 ValueError，一律视为不安全
        return ""
    return _esc(url) if scheme in _SAFE_LINK_SCHEMES else ""


def _detect_target_type(target):
    """保留原函数名做薄封装，实际判定收敛到 core.runner（含 IPv6/链路本地地址）。"""
    return detect_target_type(target)


def _build_config(target, mode="deep", depth=3, threads=8, timeout=30,
                   report_type="html", keyword_file=None, headless=False,
                   proxy=None, exclude=None):
    config = Config()
    # 本地路径统一转成绝对路径，避免相对路径随 cwd 漂移
    target = normalize_target(target)
    config.target = target
    config.target_type = detect_target_type(target)
    # Config.mode 现在是 property：赋值会自动同步 scan_mode 并刷新各扫描开关，
    # 不需要再写 scan_mode= / mode= / _set_mode_config() 三连（重复且易漏）。
    config.mode = mode
    # depth 同理是 crawl_depth 的 property 别名，单次赋值即可。
    config.depth = depth
    config.threads = threads
    config.timeout = timeout
    config.report_type = report_type
    config.keywords_file = keyword_file
    config.use_headless_browser = headless
    config.proxy = proxy or None
    config.exclude = exclude or []
    os.makedirs(REPORTS_DIR, exist_ok=True)
    config.report_file = new_report_path(REPORTS_DIR, report_type)
    if headless:
        config.js_wait_time = 3
        config.headless_timeout = 60
        config.headless_auto_download = True
    return config

def _run_scan(config):
    # 走 core.runner.run_target：它会捕获 Scanner 抛出的异常并记入 result['errors']，
    # 调用方因此能区分「扫干净了」和「压根没扫成」，而不是只看到一个空结果。
    return run_target(config)

def _generate_report(config, result, duration):
    reporter = Reporter(config)
    return reporter.generate_report(result, duration)

def _read_file_safe(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def _render_stats(result):
    # 这几个值理论上是整数，但它们来自 Scanner 结果字典（可被扫描目标间接影响），
    # 仍然统一 _esc()：unsafe_allow_html=True 的上下文里不做例外，少一处判断少一个洞。
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="stat-card"><h3>{_esc(result.get("scanned_files", 0))}</h3><p>扫描文件数</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-card stat-card-green"><h3>{_esc(result.get("scanned_urls", 0))}</h3><p>扫描URL数</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="stat-card stat-card-orange"><h3>{len(result.get("suspicious_links") or [])}</h3><p>可疑链接</p></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="stat-card stat-card-blue"><h3>{len(result.get("keyword_matches") or [])}</h3><p>关键词匹配</p></div>', unsafe_allow_html=True)


def _render_errors(result):
    """Scanner 现在会把过程中的异常收进 results['errors']。
    不提示的话，一次「全部失败」的扫描和一次「干干净净」的扫描在 UI 上长得一模一样。"""
    errors = result.get("errors") or []
    skipped = result.get("skipped_targets") or []
    if errors:
        with st.expander(f"⚠️ 扫描过程中出现 {len(errors)} 个错误（结果可能不完整）", expanded=False):
            for e in errors[:50]:
                st.text(str(e))          # st.text 不解析 HTML/Markdown，天然安全
            if len(errors) > 50:
                st.caption(f"仅展示前 50 条，共 {len(errors)} 条。")
    if skipped:
        with st.expander(f"⏭️ 已跳过 {len(skipped)} 个无法识别的目标", expanded=False):
            for s in skipped[:50]:
                st.text(str(s))

def _risk_badge(level):
    try:
        lv = int(level)
    except:
        lv = 0
    if lv >= 6:
        return f'<span class="risk-badge-high">高风险 ({lv})</span>'
    elif lv >= 3:
        return f'<span class="risk-badge-medium">中风险 ({lv})</span>'
    else:
        return f'<span class="risk-badge-low">低风险 ({lv})</span>'

def _render_suspicious_links(links, max_show=50):
    if not links:
        st.info("未发现可疑链接")
        return
    sorted_links = sorted(links, key=lambda x: x.get("risk_level", 0), reverse=True)
    show = sorted_links[:max_show]
    rows = ""
    for i, lk in enumerate(show, 1):
        # 以下所有字段都来自被扫描的不可信页面，逐个转义后才能进 HTML。
        url = str(lk.get("link") or lk.get("url") or "N/A")
        source = str(lk.get("source") or lk.get("file_path") or "N/A")
        # 原实现只把 context 的 < > 替换掉，漏了 " 和 &（& 漏转义会破坏实体、
        # 允许构造 &lt;script&gt; 之外的绕过），改用统一的 _esc()。
        ctx = _esc((lk.get("context") or "")[:120])
        badge = _risk_badge(lk.get("risk_level", 0))
        url_display = _esc(url[:80] + ("..." if len(url) > 80 else ""))
        href = _safe_href(url)
        if href:
            link_cell = f'<a href="{href}" target="_blank" rel="noopener noreferrer">{url_display}</a>'
        else:
            # javascript:/data:/vbscript: 等非白名单协议降级为纯文本，避免点击即中招
            link_cell = f'<code>{url_display}</code>'
        rows += f'<tr><td>{i}</td><td style="word-break:break-all">{link_cell}</td><td>{_esc(source[:60])}</td><td>{badge}</td><td><code>{ctx}</code></td></tr>'
    st.markdown(f'<table class="result-table"><thead><tr><th>#</th><th>链接</th><th>来源</th><th>风险</th><th>上下文</th></tr></thead><tbody>{rows}</tbody></table>', unsafe_allow_html=True)
    if len(sorted_links) > max_show:
        st.caption(f"仅展示前 {max_show} 条，共 {len(sorted_links)} 条。完整数据请查看报告文件。")

def _render_keyword_matches(matches, max_show=50):
    if not matches:
        st.info("未发现关键词匹配")
        return
    sorted_m = sorted(matches, key=lambda x: x.get("weight", 0), reverse=True)
    show = sorted_m[:max_show]
    rows = ""
    for i, m in enumerate(show, 1):
        # keyword / category 可能来自用户上传的关键词文件，source / context 来自被扫内容，
        # 全部不可信 —— 原实现除 context 外零转义。
        kw = _esc(m.get("keyword", "N/A"))
        cat = _esc(m.get("category", "N/A"))
        wt = _esc(m.get("weight", 0))
        src = _esc(str(m.get("source") or "N/A")[:50])
        ctx = _esc((m.get("context") or "")[:100])
        rows += f'<tr><td>{i}</td><td><strong>{kw}</strong></td><td>{cat}</td><td>{wt}</td><td>{src}</td><td><code>{ctx}</code></td></tr>'
    st.markdown(f'<table class="result-table"><thead><tr><th>#</th><th>关键词</th><th>类别</th><th>权重</th><th>来源</th><th>上下文</th></tr></thead><tbody>{rows}</tbody></table>', unsafe_allow_html=True)
    if len(sorted_m) > max_show:
        st.caption(f"仅展示前 {max_show} 条，共 {len(sorted_m)} 条。")

# ==================== 顶部标题 ====================
st.markdown("""
<div class="top-card">
    <h1 style="margin:0 0 6px 0;font-size:30px;">🔬 LinkRecon 智能内容安全检测平台</h1>
    <span style="font-size:15px;">关键词扫描 · 网页暗链检测 · 本地文件/目录分析 · 无头浏览器增强 · 多格式报告导出</span>
</div>
""", unsafe_allow_html=True)

# 监听地址安全提示：Streamlit 默认 --server.address 0.0.0.0，而本工具能读取本机
# 任意文件、并可对内网地址发起请求。只提示一次，放在页面顶部保证一定会被看到。
st.warning(
    "⚠️ **安全提示**：Streamlit 默认监听 `0.0.0.0`（对局域网/公网开放）。"
    "本工具可读取运行机器上的任意本地文件、目录，并能向内网地址发起请求，"
    "对外暴露等同于无鉴权的任意文件读取 + 内网探测服务。"
    "请务必使用 `streamlit run web.py --server.address 127.0.0.1` 启动，"
    "并避免在共享主机上运行。"
)

# ==================== 侧边栏 ====================
with st.sidebar:
    # 当前登录用户 + 退出入口
    _role_label = "管理员" if IS_ADMIN else "只读"
    st.markdown(
        f"**👤 {escape(CURRENT_USER['username'])}** &nbsp;"
        f"<span style='font-size:12px;opacity:.75'>({_role_label})</span>",
        unsafe_allow_html=True,
    )
    if st.button("退出登录", key="logout_btn", use_container_width=True):
        st.session_state.pop("auth_user", None)
        st.rerun()
    if not IS_ADMIN:
        st.caption("只读账号：可查看报告与历史，不能发起扫描或修改配置。")
    st.divider()
    st.markdown("### 📋 功能导航菜单")
    func = st.radio("", ["🔍 暗链扫描检测", "📝 关键词匹配检测", "📦 批量目标分析", "📊 报告查看与管理"])
    st.divider()
    st.markdown("### ⚙️ 平台说明")
    st.info("· 支持 URL / 本地文件 / 本地目录扫描\n· 三种扫描模式：fast / standard / deep\n· 检测报告自动归档到 reports/\n· 支持自定义关键词库")

# ========================================================================
# 功能1: 暗链扫描检测
# ========================================================================
if func == "🔍 暗链扫描检测":
    st.markdown('<div class="func-card">', unsafe_allow_html=True)
    st.subheader("🔍 站点暗链风险扫描")
    st.caption("集成 HTML/JS/CSS/关键词/特殊隐藏技术 等多层检测引擎，支持 URL、本地文件、本地目录")
    st.divider()

    col_input, col_config = st.columns([3, 2])
    with col_input:
        scan_target = st.text_input("扫描目标", placeholder="https://example.com  或  /path/to/file.html", help="支持 HTTP/HTTPS URL、本地文件路径、本地目录路径")
    with col_config:
        scan_mode = st.selectbox("扫描模式", ["deep", "standard", "fast"], index=0)
        scan_depth = st.number_input("递归深度", min_value=0, max_value=20, value=1)
        report_format = st.selectbox("报告格式", ["html", "txt", "json", "csv"], index=0)

    with st.expander("🔧 高级配置", expanded=False):
        adv_col1, adv_col2, adv_col3 = st.columns(3)
        with adv_col1:
            scan_threads = st.slider("并发线程", 1, 32, 8)
            scan_timeout = st.slider("请求超时(秒)", 5, 120, 30)
        with adv_col2:
            use_headless = st.checkbox("启用无头浏览器", value=False)
            scan_proxy = st.text_input("代理服务器", placeholder="http://127.0.0.1:8080")
        with adv_col3:
            keyword_file_path = st.text_input("关键词文件路径", placeholder="留空使用默认 keywords_example.txt")
            exclude_patterns = st.text_area("排除规则", placeholder="*.jpg\n*.png\nnode_modules/", height=68)

    st.markdown("<br>", unsafe_allow_html=True)

    # P2-8：Streamlit 每次交互都会从头重跑整个脚本，st.button() 只在「刚被点击的那一次
    # 运行」返回 True。原来把整个结果渲染塞在 if st.button(...) 里面，用户一点
    # 「📥 下载扫描报告」触发 rerun，按钮返回 False，整块扫描结果瞬间消失、必须重扫。
    # 修法：按钮分支只负责「跑扫描 + 写入 st.session_state」，渲染逻辑挪到分支外，
    # 依据 session_state 里有没有结果来决定渲染。
    if st.button("🚀 开始扫描", use_container_width=True, type="primary",
                 disabled=not IS_ADMIN) and _require_admin("发起扫描"):
        if not scan_target.strip():
            st.error("请输入扫描目标！")
        else:
            target_type = _detect_target_type(scan_target.strip())
            if target_type == "unknown":
                st.error(f"无法识别目标类型: {scan_target}")
            else:
                kw_file = keyword_file_path.strip() if keyword_file_path.strip() else None
                excl = [e.strip() for e in exclude_patterns.split("\n") if e.strip()] if exclude_patterns else []
                config = _build_config(target=scan_target.strip(), mode=scan_mode, depth=scan_depth, threads=scan_threads, timeout=scan_timeout, report_type=report_format, keyword_file=kw_file, headless=use_headless, proxy=scan_proxy.strip() or None, exclude=excl)

                with st.spinner(f"正在扫描 {scan_target}（模式: {scan_mode}，类型: {target_type}）..."):
                    try:
                        start_time = datetime.now()
                        result = _run_scan(config)
                        end_time = datetime.now()
                        duration = str(end_time - start_time)
                        report_path = _generate_report(config, result, duration)

                        st.session_state["last_result"] = {
                            "result": result,
                            "report_path": report_path,
                            "duration": duration,
                            "target": scan_target.strip(),
                            "target_type": target_type,
                            "mode": scan_mode,
                            "finished_at": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    except Exception as e:
                        # 失败同样落到 session_state，否则错误信息也会被下一次 rerun 抹掉
                        st.session_state["last_result"] = {"error": str(e)}
                        st.exception(e)

    # ---- 渲染区：只看 session_state，不依赖按钮本次是否被点击 ----
    _last = st.session_state.get("last_result")
    if _last:
        if _last.get("error"):
            st.error(f"扫描过程中发生错误: {_last['error']}")
        else:
            result = _last["result"]
            report_path = _last.get("report_path")
            st.success(
                f"✅ 扫描完成（{_last.get('finished_at', '')}）！目标: {_last.get('target', '')}，"
                f"耗时 {_last.get('duration', '')}，报告已保存至: {report_path}"
            )

            st.markdown("<br>", unsafe_allow_html=True)
            _render_stats(result)
            _render_errors(result)
            st.markdown("<br>", unsafe_allow_html=True)

            if result.get("suspicious_links"):
                with st.expander(f"🔗 可疑链接详情（{len(result['suspicious_links'])} 条）", expanded=True):
                    _render_suspicious_links(result["suspicious_links"])

            if result.get("keyword_matches"):
                with st.expander(f"🏷️ 关键词匹配详情（{len(result['keyword_matches'])} 条）", expanded=True):
                    _render_keyword_matches(result["keyword_matches"])

            # 下面三块用 st.markdown 渲染不可信字段，Streamlit 虽然会拦掉裸 HTML，
            # 但 Markdown 链接语法仍可被注入 —— 统一走 _md() 转义。
            if result.get("hidden_elements"):
                with st.expander(f"👻 隐藏技术检测（{len(result['hidden_elements'])} 条）"):
                    for he in result["hidden_elements"][:30]:
                        st.markdown(f"- **{_md(he.get('type', 'N/A'))}** | 来源: {_md(he.get('source', 'N/A'))} | 风险: {_md(he.get('risk_level', 'N/A'))}")

            if result.get("js_issues"):
                with st.expander(f"⚡ JavaScript 问题（{len(result['js_issues'])} 条）"):
                    for js in result["js_issues"][:30]:
                        st.markdown(f"- **{_md(js.get('type', 'N/A'))}** | {_md(js.get('function_name', js.get('description', 'N/A')))} | 风险: {_md(js.get('risk_level', 'N/A'))}")

            if result.get("css_issues"):
                with st.expander(f"🎨 CSS 问题（{len(result['css_issues'])} 条）"):
                    for css in result["css_issues"][:30]:
                        st.markdown(f"- **{_md(css.get('type', 'N/A'))}** | {_md(css.get('description', 'N/A'))} | 风险: {_md(css.get('risk_level', 'N/A'))}")

            if report_path and os.path.exists(report_path):
                with open(report_path, "rb") as f:
                    report_data = f.read()
                # 点击下载会触发 rerun —— 因为结果已存在 session_state，这里不再清空页面
                st.download_button("📥 下载扫描报告", data=report_data,
                                   file_name=os.path.basename(report_path), key="dl_last_scan")

            if st.button("🧹 清除本次扫描结果", key="clear_last_scan"):
                st.session_state.pop("last_result", None)

    st.markdown("</div>", unsafe_allow_html=True)

# ========================================================================
# 功能2: 关键词匹配检测
# ========================================================================
elif func == "📝 关键词匹配检测":
    st.markdown('<div class="func-card">', unsafe_allow_html=True)
    st.subheader("📝 关键词内容匹配检测")
    st.caption("使用内置关键词库或自定义关键词，对文本内容进行风险匹配分析")
    st.divider()

    input_mode = st.radio("关键词数据源", ["📋 使用内置关键词库", "✏️ 手动录入", "📁 上传关键词文件"], horizontal=True)
    keywords = []

    if input_mode == "📋 使用内置关键词库":
        # 同 REPORTS_DIR：内置关键词库随脚本走，不能依赖启动时的工作目录
        default_kw_path = os.path.join(BASE_DIR, "keywords_example.txt")
        if os.path.exists(default_kw_path):
            tmp_config = Config()
            kd = KeywordDetector(tmp_config)
            if kd.load_keywords(default_kw_path):
                st.success(f"✅ 已加载内置关键词库: {len(kd.keywords)} 个关键词")
                stats = kd.get_keyword_statistics()
                cat_items = list(stats["by_category"].items())
                if cat_items:
                    cols = st.columns(min(len(cat_items), 6))
                    for idx, (cat, cnt) in enumerate(cat_items):
                        cols[idx % len(cols)].metric(cat, cnt)
            else:
                st.warning("内置关键词库加载失败")
        else:
            st.warning(f"未找到内置关键词库: {default_kw_path}")

    elif input_mode == "✏️ 手动录入":
        key_input = st.text_area("关键词列表（每行一个关键词）", height=120, placeholder="赌博\n色情\nmalware\nphishing")
        if key_input:
            keywords = [k.strip() for k in key_input.split("\n") if k.strip()]
    else:
        up_key = st.file_uploader("上传关键词文件 (CSV 格式)", type=["txt", "csv"])
        if up_key:
            content = up_key.read().decode("utf-8", errors="replace")
            keywords = [k.strip() for k in content.splitlines() if k.strip() and not k.strip().startswith("#")]
            st.success(f"✅ 已成功加载关键词: {len(keywords)} 条")

    st.markdown("<br>", unsafe_allow_html=True)
    detect_mode = st.radio("检测目标", ["📝 粘贴文本内容", "📄 上传文件检测", "🌐 URL内容检测"], horizontal=True)
    target_content = ""
    target_source = "手动输入"

    if detect_mode == "📝 粘贴文本内容":
        target_content = st.text_area("待检测原文内容", height=220, placeholder="粘贴需要扫描检测的正文文本内容")
    elif detect_mode == "📄 上传文件检测":
        up_file = st.file_uploader("上传待检测文件", type=["html", "htm", "css", "js", "txt", "php", "asp", "jsp"])
        if up_file:
            target_content = up_file.read().decode("utf-8", errors="replace")
            target_source = up_file.name
            st.info(f"已加载文件: {up_file.name} ({len(target_content)} 字符)")
    else:
        url_input = st.text_input("目标URL", placeholder="https://example.com/page")
        if (url_input and st.button("📥 抓取页面内容", disabled=not IS_ADMIN)
                and _require_admin("抓取页面内容")):
            with st.spinner("正在抓取页面内容..."):
                try:
                    from utils.network_utils import fetch_url_content
                    result_tuple = fetch_url_content(url_input.strip())
                    if result_tuple:
                        target_content, _ = result_tuple
                        target_source = url_input.strip()
                        st.success(f"✅ 成功抓取页面内容 ({len(target_content)} 字符)")
                    else:
                        st.error("无法获取页面内容")
                except Exception as e:
                    st.error(f"抓取失败: {str(e)}")

    st.markdown("<br>", unsafe_allow_html=True)
    run_btn = (st.button("🚀 执行关键词检测", use_container_width=True, type="primary",
                         disabled=not IS_ADMIN)
               and _require_admin("执行关键词检测"))

    if run_btn:
        if not target_content:
            st.warning("请输入或上传待检测内容")
        else:
            tmp_config = Config()
            kd = KeywordDetector(tmp_config)
            kw_path = os.path.join(BASE_DIR, "keywords_example.txt")

            if input_mode == "📋 使用内置关键词库":
                kd.load_keywords(kw_path)
            elif keywords:
                tmp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8", newline="")
                writer = csv_mod.writer(tmp_file)
                for kw in keywords:
                    writer.writerow([kw, "other", 5])
                tmp_file.close()
                kd.load_keywords(tmp_file.name)
                os.unlink(tmp_file.name)
            else:
                st.warning("请先配置关键词")
                st.stop()

            with st.spinner("正在执行关键词匹配..."):
                matches = kd.detect(target_content, target_source)

            st.success(f"✅ 检测完成！命中关键词: {len(matches)} 个")

            if matches:
                st.markdown("<br>", unsafe_allow_html=True)
                _render_keyword_matches(matches)
                cat_counts = {}
                for m in matches:
                    cat = m.get("category", "其他")
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                st.markdown("#### 📊 类别统计")
                for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
                    # 类别名来自关键词文件（可由用户上传），转义后再进 Markdown
                    st.markdown(f"- **{_md(cat)}**: {cnt} 个匹配")
            else:
                st.info("✅ 未发现关键词匹配")

    st.markdown("</div>", unsafe_allow_html=True)

# ========================================================================
# 功能3: 批量目标分析
# ========================================================================
elif func == "📦 批量目标分析":
    st.markdown('<div class="func-card">', unsafe_allow_html=True)
    st.subheader("📦 批量目标清单分析")
    st.caption("上传目标列表文件或手动输入多个目标，一键批量扫描")
    st.divider()

    batch_input_mode = st.radio("目标输入方式", ["📁 上传目标列表文件", "✏️ 手动输入"], horizontal=True)
    targets = []

    if batch_input_mode == "📁 上传目标列表文件":
        up_target = st.file_uploader("上传批量目标清单文件(.txt)", type=["txt"])
        if up_target:
            targets = [i.strip() for i in up_target.read().decode("utf-8", errors="replace").splitlines() if i.strip()]
            st.success(f"✅ 载入待分析目标总数: {len(targets)} 个")
            with st.expander("查看目标列表"):
                for t in targets:
                    st.code(t)
    else:
        manual_input = st.text_area("目标列表（每行一个目标）", height=180, placeholder="https://example.com\nhttps://test.com\n/path/to/file.html")
        if manual_input:
            targets = [t.strip() for t in manual_input.split("\n") if t.strip()]

    if targets:
        st.markdown("<br>", unsafe_allow_html=True)
        batch_col1, batch_col2 = st.columns(2)
        with batch_col1:
            batch_mode = st.selectbox("扫描模式", ["deep", "standard", "fast"], index=0)
        with batch_col2:
            batch_report_format = st.selectbox("报告格式", ["html", "txt", "json", "csv"], index=0)

        st.markdown("<br>", unsafe_allow_html=True)

        if (st.button("🚀 开始批量分析", use_container_width=True, type="primary",
                      disabled=not IS_ADMIN)
                and _require_admin("批量分析")):
            progress_bar = st.progress(0)
            status_text = st.empty()
            all_results = []

            # P1-8：原来生成报告时用的是循环体内的 `config`。
            #   · 如果所有目标都被判成 unknown（例如在 Linux 上跑一份全是 Windows 路径的
            #     清单），或者第一次 _build_config 就抛异常，循环体内 config 从未赋值，
            #     循环结束后 `config.report_file = ...` 直接 NameError，
            #     前面已经聚合好的结果全部丢失；
            #   · 即便没崩，复用「最后一个目标」的 config 本身也是错的 —— 报告里的
            #     模式/格式/目标类型取自最后一次循环，与整批不符。
            # 修法：循环前显式构造一个只服务于报告的 batch_config，循环内一律用局部变量。
            batch_config = _build_config(
                target=f"批量目标 ({len(targets)} 项)",
                mode=batch_mode,
                report_type=batch_report_format,
            )
            batch_config.target = f"批量目标 ({len(targets)} 项)"
            batch_config.target_type = "batch"

            # 聚合结构改用 core.runner.new_aggregate()：与 Scanner.results 同源，
            # 原来手写的那份漏了 link_inventory，批量报告的链接统计因此永远不完整。
            agg = new_aggregate()
            start_time = datetime.now()

            for idx, tgt in enumerate(targets):
                progress_bar.progress((idx + 1) / len(targets))
                status_text.text(f"正在扫描 ({idx + 1}/{len(targets)}): {tgt}")
                tgt_type = detect_target_type(tgt)
                if tgt_type == "unknown":
                    st.warning(f"⚠️ 跳过无法识别的目标: {tgt}")
                    agg["skipped_targets"].append(tgt)
                    continue
                # 每个目标用自己的局部 config，不再泄漏到循环外
                tgt_config = _build_config(target=tgt, mode=batch_mode, report_type=batch_report_format)
                result = run_target(tgt_config)   # 内部已捕获异常并写入 result['errors']
                all_results.append({"target": tgt, "result": result})
                merge_result(agg, result)

            finalize_aggregate(agg)               # 重算 link_stats（各次结果不能直接相加）

            end_time = datetime.now()
            agg["scan_time"] = (end_time - start_time).total_seconds()
            duration = str(end_time - start_time)
            progress_bar.progress(1.0)
            status_text.text("✅ 批量扫描完成！")

            # 报告生成放在「确实扫到了东西」的保护下：一个目标都没扫成时生成空报告
            # 只会误导人，也没必要为此掩盖前面的跳过/错误提示。
            batch_report_path = None
            if all_results:
                try:
                    os.makedirs(REPORTS_DIR, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    batch_report_path = os.path.join(REPORTS_DIR, f"batch_report_{ts}.{batch_report_format}")
                    batch_config.report_file = batch_report_path
                    Reporter(batch_config).generate_report(agg, duration)
                except Exception as e:
                    batch_report_path = None
                    agg["errors"].append(f"生成批量报告失败: {e}")

            # 与单目标扫描同理：结果写进 session_state，否则点一下下载按钮就全没了
            st.session_state["batch_result"] = {
                "agg": agg,
                "all_results": all_results,
                "report_path": batch_report_path,
                "duration": duration,
                "total": len(targets),
            }

    # ---- 渲染区：只依赖 session_state，不依赖按钮本次是否被点击 ----
    _batch = st.session_state.get("batch_result")
    if _batch:
        agg = _batch["agg"]
        all_results = _batch["all_results"]
        batch_report_path = _batch.get("report_path")
        st.success(f"🎉 批量分析完成！共 {_batch['total']} 个目标（成功 {len(all_results)} 个），耗时 {_batch['duration']}")

        st.markdown("<br>", unsafe_allow_html=True)
        _render_stats(agg)
        _render_errors(agg)

        if agg.get("suspicious_links"):
            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander(f"🔗 聚合可疑链接（{len(agg['suspicious_links'])} 条）", expanded=True):
                _render_suspicious_links(agg["suspicious_links"])

        if agg.get("keyword_matches"):
            with st.expander(f"🏷️ 聚合关键词匹配（{len(agg['keyword_matches'])} 条）"):
                _render_keyword_matches(agg["keyword_matches"])

        if batch_report_path and os.path.exists(batch_report_path):
            with open(batch_report_path, "rb") as f:
                st.download_button("📥 下载批量分析报告", data=f.read(),
                                   file_name=os.path.basename(batch_report_path), key="dl_batch")
        elif all_results:
            st.info("未能生成批量报告文件，详见上方错误提示。")

        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📋 逐目标扫描结果", expanded=False):
            for item in all_results:
                r = item["result"]
                # 目标字符串同样可能来自上传的清单文件，Markdown 转义后再渲染
                st.markdown(
                    f"**{_md(item['target'])}** — 文件: {r.get('scanned_files', 0)} | "
                    f"URL: {r.get('scanned_urls', 0)} | "
                    f"可疑链接: {len(r.get('suspicious_links') or [])} | "
                    f"关键词匹配: {len(r.get('keyword_matches') or [])}"
                )

        if st.button("🧹 清除批量分析结果", key="clear_batch"):
            st.session_state.pop("batch_result", None)

    st.markdown("</div>", unsafe_allow_html=True)

# ========================================================================
# 功能4: 报告查看与管理
# ========================================================================
elif func == "📊 报告查看与管理":
    st.markdown('<div class="func-card">', unsafe_allow_html=True)
    st.subheader("📊 历史检测报告管理")
    st.caption("查看、下载和管理已生成的扫描报告")
    st.divider()

    if os.path.exists(REPORTS_DIR):
        rep_list = sorted([f for f in os.listdir(REPORTS_DIR) if os.path.isfile(os.path.join(REPORTS_DIR, f))], reverse=True)
        if rep_list:
            st.markdown(f"共找到 **{len(rep_list)}** 个报告文件")
            report_types = sorted(list(set(os.path.splitext(f)[1] for f in rep_list)))
            selected_type = st.selectbox("按格式筛选", ["全部"] + report_types)
            filtered = rep_list if selected_type == "全部" else [f for f in rep_list if f.endswith(selected_type)]

            for name in filtered[:50]:
                file_path = os.path.join(REPORTS_DIR, name)
                file_size = os.path.getsize(file_path)
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
                col_name, col_size, col_time, col_action = st.columns([4, 1, 2, 1])
                with col_name:
                    # 报告文件名里可能带 Markdown 特殊字符（报告名含扫描目标时尤其如此）
                    st.markdown(f"📄 **{_md(name)}**")
                with col_size:
                    size_str = f"{file_size / 1024:.1f} KB" if file_size < 1024 * 1024 else f"{file_size / 1024 / 1024:.1f} MB"
                    st.caption(size_str)
                with col_time:
                    st.caption(mtime)
                with col_action:
                    with open(file_path, "rb") as f:
                        st.download_button("📥", data=f.read(), file_name=name, key=f"dl_{name}")

            st.markdown("<br>", unsafe_allow_html=True)
            preview_name = st.selectbox("选择报告预览", filtered[:50])
            if preview_name:
                preview_path = os.path.join(REPORTS_DIR, preview_name)
                content = _read_file_safe(preview_path)
                if preview_name.endswith(".html"):
                    with st.expander("📄 HTML 报告预览", expanded=True):
                        st.components.v1.html(content, height=600, scrolling=True)
                elif preview_name.endswith(".json"):
                    with st.expander("📄 JSON 报告预览", expanded=True):
                        try:
                            st.json(json.loads(content))
                        except:
                            st.code(content[:5000], language="json")
                else:
                    with st.expander(f"📄 {preview_name} 预览", expanded=True):
                        st.code(content[:10000], language="text")
        else:
            st.info("暂无历史检测报告，完成扫描任务后自动生成归档。")
    else:
        st.info("报告目录不存在，首次执行扫描自动创建文件夹。")

    st.markdown("</div>", unsafe_allow_html=True)
