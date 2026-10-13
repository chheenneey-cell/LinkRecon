# -*- coding: utf-8 -*-
"""Link extraction helpers used by the scanner and reports.

The scanner needs two different numbers:
- link inventory: every link-like reference we can discover in the page/code
- suspicious hits: every rule match raised by detectors

Keeping these separate prevents rule hits from being shown as raw link counts.
"""

import re
from html import unescape
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse
from utils.finding_policy import unique_findings
from utils.html_utils import is_visually_hidden

try:
    from bs4 import BeautifulSoup, Comment
except Exception:  # pragma: no cover - fallback for minimal runtimes
    BeautifulSoup = None
    Comment = ()


LINK_ATTRS = {
    "href",
    "src",
    "action",
    "formaction",
    "poster",
    "data",
    "cite",
    "longdesc",
    "manifest",
    "background",
    "profile",
    "codebase",
    "classid",
    "archive",
}

DATA_LINK_ATTRS = {
    "data-href",
    "data-src",
    "data-url",
    "data-link",
    "data-target",
    "data-redirect",
    "data-location",
}

INLINE_URL_RE = re.compile(
    r"""(?P<url>
        https?://[^\s"'<>\\)]+
        | //[^\s"'<>\\)]+
        | javascript:[^\s"'<>]+
        | data:[^;"'<>]+;base64,[^\s"'<>]+
    )""",
    re.IGNORECASE | re.VERBOSE,
)

CSS_URL_RE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r"@import\s+(?:url\(\s*)?(['\"])(.*?)\1", re.IGNORECASE)
META_REFRESH_RE = re.compile(r"url\s*=\s*([^;]+)", re.IGNORECASE)


# 裸域名形式的链接（evilsite.cn/promo）。_is_link_like 会放行这种写法，
# 但它没有 scheme，urljoin 会把它当相对路径拼到 base 上，
# 导致 <a href="evilsite.cn/promo"> 被解析成 http://victim.com/a/evilsite.cn/promo
# —— 外链变内链，后续 is_external_link 判为内部，直接漏报。
_BARE_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
    r"(?::\d{1,5})?(?:[/?#].*)?$")

# 但 "promo.html"、"style.css" 同样能匹配上面的形状（.html 看起来就像 TLD）。
# 相对文件名必须排除掉，否则会被错当成外链域名。
_FILE_EXT_TAIL_RE = re.compile(
    r"\.(?:html?|xhtml|shtml|php\d?|aspx?|jsp|cgi|do|action"
    r"|js|mjs|cjs|css|less|scss|sass|json|xml|rss|atom|txt|md"
    r"|png|jpe?g|gif|svg|webp|ico|bmp|avif"
    r"|pdf|docx?|xlsx?|pptx?|zip|rar|7z|gz|tar"
    r"|mp[34]|webm|woff2?|ttf|eot|map)$", re.IGNORECASE)


def _is_bare_domain(value: str) -> bool:
    """value 是否为「省略了 scheme 的绝对域名」而非相对路径。"""
    if not _BARE_DOMAIN_RE.match(value):
        return False
    head = value.split('/', 1)[0].split('?', 1)[0].split('#', 1)[0]
    # 只有一个点且结尾像文件扩展名 -> 是相对文件名，不是域名
    return not _FILE_EXT_TAIL_RE.search(head)


def normalize_link(value: str, base_url: Optional[str] = None) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    value = value.strip(" \t\r\n'\"")
    lower = value.lower()
    if lower.startswith(("javascript:", "data:", "mailto:", "tel:")):
        return value
    if value.startswith("//"):
        scheme = "https"
        if base_url:
            parsed = urlparse(base_url)
            scheme = parsed.scheme or scheme
        return f"{scheme}:{value}"
    if base_url and not urlparse(value).scheme:
        # 先识别裸域名并补上 scheme，再交给 urljoin
        if (not value.startswith(("/", "./", "../", "#", "?"))
                and _is_bare_domain(value)):
            scheme = urlparse(base_url).scheme or "http"
            return f"{scheme}://{value}"
        return urljoin(base_url, value)
    return value


def _is_link_like(value: str) -> bool:
    value = (value or "").strip()
    if not value or value in ("#", "about:blank"):
        return False
    lower = value.lower()
    if lower.startswith(("http://", "https://", "//", "/", "./", "../", "javascript:", "data:")):
        return True
    return bool(re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}(?:[:/].*)?$", value))


def _add(
    items: List[Dict[str, Any]],
    seen: Set[str],
    value: str,
    *,
    source: str,
    source_tag: str,
    source_attr: str,
    context_type: str,
    context: str = "",
    base_url: Optional[str] = None,
    hidden: bool = False,
) -> None:
    if not _is_link_like(value):
        return
    normalized = normalize_link(value, base_url)
    if not normalized:
        return
    # Keep every occurrence in the inventory; unique counts are computed later.
    items.append({
        "url": normalized,
        "raw": value,
        "source": source,
        "source_tag": source_tag,
        "source_attr": source_attr,
        "context_type": context_type,
        "context": (context or "")[:300],
        "hidden": bool(hidden),
    })


def _split_srcset(value: str) -> Iterable[str]:
    for part in (value or "").split(","):
        candidate = part.strip().split(" ", 1)[0].strip()
        if candidate:
            yield candidate


def _extract_css_urls(text: str) -> Iterable[str]:
    for match in CSS_URL_RE.finditer(text or ""):
        yield match.group(2)
    for match in CSS_IMPORT_RE.finditer(text or ""):
        yield match.group(2)


def _extract_inline_urls(text: str) -> Iterable[str]:
    for match in INLINE_URL_RE.finditer(text or ""):
        yield match.group("url")


def extract_link_inventory(content: str, source: str = "", base_url: Optional[str] = None, content_type: str = "html") -> List[Dict[str, Any]]:
    """Extract a broad inventory of link-like references from HTML/CSS/JS/text."""
    items: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    source = source or base_url or "unknown"
    base_url = base_url or (source if str(source).startswith(("http://", "https://")) else None)
    text = content or ""
    parsed_html = False

    if BeautifulSoup is not None and "html" in (content_type or "").lower():
        try:
            soup = BeautifulSoup(text, "lxml")
            parsed_html = True

            # <base href> 必须先处理：注入一个 <base href="http://evil.cn/"> 是
            # 暗链/流量劫持的常用手法，页面上所有相对链接都会指向恶意站点。
            # 原实现完全不看 <base>，把这些链接全部还原成受害站自身的内链，
            # 判定为"无风险"——正好被攻击者利用。
            base_tag = soup.find("base", href=True)
            if base_tag:
                declared_base = str(base_tag["href"]).strip()
                if declared_base:
                    _add(items, seen, declared_base, source=source, source_tag="base",
                         source_attr="href", context_type="base_tag",
                         context=str(base_tag)[:300], base_url=base_url, hidden=False)
                    # 后续所有相对链接都以声明的 base 为准
                    base_url = (urljoin(base_url, declared_base) if base_url
                                else declared_base)

            for tag in soup.find_all(True):
                tag_name = (tag.name or "").lower()
                if tag_name == "base":
                    continue  # 上面已单独处理，避免重复计入
                style = (tag.get("style") or "").lower()
                tag_hidden = any(is_visually_hidden(parent.attrs)
                                 for parent in [tag] + list(tag.parents) if getattr(parent, 'attrs', None) is not None)

                for attr, raw_value in list(tag.attrs.items()):
                    attr_l = str(attr).lower()
                    values = raw_value if isinstance(raw_value, list) else [raw_value]
                    for value in values:
                        value = str(value)
                        if attr_l == "srcset":
                            for candidate in _split_srcset(value):
                                _add(items, seen, candidate, source=source, source_tag=tag_name, source_attr=attr_l, context_type="html_attr", context=str(tag)[:300], base_url=base_url, hidden=tag_hidden)
                        elif attr_l in LINK_ATTRS or attr_l in DATA_LINK_ATTRS:
                            _add(items, seen, value, source=source, source_tag=tag_name, source_attr=attr_l, context_type="html_attr", context=str(tag)[:300], base_url=base_url, hidden=tag_hidden)
                        elif attr_l.startswith("on"):
                            for candidate in _extract_inline_urls(value):
                                _add(items, seen, candidate, source=source, source_tag=tag_name, source_attr=attr_l, context_type="event_handler", context=value, base_url=base_url, hidden=tag_hidden)

                if style:
                    for candidate in _extract_css_urls(style):
                        _add(items, seen, candidate, source=source, source_tag=tag_name, source_attr="style", context_type="inline_css", context=style, base_url=base_url, hidden=tag_hidden)

                if tag_name == "meta" and str(tag.get("http-equiv", "")).lower() == "refresh":
                    match = META_REFRESH_RE.search(str(tag.get("content", "")))
                    if match:
                        _add(items, seen, match.group(1), source=source, source_tag=tag_name, source_attr="content", context_type="meta_refresh", context=str(tag), base_url=base_url, hidden=tag_hidden)

            for block in soup.find_all(["script", "style"]):
                block_text = block.string or block.get_text() or ""
                context_type = "script_text" if block.name == "script" else "style_text"
                for candidate in _extract_inline_urls(block_text):
                    _add(items, seen, candidate, source=source, source_tag=block.name, source_attr="text", context_type=context_type, context=block_text[:300], base_url=base_url)
                if block.name == "style":
                    for candidate in _extract_css_urls(block_text):
                        _add(items, seen, candidate, source=source, source_tag=block.name, source_attr="text", context_type=context_type, context=block_text[:300], base_url=base_url)

            for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
                comment_text = str(comment)
                for candidate in _extract_inline_urls(comment_text):
                    _add(items, seen, candidate, source=source, source_tag="comment", source_attr="text", context_type="comment", context=comment_text[:300], base_url=base_url, hidden=True)
        except Exception:
            pass

    if not parsed_html:
        for candidate in _extract_inline_urls(text):
            _add(items, seen, candidate, source=source, source_tag="text", source_attr="text", context_type="raw_text", context=text[max(0, text.find(candidate) - 80): text.find(candidate) + len(candidate) + 80], base_url=base_url)
    for candidate in _extract_css_urls(text):
        _add(items, seen, candidate, source=source, source_tag="css", source_attr="url", context_type="css_url", context=candidate, base_url=base_url)

    return items


def summarize_link_inventory(link_inventory: List[Dict[str, Any]], suspicious_links: List[Dict[str, Any]]) -> Dict[str, int]:
    suspicious_links = list(unique_findings({'suspicious_links': suspicious_links}, reportable_only=True))
    def _clean(value: str) -> str:
        value = unescape(str(value or "").strip())
        if "..." in value or value.endswith("…"):
            return ""
        return value

    all_urls = [_clean(item.get("url")) for item in link_inventory or [] if item.get("url")]
    all_urls = [url for url in all_urls if url]
    unique_urls = set(all_urls)
    hidden_urls = {_clean(item.get("url")) for item in link_inventory or [] if item.get("url") and item.get("hidden")}
    hidden_urls.discard("")
    suspicious_urls = {
        _clean(item.get("link") or item.get("url"))
        for item in suspicious_links or []
        if item.get("link") or item.get("url")
    }
    suspicious_urls.discard("")
    # A decoded dynamic URL can be real evidence without occurring literally
    # in the raw inventory. Do not discard it by intersecting with inventory.
    suspicious_count = len(suspicious_urls)
    return {
        "link_total": len(all_urls),
        "unique_links": len(unique_urls),
        "hidden_links": len(hidden_urls),
        "suspicious_unique_links": suspicious_count,
        "suspicious_hits": len(suspicious_links or []),
    }
