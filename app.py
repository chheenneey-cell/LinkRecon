#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask entrypoint for the LinkRecon web console.

This keeps the original CLI, Tk GUI, and Streamlit app intact while serving
code.html as the browser UI and exposing the scanner through JSON APIs.
"""

import copy
import csv
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_SITE_PACKAGES = os.path.join(BASE_DIR, "site-packages")
if os.path.isdir(LOCAL_SITE_PACKAGES):
    sys.path.insert(0, LOCAL_SITE_PACKAGES)
sys.path.insert(0, BASE_DIR)

from flask import (
    Flask, abort, jsonify, redirect, render_template, request,
    send_file, send_from_directory, session, url_for,
)

from core import auth
from core.config import Config
from core.detector.keyword_detector import KeywordDetector
from core.detector.js_detector import JSDetector
from core.reporter import Reporter
# 目标类型识别 / 内网判定 / 批量聚合统一走 core.runner，
# 不再在本文件里手写内网 IP 正则和聚合字段列表 ——
# 原来那份正则漏了 IPv6 回环和 169.254.x 元数据地址，
# 手写聚合还容易漏字段（CLI 侧就漏过 link_inventory）。
from core.runner import (
    detect_target_type,
    finalize_aggregate,
    merge_result,
    new_aggregate,
    normalize_target as runner_normalize_target,
    run_target,
)
from utils.network_utils import fetch_url_content
from utils.network_policy import validate_fake_ip_proxy
from utils.request_profiles import UA_MODES
from utils.link_utils import summarize_link_inventory
from utils.scan_outcome import scan_complete, scan_error
from utils.report_paths import new_report_path


app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

# 会话配置。
# SECRET_KEY 必须持久化到磁盘：每次启动都随机生成的话，服务一重启所有人的
# 登录状态就失效；多进程部署时各进程密钥不同还会导致登录态随机丢失。
app.secret_key = auth.get_or_create_secret_key()
app.config.update(
    # HttpOnly：禁止 JS 读取会话 cookie，降低 XSS 窃取会话的风险
    SESSION_COOKIE_HTTPONLY=True,
    # SameSite=Strict：浏览器不会在任何跨站请求里带上这个 cookie，
    # 等于免费拿到 CSRF 防护（控制台本身是同源 fetch，不受影响）
    SESSION_COOKIE_SAMESITE="Strict",
    # 服务默认只监听 127.0.0.1（明文 HTTP），因此不能强制 Secure，
    # 否则 cookie 根本发不出去。若放到 HTTPS 反代后面，
    # 请把环境变量 LINKRECON_COOKIE_SECURE 设为 1。
    SESSION_COOKIE_SECURE=os.environ.get("LINKRECON_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=auth.SESSION_LIFETIME_SECONDS,
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
)

REPORTS_DIR = os.path.realpath(
    os.environ.get("LINKRECON_REPORTS_DIR") or os.path.join(BASE_DIR, "reports")
)
# 测试/部署可以把运行状态放到独立目录。默认仍使用项目 data/，不会改变现有部署。
DATA_DIR = os.path.realpath(
    os.environ.get("LINKRECON_DATA_DIR") or os.path.join(BASE_DIR, "data")
)
STATE_FILE = os.path.join(DATA_DIR, "app_state.json")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")

JOBS = {}
JOBS_LOCK = threading.RLock()

# 已结束的 job 在内存里保留多久（秒）。
# 原来 JOBS 只增不减：常驻服务跑上几千次扫描后，每个 job 还挂着最多 500 条日志
# 和完整的 result，内存只会一路涨到 OOM。这里给已完成/失败的 job 加 TTL。
JOB_RETENTION_SECONDS = 3600


class TargetNotAllowed(ValueError):
    """扫描目标（或报告输出目录）不在允许的路径白名单内。路由层据此返回 403。"""


class TaskNotFound(Exception):
    """任务 ID 不存在。

    原来 run_task_scan 抛的是 ValueError("task not found")，而 api_run_task
    用 `except ValueError` 捕获后一律映射成 404 —— 结果连 run_scan 里
    ValueError("target is required") 这类参数校验错误也被报成「任务不存在」，
    排查时完全指错方向。所以「任务不存在」单独用一个异常类型。
    """


class TaskBusy(ValueError):
    """One task can have only one active execution."""


# ---------------------------------------------------------------------------
# 本地扫描根目录白名单。
#
# 原来 _normalize_target() 只要 os.path.exists(target) 成立就 abspath 放行，
# 于是 POST /api/scan {"target": "/etc/shadow"} 会被判成 local_file 正常扫描，
# 命中的内容写进 HTML 报告，再通过 GET /reports/<name> 原样读回来 ——
# 一个暗链扫描器就这样退化成了任意本地文件读取器。
#
# 这里把本地目标限制在白名单目录内（默认只有项目目录本身）；
# 确需扫描项目外的目录时，由部署方通过环境变量 LINKRECON_SCAN_ROOTS
# （os.pathsep 分隔的多个绝对路径）显式授权，而不是默认放开整个文件系统。
# 注意：URL 目标不受此限制。
# ---------------------------------------------------------------------------
def _load_allowed_scan_roots():
    raw = os.environ.get("LINKRECON_SCAN_ROOTS", "")
    roots = []
    for item in raw.split(os.pathsep):
        item = item.strip().strip('"').strip("'")
        if not item:
            continue
        try:
            roots.append(os.path.realpath(os.path.expanduser(item)))
        except (OSError, ValueError):
            continue
    return roots or [os.path.realpath(BASE_DIR)]


ALLOWED_SCAN_ROOTS = _load_allowed_scan_roots()


def _path_within(path, root):
    """判断 path 是否位于 root 之内（含 root 本身）。

    必须先 realpath 再比较：只做字符串前缀匹配的话，
    reports/../../etc 或者一条指向 /etc 的软链接都能绕过去。
    """
    if not path or not root:
        return False
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
        # commonpath 在两个路径不同盘符（Windows C:\ vs D:\）
        # 或一个相对一个绝对时会抛 ValueError，此时按「不在范围内」处理。
        return os.path.commonpath([real_path, real_root]) == real_root
    except (OSError, ValueError):
        return False


def _is_within_allowed_roots(path):
    """本地扫描目标是否落在 ALLOWED_SCAN_ROOTS 里的任意一个根目录内。"""
    return any(_path_within(path, root) for root in ALLOWED_SCAN_ROOTS)


# 状态文件降级标志：_load_state() 读失败时置位，并在 /api/health 暴露。
# 原来加载失败只往 app.logger 打一条异常就静默继续，服务表面正常、
# 历史记录却全空了，运维根本发现不了。
STATE_DEGRADED = {
    "degraded": False,
    "error": "",
    "backup": "",
}

DEFAULT_SETTINGS = {
    "mode": "deep",
    "depth": 3,
    "threads": 8,
    "timeout": 30,
    "report_format": "html",
    "headless": False,
    "proxy": "",
    "allow_proxy_fake_ip": False,
    "ua_mode": "dual",
    "exclude": [],
}

STATE = {
    "clients": [],
    "tasks": [],
    "history": [],
    "settings": dict(DEFAULT_SETTINGS),
}

# STATE 的全局锁。
# 原来只有 JOBS_LOCK，且只护着 JOBS，STATE 是彻底裸奔的：
#   * 两个后台 job 同时完成会并发 _save_state()，同一个 app_state.json
#     被两个线程交错写入，最坏情况落盘一份被截断的、下次启动读不回来的 JSON；
#   * _ensure_history_ids() 正在遍历 history 时后台线程 insert(0, ...)，
#     会抛 RuntimeError: list changed size during iteration。
# 用可重入锁：_save_state() 常常在已持锁的代码块里被调用。
STATE_LOCK = threading.RLock()


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _backup_broken_state():
    """把读不回来的状态文件挪成 .bak，避免下一次 _save_state() 直接覆盖掉现场。"""
    backup = f"{STATE_FILE}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
    try:
        os.replace(STATE_FILE, backup)
        return backup
    except OSError:
        return ""


def _load_state():
    _ensure_data_dir()
    if not os.path.exists(STATE_FILE):
        return
    with STATE_LOCK:
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError("状态文件顶层不是 JSON 对象")
            STATE["clients"] = loaded.get("clients", [])
            STATE["tasks"] = loaded.get("tasks", [])
            STATE["history"] = loaded.get("history", [])
            settings = dict(DEFAULT_SETTINGS)
            settings.update(loaded.get("settings", {}))
            STATE["settings"] = settings
        except Exception as exc:
            # 文件损坏（多半就是并发写留下的截断 JSON）时：备份 + 置降级标志。
            # 直接静默吞掉的话，用户只会看到「历史记录莫名其妙清空了」。
            app.logger.exception("Failed to load state file")
            backup = _backup_broken_state()
            STATE_DEGRADED.update({
                "degraded": True,
                "error": str(exc),
                "backup": backup,
            })


def _save_state():
    """原子落盘：先写同目录临时文件再 os.replace 覆盖。

    原实现直接以 "w" 打开目标文件再 json.dump：写到一半进程退出、
    或者两个线程同时写，留在磁盘上的就是半截 JSON，下次启动整份状态全丢。
    os.replace 在同一文件系统内是原子的，读者要么看到旧版本要么看到新版本。
    """
    _ensure_data_dir()
    with STATE_LOCK:
        _refresh_client_activity()
        payload = json.dumps(STATE, ensure_ascii=False, indent=2)
    tmp_path = f"{STATE_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, STATE_FILE)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _refresh_client_activity():
    counts = {}
    for task in STATE["tasks"]:
        if task.get("status") in ("pending", "queued", "running"):
            client_id = str(task.get("client_id") or "")
            counts[client_id] = counts.get(client_id, 0) + 1
    for client in STATE["clients"]:
        client["active"] = counts.get(str(client.get("id")), 0)


def _claim_task(task_id, owner):
    with STATE_LOCK:
        task = _find_by_id(STATE["tasks"], task_id)
        if not task:
            raise TaskNotFound(f"任务不存在: {task_id}")
        if task.get("status") in ("running", "queued"):
            raise TaskBusy("任务正在运行，请勿重复提交")
        task.update(status="running", running_job_id=owner, updated_at=_now(), last_error="")
        _save_state()
        return task


def _recover_interrupted_tasks():
    changed = False
    with STATE_LOCK:
        previous = [(c.get("id"), c.get("active")) for c in STATE["clients"]]
        for task in STATE["tasks"]:
            if task.get("status") in ("running", "queued"):
                task.update(status="error", last_error="服务重启中断了扫描，请重新运行",
                            running_job_id="", updated_at=_now())
                changed = True
        _refresh_client_activity()
        if changed or previous != [(c.get("id"), c.get("active")) for c in STATE["clients"]]:
            _save_state()
    return changed


def _ensure_history_ids():
    with STATE_LOCK:
        changed = False
        # 持锁遍历：否则后台 job 的 history.insert(0, ...) 会让这里
        # 抛 RuntimeError: list changed size during iteration。
        for item in reversed(STATE["history"]):
            if not item.get("id"):
                item["id"] = _new_id("hist")
                changed = True
            # 旧版快速扫描只保存了名称，没有对应任务。按每次扫描独立补齐，
            # 不能用名称查找任务，否则同名但不同次的扫描会串到同一详情页。
            # 已有 task_id 的记录（包括用户删除过的任务）保持原关联不变。
            if not item.get("task_id") and (item.get("task_name") or "").strip() and item.get("target"):
                task = _create_task({
                    "name": item["task_name"], "target": item["target"],
                    "client_id": item.get("client_id") or "",
                    "client": item.get("client") or "unassigned",
                    "status": "done", "source": "history",
                    "created_at": item.get("created_at") or _now(),
                    "report_url": item.get("report_url") or "",
                    "notes": "由历史扫描记录恢复。原扫描参数未保存，当前参数为默认值；再次运行前请确认。",
                }, save=False)
                item["task_id"] = task["id"]
                changed = True
        if changed:
            _save_state()
        return changed


def _state_snapshot(key=None):
    """在锁内做一份深拷贝再交给 jsonify，避免序列化过程中被后台线程改写。"""
    with STATE_LOCK:
        return copy.deepcopy(STATE if key is None else STATE[key])


def _find_by_id(items, item_id):
    return next((item for item in items if str(item.get("id")) == str(item_id)), None)


def _ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _ensure_uploads_dir():
    os.makedirs(UPLOADS_DIR, exist_ok=True)


def _resolve_report_dir(payload):
    """把 payload["output_dir"] 解析成 reports/ 之下的目录。

    原实现对绝对路径直接放行（`elif os.path.isabs(output_dir): report_dir = output_dir`），
    调用方随手传一个 "/etc/cron.d" 或 "/var/www/html" 就能把扫描报告写进任意
    可写目录 —— 配合 HTML 报告里可控的内容就是一次任意文件写入。
    相对路径也没做校验，"../../.." 一样能逃出项目目录。
    现在一律相对 REPORTS_DIR 解析，并用 realpath + commonpath 复核落点。
    """
    output_dir = (payload.get("output_dir") or "").strip()
    reports_root = os.path.realpath(REPORTS_DIR)
    if not output_dir:
        report_dir = reports_root
    else:
        if os.path.isabs(output_dir):
            raise TargetNotAllowed(
                f"output_dir 只能是相对 reports/ 的相对路径，已拒绝绝对路径：{output_dir}"
            )
        report_dir = os.path.realpath(os.path.join(reports_root, output_dir))
        if not _path_within(report_dir, reports_root):
            raise TargetNotAllowed(
                f"output_dir 超出了报告根目录 reports/，已拒绝：{output_dir}"
            )
    os.makedirs(report_dir, exist_ok=True)
    return report_dir


def _report_url_for_path(report_path):
    if not report_path:
        return ""
    abs_path = os.path.abspath(report_path)
    reports_root = os.path.abspath(REPORTS_DIR)
    try:
        rel = os.path.relpath(abs_path, reports_root)
    except ValueError:
        return ""
    if rel.startswith(".."):
        return ""
    return "/reports/" + rel.replace("\\", "/")


def _safe_upload_name(filename):
    name = os.path.basename(filename or "targets.txt")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return name or "targets.txt"


def _normalize_target(target):
    """规范化扫描目标；本地路径必须落在 ALLOWED_SCAN_ROOTS 内。

    原实现见到 os.path.exists(target) 就 abspath 放行，任何存在的本地文件
    （/etc/shadow、~/.ssh/id_rsa、/proc/self/environ …）都会被当成扫描目标读进来，
    命中内容再随报告经 /reports/<name> 泄露出去。
    现在越界目标直接抛 TargetNotAllowed，由路由层返回 403。
    URL 目标不走这条校验（它本来就不读本地文件）。
    """
    raw = (target or "").strip().strip('"').strip("'")
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return runner_normalize_target(raw)

    # 相对路径优先按「项目目录内」解释，而不是按进程 cwd（cwd 不受控）。
    candidates = [raw] if os.path.isabs(raw) else [os.path.join(BASE_DIR, raw), raw]
    for candidate in candidates:
        try:
            exists = os.path.exists(candidate)
        except (OSError, ValueError):
            exists = False
        if not exists:
            continue
        if not _is_within_allowed_roots(candidate):
            raise TargetNotAllowed(
                f"目标路径不在允许的扫描根目录内，已拒绝：{raw}。"
                f"当前允许的根目录：{os.pathsep.join(ALLOWED_SCAN_ROOTS)}。"
                f"如确需扫描其它目录，请通过环境变量 LINKRECON_SCAN_ROOTS 显式授权。"
            )
        return os.path.realpath(candidate)

    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?$", raw):
        return "https://" + raw
    return raw


def _as_int(value, default, lo, hi):
    """把入参转成 [lo, hi] 区间内的整数。

    原来到处直接写 int(payload.get("depth", ...))：前端把输入框清空后
    传上来的是 "" 或 null，int("") 直接抛 ValueError，
    在同步接口上表现为 400、在后台 job 上表现为任务整个失败，
    而这本来只该退回默认值。顺便做上下界钳制，
    避免 threads=100000 之类的取值把服务打死。
    """
    for source in (value, default):
        try:
            if source is None or isinstance(source, bool):
                continue
            text = str(source).strip()
            if not text:
                continue
            return max(lo, min(hi, int(float(text))))
        except (TypeError, ValueError):
            continue
    return lo


def _risk_to_int(value):
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "").strip().lower()
    if text in ("high", "critical") or "高" in text:
        return 8
    if text in ("medium", "mid") or "中" in text:
        return 5
    if text in ("low",) or "低" in text:
        return 2
    try:
        return int(float(text))
    except Exception:
        return 0


class JobLogHandler(logging.Handler):
    def __init__(self, job_id):
        super().__init__()
        self.job_id = job_id
        self.setFormatter(logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S",
        ))

    def emit(self, record):
        try:
            _append_job_log(self.job_id, self.format(record))
        except Exception:
            pass


def _job_snapshot(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None
        return _jsonable(dict(job))


def _update_job(job_id, **updates):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job.update(updates)
        job["updated_at"] = _now()
        # 记录终态时间戳（单调可比较的 epoch 秒），供 TTL 清理使用；
        # created_at/updated_at 是给人看的字符串，不适合拿来算差值。
        if updates.get("status") in ("done", "error") and not job.get("finished_ts"):
            job["finished_ts"] = time.time()


def _cleanup_jobs():
    """清掉已结束且超过 TTL 的 job。

    JOBS 原来只增不减，每个 job 还挂着最多 500 条日志和完整 result，
    常驻进程跑久了就是稳定的内存泄漏。这里在新建 job 时顺带回收。
    """
    now = time.time()
    with JOBS_LOCK:
        stale = [
            job_id for job_id, job in JOBS.items()
            if job.get("finished_ts") and now - job["finished_ts"] > JOB_RETENTION_SECONDS
        ]
        for job_id in stale:
            JOBS.pop(job_id, None)
    return len(stale)


def _append_job_log(job_id, message):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        logs = job.setdefault("logs", [])
        logs.append({"time": _now(), "message": str(message)})
        del logs[:-500]


def _create_job(kind, payload):
    _cleanup_jobs()
    job_id = _new_id("job")
    if kind == "task":
        _claim_task(payload.get("task_id"), job_id)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "kind": kind,
            "status": "queued",
            "progress": 0,
            "message": "等待执行",
            "logs": [],
            "payload": payload,
            "result": None,
            "error": "",
            "created_at": _now(),
            "updated_at": _now(),
            "finished_ts": None,
        }
    thread = threading.Thread(target=_run_job, args=(job_id,), daemon=True)
    try:
        thread.start()
    except Exception as error:
        _update_job(job_id, status="error", error=str(error))
        if kind == "task":
            with STATE_LOCK:
                task = _find_by_id(STATE["tasks"], payload.get("task_id"))
                task.update(status="error", running_job_id="", last_error=str(error))
                _save_state()
        raise
    return _job_snapshot(job_id)


def _run_job(job_id):
    job = _job_snapshot(job_id)
    if not job:
        return
    payload = dict(job.get("payload") or {})
    kind = job.get("kind")
    _update_job(job_id, status="running", progress=5, message="任务已启动")
    _append_job_log(job_id, f"开始执行 {kind} 任务")
    try:
        if kind == "scan":
            result = run_quick_scan(payload, job_id=job_id)
        elif kind == "batch":
            result = run_batch(payload, job_id=job_id)
        elif kind == "task":
            result = run_task_scan(payload.get("task_id"), job_id=job_id)
        else:
            raise ValueError(f"unknown job kind: {kind}")
        if result.get("ok"):
            _update_job(job_id, status="done", progress=100, message="任务完成", result=result)
            _append_job_log(job_id, "任务完成")
        else:
            message = result.get("error") or "扫描失败或不完整"
            _update_job(job_id, status="error", progress=100, message="扫描不完整", error=message, result=result)
            _append_job_log(job_id, message)
    except Exception as exc:
        _update_job(job_id, status="error", progress=100, message="任务失败", error=str(exc))
        _append_job_log(job_id, f"任务失败: {exc}")


def _jsonable(value):
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_jsonable(v) for v in value]
        return str(value)


def _build_job_logger(job_id, log_dir, level):
    """为单个任务创建独立 logger，返回 (logger, log_file)。

    原来每个任务都调一次 setup_logging()，而 utils/logging_utils.Logger.__init__
    里有 self.logger.handlers.clear() —— 拿到的永远是同一个全局 'LinkRecon' logger，
    于是新任务一开始就把上一个任务挂着的 JobLogHandler 和 FileHandler 全清掉：
    任务 A 的前端实时日志当场卡死不再更新，A 之后产生的日志还会写进 B 的日志文件。
    改成 per-job logger + propagate=False，各任务的 handler 互不干扰，
    也不会污染全局 'LinkRecon' logger。
    """
    name = f"LinkRecon.job.{job_id}" if job_id else f"LinkRecon.sync.{uuid.uuid4().hex[:8]}"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # 不向上冒泡到 'LinkRecon'/root，避免和别处的 handler 互相重复输出
    logger.propagate = False
    # 同一个 job 内可能多次 _build_config（批量扫描逐个目标），
    # 复用同名 logger 前先摘掉自己上一轮的 handler（只动本 logger，不动全局）。
    _release_logger(logger)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    os.makedirs(log_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"LinkRecon_{stamp}_{uuid.uuid4().hex[:6]}.log")
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if job_id:
        job_handler = JobLogHandler(job_id)
        job_handler.setLevel(level)
        logger.addHandler(job_handler)
    return logger, log_file


def _release_logger(logger):
    """摘掉并关闭 logger 上的全部 handler。

    任务结束必须调用，否则 FileHandler 会一直占着文件句柄不释放
    （长跑服务下就是 too many open files）。
    """
    if not logger:
        return
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass


def _proxy_options(payload, settings):
    proxy = payload.get("proxy") or settings.get("proxy") or None
    option = payload.get("allow_proxy_fake_ip", settings.get("allow_proxy_fake_ip", False))
    if not isinstance(option, bool):
        raise ValueError("Fake-IP 兼容开关必须为布尔值")
    if option:
        validate_fake_ip_proxy(proxy)
    return proxy, option


def _build_config(payload, target, job_id=None):
    # 在锁内取一份 settings 快照：直接持有 STATE["settings"] 的引用的话，
    # 组装过程中别的线程保存设置会让前后读到的值不一致。
    with STATE_LOCK:
        settings = dict(STATE.get("settings") or DEFAULT_SETTINGS)
    report_format = payload.get("report_format") or payload.get("format") or settings.get("report_format") or "html"
    mode = payload.get("mode") or settings.get("mode") or "deep"
    config = Config()
    config.target = target
    config.target_type = detect_target_type(target)
    # mode 现在是 property，赋值会自动同步 scan_mode 并刷新模式开关，
    # 不用再写 scan_mode/mode 双重赋值 + 手动 _set_mode_config()。
    config.mode = mode
    # depth 同理是 crawl_depth 的别名，写一个就够。
    config.depth = _as_int(payload.get("depth"), settings.get("depth", 1), 1, 10)
    config.threads = _as_int(payload.get("threads"), settings.get("threads", 8), 1, 64)
    config.timeout = _as_int(payload.get("timeout"), settings.get("timeout", 30), 1, 600)
    config.proxy, config.allow_proxy_fake_ip = _proxy_options(payload, settings)
    config.ua_mode = payload.get("ua_mode") or settings.get("ua_mode") or "dual"
    if config.ua_mode not in UA_MODES:
        raise ValueError("UA 模式必须是 dual、browser 或 baidu")
    config.exclude = payload.get("exclude") or []
    # Config 里的字段名是 keywords_file（带 s）；
    # 关键字文件同样是调用方可控的读取路径，走白名单校验。
    keyword_file = payload.get("keyword_file") or payload.get("keywords_file")
    config.keywords_file = _resolve_keyword_file(keyword_file) if keyword_file else None
    config.report_type = report_format
    config.debug = bool(payload.get("verbose", False))
    config.use_headless_browser = bool(payload.get("headless", settings.get("headless", False)))
    config.headless_browser = payload.get("browser_type", "chrome")
    config.js_wait_time = _as_int(payload.get("js_wait"), 3, 0, 60)
    config.headless_timeout = _as_int(payload.get("headless_timeout"), 60, 5, 600)
    config.headless_binary = payload.get("headless_binary")
    config.headless_driver_path = payload.get("headless_driver")
    config.headless_auto_download = config.use_headless_browser
    config.max_pages = _as_int(payload.get("max_pages"), 200, 1, 1000)

    report_dir = _resolve_report_dir(payload)
    config.report_file = new_report_path(report_dir, report_format)
    level = logging.DEBUG if config.debug else logging.INFO
    config.logger, config.log_file = _build_job_logger(job_id, report_dir, level)
    return config


def _summarize(target, result, report_path, duration):
    from utils.finding_policy import issue_count, unique_findings
    suspicious_links = result.get("suspicious_links", [])
    keyword_matches = result.get("keyword_matches", [])
    hidden_elements = result.get("hidden_elements", [])
    link_stats = result.get("link_stats") or summarize_link_inventory(result.get("link_inventory", []), suspicious_links)
    high_risk = issue_count(result)

    # Scanner 现在会把吞掉的异常记进 results["errors"]，
    # 带进摘要里，否则「扫了但全失败」和「扫干净了」在历史记录上长得一模一样。
    errors = [str(item) for item in (result.get("errors") or [])]

    report_name = os.path.basename(report_path) if report_path else ""
    return {
        "id": _new_id("hist"),
        "target": target,
        "scan_status": "complete" if scan_complete(result) else "incomplete",
        "target_type": detect_target_type(target),
        "scanned_files": int(result.get("scanned_files", 0) or 0),
        "scanned_urls": int(result.get("scanned_urls", 0) or 0),
        "total_issues": high_risk,
        "review_count": sum(item.get("assessment") == "needs_review" for item in unique_findings(result)),
        "link_total": int(link_stats.get("link_total", 0) or 0),
        "unique_links": int(link_stats.get("unique_links", 0) or 0),
        "hidden_links": int(link_stats.get("hidden_links", 0) or 0),
        "suspicious_links": int(link_stats.get("suspicious_unique_links", 0) or 0),
        "suspicious_hits": int(link_stats.get("suspicious_hits", len(suspicious_links)) or 0),
        "keyword_matches": len(keyword_matches),
        "keyword_review_count": sum(item.get("assessment") == "needs_review" for item in keyword_matches),
        "hidden_elements": len(hidden_elements),
        "high_risk": high_risk,
        "errors": errors[:20],
        "error_count": len(errors),
        "duration": duration,
        "report": report_name,
        "report_path": os.path.abspath(report_path) if report_path else "",
        "report_url": _report_url_for_path(report_path),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def run_scan(payload, job_id=None, update_progress=True):
    target = _normalize_target(payload.get("target", ""))
    if not target:
        raise ValueError("缺少扫描目标 target")

    target_type = detect_target_type(target)
    if target_type == "unknown":
        raise ValueError(f"无法识别的扫描目标: {target}")

    sync_client = payload.get("sync_client") is True
    task_name = (payload.get("task_name") or "").strip()
    if sync_client and (not task_name or len(task_name) > 100):
        raise ValueError("同步客户需要任务名称（最多100字）")

    config = _build_config(payload, target, job_id=job_id)
    try:
        if job_id and update_progress:
            _update_job(job_id, progress=12, message="扫描器已配置")
            _append_job_log(job_id, f"目标类型: {config.target_type}")
        started = datetime.now()
        # 走 core.runner.run_target：异常会被记进 result["errors"]，
        # 调用方能区分「没发现问题」和「压根没扫成」。
        result = run_target(config)
        if job_id and update_progress:
            _update_job(job_id, progress=82, message="扫描完成，正在生成报告")
        duration = str(datetime.now() - started).split(".")[0]
        report_path = Reporter(config).generate_report(result, duration)
    finally:
        # 任务结束务必摘掉 handler 并关闭文件句柄，
        # 否则 JobLogHandler 会一直挂着已完成 job 的引用、FileHandler 也不释放。
        _release_logger(config.logger)

    summary = _summarize(target, result, report_path, duration)
    summary["client"] = payload.get("client") or payload.get("client_name") or "unassigned"
    summary["client_id"] = payload.get("client_id") or ""
    summary["task_id"] = payload.get("task_id") or ""
    summary["task_name"] = task_name
    complete = scan_complete(result)
    if job_id and summary.get("errors"):
        for message in summary["errors"]:
            _append_job_log(job_id, f"扫描告警: {message}")
    # 历史写入必须持锁：两个 job 同时完成时，无锁的 insert + 截断 + 落盘
    # 会互相覆盖，甚至写出半截 JSON。任务扫描完成时也在这里新增一条记录。
    with STATE_LOCK:
        if sync_client and complete:
            # 仅扫描成功并生成报告后同步；同名查找、创建和计数使用同一把锁，
            # 防止并发扫描创建重复客户。不覆盖已有客户的域名、联系人或备注。
            client = next((c for c in STATE["clients"] if c.get("name") == task_name), None)
            if client is None:
                client = {
                    "id": _new_id("cli"), "name": task_name, "domain": target,
                    "contact": "--", "notes": "", "icon": "C", "color": "accent",
                    "scans": 0, "threats": 0, "active": 0,
                    "created_at": _now(), "updated_at": _now(),
                }
                STATE["clients"].append(client)
            client["scans"] = int(client.get("scans", 0) or 0) + 1
            client["threats"] = int(client.get("threats", 0) or 0) + int(summary.get("high_risk", 0) or 0)
            client["updated_at"] = _now()
            summary["client"] = client["name"]
            summary["client_id"] = client["id"]
        STATE["history"].insert(0, summary)
        del STATE["history"][200:]
        _save_state()
    if job_id and update_progress:
        _update_job(job_id, progress=95, message="报告已生成")
    return {
        "ok": complete,
        "error": "" if complete else scan_error(result),
        "summary": summary,
        "result": _jsonable(result),
    }


def run_quick_scan(payload, job_id=None):
    """命名的快速扫描必须持久化为任务，才能从历史进入详情并再次运行。"""
    name = (payload.get("task_name") or "").strip()
    if not name or payload.get("task_id"):
        return run_scan(payload, job_id=job_id)
    if len(name) > 100:
        raise ValueError("任务名称最多100字")
    target = _normalize_target(payload.get("target", ""))
    if not target or detect_target_type(target) == "unknown":
        raise ValueError("缺少或无法识别的扫描目标")
    task = _create_task({
        **payload, "id": _new_id("task"), "name": name, "target": target,
        "status": "running", "source": "quick_scan",
    })
    scan_payload = {**payload, "target": target, "task_id": task["id"], "task_name": name}
    try:
        scanned = run_scan(scan_payload, job_id=job_id)
        summary = scanned["summary"]
        with STATE_LOCK:
            stored = _find_by_id(STATE["tasks"], task["id"])
            if stored:
                stored.update({
                    "status": "done" if scanned["ok"] else "error", "report_url": summary.get("report_url") or "",
                    "client_id": summary.get("client_id") or "",
                    "client": summary.get("client") or "unassigned",
                    "last_error": scanned.get("error") or "", "updated_at": _now(),
                })
                # 同步客户时 run_scan 已计数；普通的手动客户关联在这里计数。
                client = _find_by_id(STATE["clients"], stored["client_id"])
                if client and scanned["ok"] and payload.get("sync_client") is not True:
                    client["scans"] = int(client.get("scans", 0) or 0) + 1
                    client["threats"] = int(client.get("threats", 0) or 0) + int(summary.get("high_risk", 0) or 0)
                    client["updated_at"] = _now()
                original_client = _find_by_id(STATE["clients"], task.get("client_id"))
                if original_client:
                    original_client["active"] = max(0, int(original_client.get("active", 0) or 0) - 1)
                _save_state()
                task = dict(stored)
        return {**scanned, "task": task}
    except Exception as exc:
        with STATE_LOCK:
            stored = _find_by_id(STATE["tasks"], task["id"])
            if stored:
                stored.update({"status": "error", "last_error": str(exc), "updated_at": _now()})
                _save_state()
        raise


# ---------------------------------------------------------------------------
# 认证与授权
# ---------------------------------------------------------------------------
#
# 设计要点：用 before_request 做「默认拒绝」，而不是给 28 个路由逐个挂装饰器。
# 逐个挂的问题是漏一个就是一个未授权入口，而且以后每加一个路由都得记得加 ——
# 这个项目已经在「漏改一处」上栽过好几次（keywords_file 拼写、_risk 引用）。
# 默认拒绝则相反：新加的路由自动受保护，只有显式列进白名单才放行。

# 无需登录即可访问的端点（Flask endpoint 名，不是 URL）
PUBLIC_ENDPOINTS = {
    "login",
    "logout",
    "health",        # 供反向代理/监控探活，只返回状态不含业务数据
    "static",
}

# 只读角色（viewer）允许的写操作端点。
# 默认规则：GET/HEAD 放行给 viewer，其余方法一律要求 admin ——
# 扫描器能读本地文件、能发网络请求、能改配置，只读账号必须挡在这些能力之外。
# 新增的写路由默认就是 admin-only，不会因为忘记标注而漏保护。
VIEWER_WRITABLE_ENDPOINTS = set()


auth_logger = logging.getLogger("LinkRecon.web.auth")


def _client_ip() -> str:
    """取来源 IP。放在反代后面时优先用 X-Forwarded-For 的第一跳。"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "-"


def current_user():
    """返回当前登录用户 {'username','role'}，未登录返回 None。"""
    username = session.get("username")
    if not username:
        return None
    return {"username": username, "role": session.get("role", auth.ROLE_VIEWER)}


def _wants_json() -> bool:
    """判断该请求应返回 JSON 还是跳转到登录页。"""
    if request.path.startswith("/api/"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


@app.before_request
def _require_login():
    endpoint = request.endpoint
    # endpoint 为 None 表示 404，交给 Flask 自己处理
    if endpoint is None or endpoint in PUBLIC_ENDPOINTS:
        return None

    user = current_user()
    if not user:
        if _wants_json():
            return jsonify({"error": "未登录", "code": "unauthenticated"}), 401
        return redirect(url_for("login", next=request.full_path.rstrip("?")))

    # 会话内的用户可能已被删除或停用 —— 每次请求校验一次，
    # 否则被停用的账号在会话过期前还能继续操作。
    stored = auth.load_users().get(user["username"])
    if not stored or stored.get("disabled"):
        session.clear()
        if _wants_json():
            return jsonify({"error": "账号已停用或不存在", "code": "unauthenticated"}), 401
        return redirect(url_for("login", notice="账号已停用，请联系管理员"))
    # 角色以磁盘上的为准，管理员改了角色立即生效，不用等对方重新登录
    session["role"] = stored.get("role", auth.ROLE_VIEWER)

    # 权限：非安全方法要求 admin
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if session["role"] != auth.ROLE_ADMIN and endpoint not in VIEWER_WRITABLE_ENDPOINTS:
            auth_logger.warning(
                f"越权尝试: user={user['username']} role={session['role']} "
                f"{request.method} {request.path}")
            if _wants_json():
                return jsonify({"error": "该操作需要管理员权限", "code": "forbidden"}), 403
            abort(403)
    return None


@app.get("/login")
@app.post("/login")
def login():
    # 已登录直接回首页，避免重复登录
    if current_user() and request.method == "GET":
        return redirect(url_for("index"))

    error = None
    notice = request.args.get("notice") or None
    username = ""
    # next 只接受站内相对路径，防止被构造成 //evil.com 做开放重定向
    next_url = _safe_next(request.values.get("next"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember = request.form.get("remember") == "1"
        try:
            user = auth.authenticate(username, password, ip=_client_ip())
        except auth.AuthError as exc:
            error = str(exc)
        else:
            # 登录成功后换一个新 session，避免会话固定攻击
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session.permanent = bool(remember)
            if remember:
                app.permanent_session_lifetime = 7 * 24 * 3600
            return redirect(next_url or url_for("index"))

    return render_template(
        "login.html",
        action=url_for("login"),
        error=error,
        notice=notice,
        username=username,
        next_url=next_url,
        csrf_token="",     # SameSite=Strict 已覆盖 CSRF，此处预留字段
    ), (401 if error else 200)


def _safe_next(value):
    """
    只允许站内相对路径作为登录后的跳转目标。

    直接把用户传来的 next 塞进 redirect 会变成开放重定向：
    /login?next=//evil.com 登录后就把人送去钓鱼站了。
    """
    if not value or not isinstance(value, str):
        return ""
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return ""
    return value


@app.get("/logout")
@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login", notice="已退出登录"))


@app.get("/api/me")
def api_me():
    """当前登录用户信息，供前端决定隐藏哪些操作按钮。"""
    user = current_user() or {}
    return jsonify({
        "username": user.get("username"),
        "role": user.get("role"),
        "is_admin": user.get("role") == auth.ROLE_ADMIN,
    })


@app.get("/api/users")
def api_list_users():
    """账号列表。只读信息也仅对管理员开放 —— 用户名本身就是攻击面。"""
    if session.get("role") != auth.ROLE_ADMIN:
        return jsonify({"error": "该操作需要管理员权限", "code": "forbidden"}), 403
    return jsonify({"users": auth.list_users()})


@app.post("/api/users")
def api_create_user():
    payload = request.get_json(silent=True) or {}
    try:
        auth.create_user(
            (payload.get("username") or "").strip(),
            payload.get("password") or "",
            role=payload.get("role") or auth.ROLE_VIEWER,
        )
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "users": auth.list_users()}), 201


@app.post("/api/users/<username>/password")
def api_change_password(username):
    """
    改口令。管理员可以改任何人的；普通用户只能改自己的，且必须提供旧口令。

    注意这个端点被 before_request 的「非 GET 需要 admin」规则挡住了，
    所以要显式登记到 VIEWER_WRITABLE_ENDPOINTS 里，让 viewer 能改自己的口令。
    """
    payload = request.get_json(silent=True) or {}
    user = current_user()
    is_admin = session.get("role") == auth.ROLE_ADMIN
    if not is_admin and username != user["username"]:
        return jsonify({"error": "只能修改自己的口令"}), 403
    # 非管理员改自己的口令必须验证旧口令，否则拿到会话就能锁死账号
    if not is_admin:
        try:
            auth.authenticate(username, payload.get("old_password") or "", ip=_client_ip())
        except auth.AuthError:
            return jsonify({"error": "原口令不正确"}), 403
    try:
        auth.set_password(username, payload.get("new_password") or "")
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.post("/api/users/<username>/role")
def api_set_role(username):
    payload = request.get_json(silent=True) or {}
    try:
        auth.set_role(username, payload.get("role") or "")
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "users": auth.list_users()})


@app.delete("/api/users/<username>")
def api_delete_user(username):
    if username == (current_user() or {}).get("username"):
        return jsonify({"error": "不能删除当前登录的账号"}), 400
    try:
        auth.delete_user(username)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "users": auth.list_users()})


# viewer 可以改自己的口令（上面的端点内部再做一次身份与旧口令校验）
VIEWER_WRITABLE_ENDPOINTS.add("api_change_password")


@app.get("/")
def index():
    return send_file(os.path.join(BASE_DIR, "linkrecon_console.html"))


@app.get("/legacy")
def legacy_index():
    return send_file(os.path.join(BASE_DIR, "code.html"))


@app.get("/api/health")
def health():
    with JOBS_LOCK:
        job_count = len(JOBS)
        active_count = sum(job.get("status") in ("queued", "running") for job in JOBS.values())
    return jsonify({
        "ok": True,
        "service": "LinkRecon Flask",
        "capabilities": {
            "quick_scan_task_details": True,
            "report_brand": Reporter.BRAND_NAME,
            "keyword_judgment": KeywordDetector.MATCH_POLICY_VERSION,
            "ua_comparison": "dual-v1",
            "js_judgment": JSDetector.MATCH_POLICY_VERSION,
            "pipeline_fixes": "2026-10-13-v1",
            "proxy_fake_ip": "explicit-loopback-v1",
        },
        "time": datetime.now().isoformat(timespec="seconds"),
        "jobs": job_count,
        "active_jobs": active_count,
        "scan_roots": list(ALLOWED_SCAN_ROOTS),
        # 状态文件损坏时在这里显式暴露，别让服务「看起来一切正常」
        # 而历史记录其实已经空了。
        "state": dict(STATE_DEGRADED),
    })


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(run_quick_scan(payload))
    except TargetNotAllowed as exc:
        # 路径越界是权限问题，返回 403 而不是含糊的 400
        return jsonify({"ok": False, "error": str(exc)}), 403
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/scan/start")
def api_scan_start():
    payload = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "job": _create_job("scan", payload)})


@app.post("/api/batch/start")
def api_batch_start():
    payload = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "job": _create_job("batch", payload)})


@app.post("/api/tasks/<task_id>/start")
def api_task_start(task_id):
    try:
        return jsonify({"ok": True, "job": _create_job("task", {"task_id": task_id})})
    except TaskBusy as error:
        return jsonify({"ok": False, "error": str(error)}), 409
    except TaskNotFound as error:
        return jsonify({"ok": False, "error": str(error)}), 404


@app.get("/api/jobs/<job_id>")
def api_job(job_id):
    job = _job_snapshot(job_id)
    if not job:
        return jsonify({"ok": False, "error": "job not found"}), 404
    return jsonify({"ok": True, "job": job})


@app.get("/api/jobs")
def api_jobs():
    """返回监控页需要的任务摘要，不暴露代理口令等原始 payload。"""
    _cleanup_jobs()
    with JOBS_LOCK:
        items = []
        for job in JOBS.values():
            result = job.get("result") if isinstance(job.get("result"), dict) else {}
            summary = result.get("summary") if isinstance(result, dict) else {}
            items.append({
                "id": job.get("id"),
                "kind": job.get("kind"),
                "status": job.get("status"),
                "progress": job.get("progress", 0),
                "message": job.get("message", ""),
                "error": job.get("error", ""),
                "created_at": job.get("created_at", ""),
                "updated_at": job.get("updated_at", ""),
                "logs": copy.deepcopy((job.get("logs") or [])[-100:]),
                "summary": copy.deepcopy(summary or {}),
            })
    items.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return jsonify({"ok": True, "items": items})


@app.post("/api/upload-targets")
def api_upload_targets():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"ok": False, "error": "file is required"}), 400
    _ensure_uploads_dir()
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{_safe_upload_name(uploaded.filename)}"
    path = os.path.join(UPLOADS_DIR, filename)
    uploaded.save(path)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        if filename.lower().endswith(".csv"):
            targets = []
            for row in csv.reader(f):
                values = [str(value).strip() for value in row if str(value).strip()]
                if not values:
                    continue
                target = values[0]
                if target.lower() in ("target", "url", "目标", "扫描目标"):
                    continue
                if not target.startswith("#"):
                    targets.append(target)
        else:
            targets = [line.strip() for line in f.readlines()
                       if line.strip() and not line.strip().startswith("#")]
    return jsonify({"ok": True, "filename": filename, "path": path, "targets": targets, "count": len(targets)})


@app.post("/api/batch")
def api_batch():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(run_batch(payload))
    except TargetNotAllowed as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


def run_batch(payload, job_id=None):
    targets = payload.get("targets") or []
    if isinstance(targets, str):
        targets = [line.strip() for line in targets.splitlines() if line.strip()]
    if not targets:
        raise ValueError("targets is required")

    items = []
    # 聚合结构与合并逻辑统一交给 core.runner：
    # 原来这里手抄了一份字段列表，字段一旦和 Scanner.results 脱节就会静默漏项
    # （errors / skipped_targets 之前就完全没聚合，批量扫描全失败也看不出来）。
    aggregate = new_aggregate()
    started = datetime.now()
    total_targets = len(targets)
    for index, target in enumerate(targets, 1):
        if job_id:
            progress = 8 + int((index - 1) / max(total_targets, 1) * 74)
            _update_job(job_id, progress=progress, message=f"正在扫描 {index}/{total_targets}")
            _append_job_log(job_id, f"[{index}/{total_targets}] {target}")
        scan_payload = dict(payload)
        scan_payload["target"] = target
        scan_payload["client"] = payload.get("client") or payload.get("client_name") or "unassigned"
        scan_payload["client_id"] = payload.get("client_id") or ""
        try:
            scanned = run_scan(scan_payload, job_id=job_id, update_progress=False)
            items.append({"target": target, "ok": scanned["ok"], "summary": scanned["summary"],
                          "error": scanned.get("error") or ""})
            merge_result(aggregate, scanned["result"])
        except Exception as exc:
            items.append({"target": target, "ok": False, "error": str(exc)})
            # 单个目标失败也要进聚合结果，否则批量报告里看不到它们
            aggregate["errors"].append(f"{target}: {exc}")
            aggregate["skipped_targets"].append(target)
            if job_id:
                _append_job_log(job_id, f"[{index}/{total_targets}] 失败: {exc}")

    duration = str(datetime.now() - started).split(".")[0]
    # link_stats 不能把各次结果直接相加（去重口径会错），统一在 finalize 里重算
    finalize_aggregate(aggregate)
    if job_id:
        _update_job(job_id, progress=88, message="正在生成批量报告")
    if items:
        report_payload = dict(payload)
        report_payload["target"] = f"batch ({len(targets)} targets)"
        config = _build_config(report_payload, report_payload["target"], job_id=job_id)
        config.target_type = "batch"
        try:
            report_path = Reporter(config).generate_report(aggregate, duration)
        finally:
            _release_logger(config.logger)
        summary = _summarize(config.target, aggregate, report_path, duration)
    else:
        summary = _summarize("batch", aggregate, "", duration)

    complete = scan_complete(aggregate) and all(item["ok"] for item in items)
    return {"ok": complete, "error": "" if complete else scan_error(aggregate),
            "summary": summary, "items": items, "result": _jsonable(aggregate)}


@app.get("/api/history")
def api_history():
    # 所有读 STATE 的路由都要持锁：后台 job 随时可能 insert 历史记录，
    # 无锁的遍历/序列化会读到半更新的结构甚至抛 RuntimeError。
    _ensure_history_ids()
    return jsonify({"ok": True, "items": _state_snapshot("history")})


@app.delete("/api/history")
def api_clear_history():
    with STATE_LOCK:
        STATE["history"] = []
        _save_state()
    return jsonify({"ok": True, "items": []})


@app.delete("/api/history/<history_id>")
def api_delete_history_item(history_id):
    with STATE_LOCK:
        before = len(STATE["history"])
        STATE["history"] = [
            item for item in STATE["history"]
            if str(item.get("id")) != str(history_id)
        ]
        if len(STATE["history"]) == before:
            return jsonify({"ok": False, "error": "history record not found"}), 404
        _save_state()
        items = copy.deepcopy(STATE["history"])
    return jsonify({"ok": True, "items": items})


@app.get("/api/state")
def api_state():
    _ensure_history_ids()
    return jsonify({"ok": True, "state": _state_snapshot()})


@app.get("/api/clients")
def api_clients():
    return jsonify({"ok": True, "items": _state_snapshot("clients")})


@app.post("/api/clients")
def api_create_client():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "client name is required"}), 400
    # 查重和写入必须在同一把锁里，否则两个并发请求会建出两个同名客户
    with STATE_LOCK:
        if any(c.get("name") == name for c in STATE["clients"]):
            return jsonify({"ok": False, "error": "client already exists"}), 400
        client = {
            "id": payload.get("id") or _new_id("cli"),
            "name": name,
            "domain": (payload.get("domain") or "未设置").strip(),
            "contact": (payload.get("contact") or "--").strip(),
            "notes": (payload.get("notes") or "").strip(),
            "icon": payload.get("icon") or "C",
            "color": payload.get("color") or "accent",
            "scans": _as_int(payload.get("scans"), 0, 0, 10 ** 9),
            "threats": _as_int(payload.get("threats"), 0, 0, 10 ** 9),
            "active": _as_int(payload.get("active"), 0, 0, 10 ** 9),
            "created_at": payload.get("created_at") or _now(),
            "updated_at": _now(),
        }
        STATE["clients"].append(client)
        _save_state()
        item = dict(client)
    return jsonify({"ok": True, "item": item})


@app.put("/api/clients/<client_id>")
def api_update_client(client_id):
    payload = request.get_json(silent=True) or {}
    with STATE_LOCK:
        client = _find_by_id(STATE["clients"], client_id)
        if not client:
            return jsonify({"ok": False, "error": "client not found"}), 404
        next_name = (payload.get("name") or client.get("name") or "").strip()
        if any(c.get("name") == next_name and str(c.get("id")) != str(client_id) for c in STATE["clients"]):
            return jsonify({"ok": False, "error": "client already exists"}), 400
        for key in ("name", "domain", "contact", "notes", "icon", "color"):
            if key in payload:
                client[key] = payload.get(key)
        client["updated_at"] = _now()
        _save_state()
        item = dict(client)
    return jsonify({"ok": True, "item": item})


@app.delete("/api/clients/<client_id>")
def api_delete_client(client_id):
    with STATE_LOCK:
        before = len(STATE["clients"])
        STATE["clients"] = [c for c in STATE["clients"] if str(c.get("id")) != str(client_id)]
        if len(STATE["clients"]) == before:
            return jsonify({"ok": False, "error": "client not found"}), 404
        _save_state()
    return jsonify({"ok": True})


@app.get("/api/tasks")
def api_tasks():
    _ensure_history_ids()
    return jsonify({"ok": True, "items": _state_snapshot("tasks")})


def _create_task(payload, save=True):
    name = (payload.get("name") or "").strip()
    target = (payload.get("target") or payload.get("url") or "").strip()
    if not name or not target:
        raise ValueError("task name and target are required")
    client_id = payload.get("client_id") or ""
    if "allow_proxy_fake_ip" in payload and not isinstance(payload["allow_proxy_fake_ip"], bool):
        raise ValueError("Fake-IP 兼容开关必须为布尔值")
    with STATE_LOCK:
        client = _find_by_id(STATE["clients"], client_id) if client_id else None
        mode = payload.get("mode") if payload.get("mode") in ("fast", "standard", "deep") else STATE["settings"].get("mode", "deep")
        report_format = payload.get("report_format") or STATE["settings"].get("report_format", "html")
        if report_format not in ("txt", "html", "json", "csv"):
            report_format = "html"
        exclude = payload.get("exclude") or []
        if isinstance(exclude, str):
            exclude = [item.strip() for item in re.split(r"[\r\n,]+", exclude) if item.strip()]
        task = {
            "id": payload.get("id") or _new_id("task"),
            "name": name,
            "target": target,
            "client_id": client_id,
            "client": payload.get("client") or (client.get("name") if client else "unassigned"),
            "priority": payload.get("priority") or "normal",
            "status": payload.get("status") or "pending",
            "source": payload.get("source") or "manual",
            "mode": mode,
            # 前端清空深度输入框会传 "" / null，原来的 int() 直接 500
            "depth": _as_int(payload.get("depth"), STATE["settings"].get("depth", 3), 1, 10),
            "threads": _as_int(payload.get("threads"), STATE["settings"].get("threads", 8), 1, 64),
            "timeout": _as_int(payload.get("timeout"), STATE["settings"].get("timeout", 30), 1, 600),
            "report_format": report_format,
            "headless": bool(payload.get("headless", STATE["settings"].get("headless", False))),
            "verbose": bool(payload.get("verbose", False)),
            "js_wait": _as_int(payload.get("js_wait"), 3, 0, 60),
            "keyword_file": (payload.get("keyword_file") or "").strip(),
            "proxy": (payload.get("proxy") or STATE["settings"].get("proxy") or "").strip(),
            # 未显式选择时继承运行时默认配置，老任务也能使用新增的代理兼容选项。
            "allow_proxy_fake_ip": payload.get("allow_proxy_fake_ip"),
            "exclude": exclude,
            "output_dir": (payload.get("output_dir") or "").strip(),
            "due_at": (payload.get("due_at") or "").strip(),
            "notes": payload.get("notes") or "",
            "created_at": payload.get("created_at") or _now(),
            "updated_at": _now(),
            "report_url": payload.get("report_url") or "",
            "last_error": "",
        }
        STATE["tasks"].insert(0, task)
        if client and task["status"] in ("pending", "running"):
            client["active"] = int(client.get("active", 0) or 0) + 1
            client["updated_at"] = _now()
        if save:
            _save_state()
        item = dict(task)
    return item


@app.post("/api/tasks")
def api_create_task():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify({"ok": True, "item": _create_task(payload)})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.delete("/api/tasks/<task_id>")
def api_delete_task(task_id):
    with STATE_LOCK:
        task = _find_by_id(STATE["tasks"], task_id)
        if not task:
            return jsonify({"ok": False, "error": "task not found"}), 404
        STATE["tasks"] = [t for t in STATE["tasks"] if str(t.get("id")) != str(task_id)]
        client = _find_by_id(STATE["clients"], task.get("client_id"))
        if client:
            client["active"] = max(0, int(client.get("active", 0) or 0) - 1)
        _save_state()
    return jsonify({"ok": True})


@app.post("/api/tasks/<task_id>/run")
def api_run_task(task_id):
    try:
        return jsonify(run_task_scan(task_id))
    except TaskBusy as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409
    except TaskNotFound as exc:
        # 只有「任务真的不存在」才是 404。
        # 原来这里 except ValueError -> 404，把 run_scan 的参数校验错误
        # （target is required / 目标类型无法识别）也一并报成了「任务不存在」。
        return jsonify({"ok": False, "error": str(exc)}), 404
    except TargetNotAllowed as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    except Exception as exc:
        with STATE_LOCK:
            task = copy.deepcopy(_find_by_id(STATE["tasks"], task_id))
        return jsonify({"ok": False, "error": str(exc), "task": task}), 400


def run_task_scan(task_id, job_id=None):
    with STATE_LOCK:
        task = _find_by_id(STATE["tasks"], task_id)
        if not task:
            raise TaskNotFound(f"任务不存在: {task_id}")
        if not job_id or task.get("running_job_id") != job_id:
            task = _claim_task(task_id, job_id or _new_id("sync"))
        task["status"] = "running"
        task["updated_at"] = _now()
        _save_state()
        settings = dict(STATE["settings"])
    if job_id:
        _update_job(job_id, progress=8, message="任务已读取")
        _append_job_log(job_id, f"运行任务: {task.get('name')}")
    payload = dict(settings)
    payload.update({
        "target": task.get("target"),
        "mode": task.get("mode") or settings.get("mode"),
        "depth": task.get("depth") or settings.get("depth"),
        "threads": task.get("threads") or settings.get("threads"),
        "timeout": task.get("timeout") or settings.get("timeout"),
        "report_format": task.get("report_format") or settings.get("report_format"),
        "headless": bool(task.get("headless", settings.get("headless", False))),
        "verbose": bool(task.get("verbose", False)),
        "js_wait": task.get("js_wait", 3),
        "keyword_file": task.get("keyword_file") or "",
        "proxy": task.get("proxy") or settings.get("proxy") or "",
        "allow_proxy_fake_ip": (task.get("allow_proxy_fake_ip") if task.get("allow_proxy_fake_ip") is not None
                                else settings.get("allow_proxy_fake_ip", False)),
        "exclude": task.get("exclude") or settings.get("exclude") or [],
        "output_dir": task.get("output_dir") or "",
        "client": task.get("client"),
        "client_id": task.get("client_id"),
        "task_id": task.get("id"),
        "task_name": task.get("name"),
    })
    try:
        scanned = run_scan(payload, job_id=job_id)
        summary = scanned.get("summary", {})
        with STATE_LOCK:
            task["status"] = "done" if scanned["ok"] else "error"
            task["report_url"] = summary.get("report_url", "")
            task["last_error"] = scanned.get("error") or ""
            task["running_job_id"] = ""
            task["updated_at"] = _now()
            client = _find_by_id(STATE["clients"], task.get("client_id"))
            if client and scanned["ok"]:
                client["scans"] = int(client.get("scans", 0) or 0) + 1
                client["threats"] = int(client.get("threats", 0) or 0) + int(summary.get("high_risk", 0) or 0)
                client["active"] = max(0, int(client.get("active", 0) or 0) - 1)
                client["updated_at"] = _now()
            _save_state()
            task_view = dict(task)
        return {"ok": True, "task": task_view, **scanned}
    except Exception as exc:
        with STATE_LOCK:
            task["status"] = "error"
            task["last_error"] = str(exc)
            task["running_job_id"] = ""
            task["updated_at"] = _now()
            _save_state()
        raise


@app.get("/api/settings")
def api_get_settings():
    return jsonify({"ok": True, "settings": _state_snapshot("settings")})


@app.post("/api/settings")
def api_save_settings():
    payload = request.get_json(silent=True) or {}
    if "ua_mode" in payload and payload["ua_mode"] not in UA_MODES:
        return jsonify({"ok": False, "error": "UA 模式必须是 dual、browser 或 baidu"}), 400
    with STATE_LOCK:
        settings = dict(STATE["settings"])
        for key in DEFAULT_SETTINGS:
            if key in payload:
                settings[key] = payload[key]
        if not isinstance(settings.get("allow_proxy_fake_ip"), bool):
            return jsonify({"ok": False, "error": "Fake-IP 兼容开关必须为布尔值"}), 400
        if settings["allow_proxy_fake_ip"]:
            try:
                validate_fake_ip_proxy(settings.get("proxy"))
            except ValueError as error:
                return jsonify({"ok": False, "error": str(error)}), 400
        # 数值型设置统一钳制，避免把 depth="" / threads=99999 存进状态文件后
        # 每一次后续扫描都要在 _build_config 里踩一遍。
        settings["depth"] = _as_int(settings.get("depth"), DEFAULT_SETTINGS["depth"], 1, 10)
        settings["threads"] = _as_int(settings.get("threads"), DEFAULT_SETTINGS["threads"], 1, 64)
        settings["timeout"] = _as_int(settings.get("timeout"), DEFAULT_SETTINGS["timeout"], 1, 600)
        STATE["settings"] = settings
        _save_state()
        result = dict(settings)
    return jsonify({"ok": True, "settings": result})


def _resolve_keyword_file(raw):
    """把关键字文件路径限制在扫描根目录白名单内。

    keyword_file 同样是「调用方传路径、服务端读文件」，
    不校验的话它就是 P1-23 那条任意文件读取路径的另一个入口。
    """
    keyword_file = (raw or "").strip()
    if not keyword_file:
        return os.path.join(BASE_DIR, "keywords_example.txt")
    if not os.path.isabs(keyword_file):
        keyword_file = os.path.join(BASE_DIR, keyword_file)
    if not _is_within_allowed_roots(keyword_file):
        raise TargetNotAllowed(f"关键字文件不在允许的目录内，已拒绝：{raw}")
    return os.path.realpath(keyword_file)


@app.get("/api/keywords")
def api_keywords():
    try:
        keyword_file = _resolve_keyword_file(request.args.get("keyword_file"))
    except TargetNotAllowed as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    detector = KeywordDetector(Config())
    loaded = detector.load_keywords(keyword_file) if os.path.exists(keyword_file) else False
    stats = detector.get_keyword_statistics() if loaded else {"total_keywords": 0, "by_category": {}}
    return jsonify({
        "ok": loaded,
        "keyword_file": keyword_file,
        "stats": stats,
        "error": "" if loaded else "keyword file not found or failed to load",
    })


@app.post("/api/keyword-detect")
def api_keyword_detect():
    payload = request.get_json(silent=True) or {}
    source = payload.get("source") or "manual"
    content = payload.get("content") or ""
    if payload.get("url"):
        with STATE_LOCK:
            settings = dict(STATE["settings"])
        try:
            proxy, fake_ip = _proxy_options(payload, settings)
        except ValueError as error:
            return jsonify({"ok": False, "error": str(error)}), 400
        fetch_errors = []
        fetched = fetch_url_content(payload.get("url"),
            proxies={"http": proxy, "https": proxy} if proxy else None,
            allow_proxy_fake_ip=fake_ip, error_callback=fetch_errors.append)
        if fetched is None:
            error = fetch_errors[-1] if fetch_errors else {"code": "request_failed", "message": "请求失败，未获得响应"}
            return jsonify({"ok": False, "error": error["message"], "error_code": error["code"]}), 502
        content = fetched[0] if isinstance(fetched, tuple) else (fetched or "")
        source = payload.get("url")
    if not content:
        return jsonify({"ok": False, "error": "content or url is required"}), 400

    detector = KeywordDetector(Config())
    try:
        keyword_file = _resolve_keyword_file(payload.get("keyword_file"))
    except TargetNotAllowed as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    if os.path.exists(keyword_file):
        detector.load_keywords(keyword_file)
    for item in payload.get("keywords", []) or []:
        if isinstance(item, dict):
            # weight 走 _as_int：前端传 "" / "high" 时原来的 int() 会 500
            detector.add_keyword(
                item.get("keyword", ""),
                item.get("category", "other"),
                _as_int(item.get("weight"), 5, 1, 10),
            )
        else:
            detector.add_keyword(str(item), "other", 5)
    matches = detector.detect(content, source)
    by_category = {}
    for match in matches:
        category = match.get("category") or "other"
        by_category[category] = by_category.get(category, 0) + 1
    return jsonify({
        "ok": True,
        "source": source,
        "total": len(matches),
        "by_category": by_category,
        "items": _jsonable(matches),
    })


@app.get("/api/reports")
def api_reports():
    _ensure_reports_dir()
    files = []
    for root, _, names in os.walk(REPORTS_DIR):
        for name in names:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, REPORTS_DIR).replace("\\", "/")
            files.append(
                {
                    "name": rel,
                    "size": os.path.getsize(path),
                    "modified": datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S"),
                    "url": f"/reports/{rel}",
                }
            )
    files.sort(key=lambda item: item["modified"], reverse=True)
    return jsonify({"ok": True, "items": files})


@app.get("/reports/<path:filename>")
def reports(filename):
    _ensure_reports_dir()
    path = os.path.join(REPORTS_DIR, filename)
    # 改用 realpath + commonpath 校验：原来的 abspath 前缀比较
    # 不会解析软链接，reports/ 下一条指向 /etc 的软链接就能读出目录外的文件。
    if not _path_within(path, REPORTS_DIR):
        abort(404)
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        abort(404)
    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=False)


_load_state()
_recover_interrupted_tasks()


if __name__ == "__main__":
    # 首次启动若一个账号都没有，自动创建管理员并把随机初始口令打印出来。
    # 刻意不用 admin/admin 这类固定默认口令 —— 那等于没有登录。
    # 这个口令只在这里打印一次，不写日志文件。
    bootstrap = auth.ensure_bootstrap_admin()
    if bootstrap:
        name, pwd = bootstrap
        line = "=" * 64
        print(f"\n{line}")
        print("  首次启动：已创建初始管理员账号")
        print(f"    用户名: {name}")
        print(f"    口  令: {pwd}")
        print("  请立即登录并修改口令。此口令只显示这一次。")
        print("  账号管理：python -m core.auth --help")
        print(f"{line}\n")

    port = int(os.environ.get("PORT", "5000"))
    print(f"控制台地址: http://127.0.0.1:{port}/")
    app.run(host="127.0.0.1", port=port, debug=False)
