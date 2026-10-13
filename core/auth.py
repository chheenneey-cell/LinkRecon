# -*- coding: utf-8 -*-

"""
认证与授权模块（app.py / web.py 共用）。

设计取舍：
- 用户存 `data/users.json`，与 app_state.json 同目录、同风格，不引入数据库依赖。
- 口令用 PBKDF2-HMAC-SHA256 + 每用户独立盐，只存哈希，不可逆。
  用标准库 hashlib 实现，不引入 bcrypt/argon2 等额外依赖 —— 项目自带的
  site-packages 里没有它们，加依赖会破坏"开箱即用"。
- 校验口令一律走 hmac.compare_digest，避免计时侧信道。
- 角色两档：admin（可发起扫描、改配置、管账号）/ viewer（只读报告与历史）。
  扫描器能读本地文件、能发网络请求，只读账号必须挡在这些能力之外。
- 登录失败按「用户名 + 来源 IP」计数并锁定，防在线爆破。

首次启动若没有任何账号，会自动创建一个 admin 并把随机初始口令打印到控制台
（只打印这一次），避免出现"默认 admin/admin"这种必然被打穿的口子。
"""

import os
import json
import hmac
import time
import base64
import hashlib
import logging
import secrets
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger('LinkRecon.auth')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.realpath(
    os.environ.get('LINKRECON_DATA_DIR') or os.path.join(BASE_DIR, 'data')
)
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SECRET_FILE = os.path.join(DATA_DIR, 'secret_key')

# PBKDF2 迭代次数。OWASP 对 PBKDF2-HMAC-SHA256 的建议值量级。
PBKDF2_ITERATIONS = 210_000
SALT_BYTES = 16

ROLE_ADMIN = 'admin'
ROLE_VIEWER = 'viewer'
ROLES = (ROLE_ADMIN, ROLE_VIEWER)

# 登录失败锁定策略
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

# 会话有效期（秒）
SESSION_LIFETIME_SECONDS = 8 * 3600

_LOCK = threading.RLock()
# {(username, ip): [失败次数, 首次失败时间戳]}
_FAILED_ATTEMPTS: Dict[Tuple[str, str], list] = {}


class AuthError(Exception):
    """认证相关错误的基类。"""


class AccountLocked(AuthError):
    """连续登录失败次数过多，账号在该来源 IP 上被临时锁定。"""


# ---------------------------------------------------------------------------
# 口令哈希
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: Optional[bytes] = None,
                  iterations: int = PBKDF2_ITERATIONS) -> str:
    """
    生成口令哈希，格式：pbkdf2_sha256$<迭代次数>$<盐 b64>$<哈希 b64>

    自带迭代次数和盐，将来调高迭代次数时旧哈希仍然可校验。
    """
    if not isinstance(password, str) or not password:
        raise ValueError('口令不能为空')
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return 'pbkdf2_sha256${}${}${}'.format(
        iterations,
        base64.b64encode(salt).decode('ascii'),
        base64.b64encode(digest).decode('ascii'),
    )


def verify_password(password: str, stored: str) -> bool:
    """校验口令。用 compare_digest 做定长比较，避免计时侧信道。"""
    if not password or not stored:
        return False
    try:
        algo, iter_s, salt_b64, hash_b64 = stored.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'),
            base64.b64decode(salt_b64), int(iter_s))
        return hmac.compare_digest(expected, actual)
    except Exception:
        # 存储格式损坏时一律判为失败，不要抛异常泄漏细节
        return False


def check_password_strength(password: str) -> Optional[str]:
    """
    返回不合规的原因；合规返回 None。

    只做最低限度的约束：这是内网安全工具，过度复杂的策略反而促使用户
    把口令写在便签上。
    """
    if not password or len(password) < 10:
        return '口令长度至少 10 位'
    kinds = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if kinds < 2:
        return '口令需至少包含大写字母、小写字母、数字、符号中的两类'
    if password.lower() in ('password12', 'admin12345', '1234567890', 'linkrecon12'):
        return '口令过于常见'
    return None


# ---------------------------------------------------------------------------
# 用户存储
# ---------------------------------------------------------------------------

def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _atomic_write_json(path: str, payload: dict) -> None:
    """
    原子写：写临时文件 + os.replace。

    与 app.py 的 _save_state 同样的理由 —— 直接覆盖写，进程在写一半时被杀
    就会留下一个截断的 JSON，下次启动所有账号一起消失。
    """
    _ensure_data_dir()
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)   # 只有属主可读写（Windows 上是 no-op）
    except OSError:
        pass


def load_users() -> Dict[str, dict]:
    """读取用户表；文件不存在返回空字典。"""
    with _LOCK:
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            users = data.get('users') if isinstance(data, dict) else None
            return users if isinstance(users, dict) else {}
        except Exception as e:
            logger.error(f"读取用户文件失败，将按「无账号」处理: {e}")
            return {}


def save_users(users: Dict[str, dict]) -> None:
    with _LOCK:
        _atomic_write_json(USERS_FILE, {'version': 1, 'users': users})


def create_user(username: str, password: str, role: str = ROLE_VIEWER,
                skip_strength_check: bool = False) -> None:
    """新建账号。用户名已存在时抛 AuthError。"""
    username = (username or '').strip()
    if not username:
        raise AuthError('用户名不能为空')
    if len(username) > 64:
        raise AuthError('用户名过长')
    if role not in ROLES:
        raise AuthError(f'角色必须是 {ROLES} 之一')
    if not skip_strength_check:
        reason = check_password_strength(password)
        if reason:
            raise AuthError(reason)

    with _LOCK:
        users = load_users()
        if username in users:
            raise AuthError(f"用户 '{username}' 已存在")
        users[username] = {
            'password': hash_password(password),
            'role': role,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'last_login': None,
            'disabled': False,
        }
        save_users(users)
    logger.info(f"已创建用户 {username}（角色 {role}）")


def set_password(username: str, password: str, skip_strength_check: bool = False) -> None:
    reason = None if skip_strength_check else check_password_strength(password)
    if reason:
        raise AuthError(reason)
    with _LOCK:
        users = load_users()
        if username not in users:
            raise AuthError(f"用户 '{username}' 不存在")
        users[username]['password'] = hash_password(password)
        save_users(users)
    logger.info(f"已修改用户 {username} 的口令")


def set_role(username: str, role: str) -> None:
    if role not in ROLES:
        raise AuthError(f'角色必须是 {ROLES} 之一')
    with _LOCK:
        users = load_users()
        if username not in users:
            raise AuthError(f"用户 '{username}' 不存在")
        if (users[username].get('role') == ROLE_ADMIN and role != ROLE_ADMIN
                and _count_active_admins(users) <= 1):
            raise AuthError('不能降级最后一个管理员账号')
        users[username]['role'] = role
        save_users(users)


def delete_user(username: str) -> None:
    with _LOCK:
        users = load_users()
        if username not in users:
            raise AuthError(f"用户 '{username}' 不存在")
        if users[username].get('role') == ROLE_ADMIN and _count_active_admins(users) <= 1:
            raise AuthError('不能删除最后一个管理员账号')
        del users[username]
        save_users(users)


def set_disabled(username: str, disabled: bool) -> None:
    with _LOCK:
        users = load_users()
        if username not in users:
            raise AuthError(f"用户 '{username}' 不存在")
        if (disabled and users[username].get('role') == ROLE_ADMIN
                and _count_active_admins(users) <= 1):
            raise AuthError('不能停用最后一个管理员账号')
        users[username]['disabled'] = bool(disabled)
        save_users(users)


def _count_active_admins(users: Dict[str, dict]) -> int:
    return sum(1 for u in users.values()
               if u.get('role') == ROLE_ADMIN and not u.get('disabled'))


def list_users() -> list:
    """返回用户列表（不含口令哈希），供管理界面展示。"""
    users = load_users()
    return [
        {
            'username': name,
            'role': info.get('role', ROLE_VIEWER),
            'created_at': info.get('created_at'),
            'last_login': info.get('last_login'),
            'disabled': bool(info.get('disabled')),
        }
        for name, info in sorted(users.items())
    ]


# ---------------------------------------------------------------------------
# 登录
# ---------------------------------------------------------------------------

def _attempt_key(username: str, ip: str) -> Tuple[str, str]:
    return ((username or '').lower(), ip or '-')


def is_locked_out(username: str, ip: str = '-') -> int:
    """
    返回该「用户名+IP」还需锁定多少秒；0 表示未锁定。
    """
    key = _attempt_key(username, ip)
    with _LOCK:
        entry = _FAILED_ATTEMPTS.get(key)
        if not entry:
            return 0
        count, first_ts = entry
        if count < MAX_FAILED_ATTEMPTS:
            return 0
        remaining = int(LOCKOUT_SECONDS - (time.time() - first_ts))
        if remaining <= 0:
            _FAILED_ATTEMPTS.pop(key, None)
            return 0
        return remaining


def _record_failure(username: str, ip: str) -> None:
    key = _attempt_key(username, ip)
    now = time.time()
    with _LOCK:
        entry = _FAILED_ATTEMPTS.get(key)
        if not entry or now - entry[1] > LOCKOUT_SECONDS:
            _FAILED_ATTEMPTS[key] = [1, now]
        else:
            entry[0] += 1


def _clear_failures(username: str, ip: str) -> None:
    with _LOCK:
        _FAILED_ATTEMPTS.pop(_attempt_key(username, ip), None)


def authenticate(username: str, password: str, ip: str = '-') -> dict:
    """
    校验用户名口令。成功返回用户信息（不含哈希），失败抛 AuthError。

    注意：无论「用户不存在」还是「口令错误」，对外都返回同一句提示，
    避免通过错误信息枚举出哪些用户名是有效的。
    """
    username = (username or '').strip()
    remaining = is_locked_out(username, ip)
    if remaining:
        raise AccountLocked(f'登录失败次数过多，请在 {remaining} 秒后重试')

    users = load_users()
    info = users.get(username)

    # 用户不存在时也走一次同等开销的哈希计算，让响应时间不泄漏用户是否存在
    stored = info.get('password') if info else hash_password('dummy-placeholder')
    ok = bool(info) and not info.get('disabled') and verify_password(password, stored)

    if not ok:
        _record_failure(username, ip)
        logger.warning(f"登录失败: user={username} ip={ip}")
        raise AuthError('用户名或口令错误')

    _clear_failures(username, ip)
    with _LOCK:
        users = load_users()
        if username in users:
            users[username]['last_login'] = time.strftime('%Y-%m-%d %H:%M:%S')
            save_users(users)
    logger.info(f"登录成功: user={username} role={info.get('role')} ip={ip}")
    return {'username': username, 'role': info.get('role', ROLE_VIEWER)}


# ---------------------------------------------------------------------------
# 会话密钥 / 首次启动引导
# ---------------------------------------------------------------------------

def get_or_create_secret_key() -> bytes:
    """
    读取（或首次生成并持久化）Flask session 的 SECRET_KEY。

    必须持久化：每次启动都随机生成的话，服务一重启所有人的 session 就失效，
    而且多进程部署时各进程密钥不同会导致登录状态随机丢失。
    """
    with _LOCK:
        if os.path.exists(SECRET_FILE):
            try:
                with open(SECRET_FILE, 'rb') as f:
                    key = f.read().strip()
                if len(key) >= 32:
                    return key
            except OSError as e:
                logger.error(f"读取 SECRET_KEY 失败，将重新生成: {e}")
        key = base64.urlsafe_b64encode(secrets.token_bytes(48))
        _ensure_data_dir()
        tmp = SECRET_FILE + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, SECRET_FILE)
        try:
            os.chmod(SECRET_FILE, 0o600)
        except OSError:
            pass
        logger.info(f"已生成新的会话密钥: {SECRET_FILE}")
        return key


def ensure_bootstrap_admin() -> Optional[Tuple[str, str]]:
    """
    首次启动时若一个账号都没有，创建 admin 并返回 (用户名, 随机初始口令)。
    已有账号时返回 None。

    刻意不使用 admin/admin 这类固定默认口令 —— 那等于没有登录。
    初始口令只在控制台打印这一次，请立即登录后修改。
    """
    with _LOCK:
        if load_users():
            return None
        password = secrets.token_urlsafe(12)
        create_user('admin', password, role=ROLE_ADMIN, skip_strength_check=True)
        return 'admin', password


# ---------------------------------------------------------------------------
# 命令行账号管理：python -m core.auth <子命令>
# ---------------------------------------------------------------------------

def _cli() -> int:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        prog='python -m core.auth',
        description='LinkRecon 账号管理')
    sub = parser.add_subparsers(dest='cmd')

    # --allow-weak：跳过口令强度校验。
    # 本工具常见的部署形态是「只监听 127.0.0.1、自己一个人用」，
    # 这种场景下强制 10 位以上口令反而促使人把口令写在便签上。
    # 但如果服务会被别人访问到，请不要用这个开关。
    p_add = sub.add_parser('add', help='新建账号')
    p_add.add_argument('username')
    p_add.add_argument('--role', choices=ROLES, default=ROLE_VIEWER)
    p_add.add_argument('--allow-weak', action='store_true',
                       help='跳过口令强度校验（仅建议在本机自用时使用）')
    p_add.add_argument('--password',
                       help='直接指定口令，跳过交互输入（会留在 shell 历史里，慎用）')

    p_pw = sub.add_parser('passwd', help='修改口令')
    p_pw.add_argument('username')
    p_pw.add_argument('--allow-weak', action='store_true',
                      help='跳过口令强度校验（仅建议在本机自用时使用）')
    p_pw.add_argument('--password',
                      help='直接指定口令，跳过交互输入（会留在 shell 历史里，慎用）')

    p_role = sub.add_parser('role', help='修改角色')
    p_role.add_argument('username')
    p_role.add_argument('role', choices=ROLES)

    p_del = sub.add_parser('delete', help='删除账号')
    p_del.add_argument('username')

    p_dis = sub.add_parser('disable', help='停用账号')
    p_dis.add_argument('username')
    p_en = sub.add_parser('enable', help='启用账号')
    p_en.add_argument('username')

    sub.add_parser('list', help='列出全部账号')
    sub.add_parser('init', help='首次初始化：无账号时创建 admin 并输出随机口令')

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 2

    def _get_password() -> str:
        # --password 直接给值时不再交互；否则要求输入两次确认
        if getattr(args, 'password', None):
            return args.password
        pw = getpass.getpass('新口令: ')
        if pw != getpass.getpass('再输入一次: '):
            raise AuthError('两次输入的口令不一致')
        return pw

    def _warn_if_weak(pw: str) -> None:
        if getattr(args, 'allow_weak', False):
            reason = check_password_strength(pw)
            if reason:
                print(f"警告：{reason}。已按 --allow-weak 跳过校验。")
                print("      本服务默认只监听 127.0.0.1；若会被其他人访问到，请改用强口令。")

    try:
        if args.cmd == 'add':
            pw = _get_password()
            _warn_if_weak(pw)
            create_user(args.username, pw, role=args.role,
                        skip_strength_check=args.allow_weak)
            print(f"已创建 {args.username}（{args.role}）")
        elif args.cmd == 'passwd':
            pw = _get_password()
            _warn_if_weak(pw)
            set_password(args.username, pw, skip_strength_check=args.allow_weak)
            print(f"已修改 {args.username} 的口令")
        elif args.cmd == 'role':
            set_role(args.username, args.role)
            print(f"{args.username} 的角色已改为 {args.role}")
        elif args.cmd == 'delete':
            delete_user(args.username)
            print(f"已删除 {args.username}")
        elif args.cmd in ('disable', 'enable'):
            set_disabled(args.username, args.cmd == 'disable')
            print(f"{args.username} 已{'停用' if args.cmd == 'disable' else '启用'}")
        elif args.cmd == 'list':
            rows = list_users()
            if not rows:
                print('（暂无账号）')
            else:
                print(f"{'用户名':<20}{'角色':<10}{'状态':<8}{'最后登录'}")
                for r in rows:
                    print(f"{r['username']:<20}{r['role']:<10}"
                          f"{'停用' if r['disabled'] else '正常':<8}{r['last_login'] or '-'}")
        elif args.cmd == 'init':
            created = ensure_bootstrap_admin()
            if created:
                print(f"已创建初始管理员 {created[0]}，初始口令：{created[1]}")
                print('请立即登录并修改口令。此口令只显示这一次。')
            else:
                print('已存在账号，无需初始化。')
    except AuthError as e:
        print(f"错误：{e}")
        return 1
    return 0


if __name__ == '__main__':
    import sys
    sys.path.insert(0, BASE_DIR)
    raise SystemExit(_cli())
