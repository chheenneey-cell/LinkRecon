#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LinkRecon - 专业暗链扫描工具（CLI 主入口）
"""

import os
from utils.report_paths import new_report_path
import sys
import argparse
import logging
from datetime import datetime

# 添加项目根目录到 Python 搜索路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
_local_sp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'site-packages')
if os.path.isdir(_local_sp):
    sys.path.insert(0, _local_sp)

from utils.logging_utils import setup_logging, log_config, log_summary
from core.config import Config
from core.runner import (
    detect_target_type,
    read_target_list,
    new_aggregate,
    merge_result,
    run_target,
)
from core.reporter import Reporter

# 退出码约定（便于 CI / 定时任务判断）
EXIT_OK = 0            # 扫描完成，未发现达到风险门槛的问题
EXIT_FINDINGS = 1      # 扫描完成，发现问题
EXIT_ERROR = 2         # 参数错误，或扫描过程中出错


def parse_arguments():
    """解析命令行参数"""
    description = '''LinkRecon - 专业暗链扫描工具

    用于检测网站、HTML 文件或目录中的可疑暗链、隐藏元素和恶意代码。
    自动识别扫描目标类型（本地文件/目录、内网 URL、公网 URL），并应用相应的扫描策略。

    主要功能：
    - 基础检测：HTML 代码、JavaScript 代码、CSS 代码、元标签、注释扫描
    - 高级检测：加密编码链接、DOM 操作、iframe 内容
    - 特殊隐藏手法：颜色隐藏、绝对定位隐藏、零宽字符隐藏、字体大小隐藏等
    - 关键字匹配：支持自定义关键字文件，按类别与风险权重组织
    - 多格式报告：txt / html / json / csv
    '''

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # 扫描目标。
    # nargs='?' —— 允许只给 --target-file 而不给位置参数。
    # 原实现把 target 定义为必需位置参数，导致 README 里
    # `LinkRecon.py --target-file targets.txt` 的用法必然报
    # "the following arguments are required: target"。
    parser.add_argument('target', nargs='?', default=None,
                        help='扫描目标：文件路径、目录路径或 URL（支持 http/https）。'
                             '与 --target-file 二选一')
    parser.add_argument('--target-file',
                        help='批量目标列表文件，每行一个目标（URL / 文件 / 目录）')

    # 扫描配置
    parser.add_argument('-d', '--depth', type=int, default=3,
                        help='递归扫描深度（默认 3，0 表示仅扫描当前文件/目录）')
    parser.add_argument('-m', '--mode', choices=['fast', 'standard', 'deep'], default='deep',
                        help='扫描模式：\n'
                             'fast     —— 仅检测基础暗链与明显可疑元素，速度最快\n'
                             'standard —— 增加 JS/HTML/CSS 分析与隐藏元素检测\n'
                             'deep     —— 执行全部检测模块，适合深度审计（默认）')
    parser.add_argument('-t', '--threads', type=int, default=8,
                        help='并发线程数（默认 8，范围 1-100）')
    parser.add_argument('-o', '--output',
                        help='报告输出目录（默认 ./reports）')
    parser.add_argument('-f', '--format', choices=['txt', 'html', 'json', 'csv'], default='txt',
                        help='报告格式（默认 txt）：\n'
                             'txt  —— 简洁文本报告\n'
                             'html —— 网页报告，含样式与表格\n'
                             'json —— 结构化数据，适合自动化集成\n'
                             'csv  —— 表格数据，适合导入电子表格分析')

    # 网络配置
    parser.add_argument('--timeout', type=int, default=30,
                        help='请求超时时间（秒，默认 30，内网与公网统一生效）')
    parser.add_argument('--proxy',
                        help='代理设置，格式：http://host:port 或 http://user:pass@host:port')
    parser.add_argument('--allow-proxy-fake-ip', action='store_true',
                        help='允许受信任本地 HTTP/HTTPS/SOCKS5H 代理处理域名 Fake-IP（默认关闭）')
    parser.add_argument('--ua-mode', choices=['dual', 'browser', 'baidu'], default='dual',
                        help='请求身份：dual 普通浏览器/百度爬虫双视角（默认），或指定单视角')
    parser.add_argument('--user-agent',
                        help='覆盖普通浏览器 UA；不改变百度爬虫 UA')

    # 高级配置
    parser.add_argument('--keyword-file',
                        help='自定义关键字文件路径（CSV 格式：关键字,类别,风险权重）。'
                             '类别可选 gambling/porn/malware/phishing/other，权重 1-10')
    parser.add_argument('--exclude', nargs='+',
                        help='排除的文件或目录（支持通配符，如 "*.log" "node_modules"）')
    parser.add_argument('--no-color', action='store_true',
                        help='禁用彩色输出（适用于自动化脚本与日志采集）')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='显示详细日志信息，包含检测过程与调试内容')

    # 无头浏览器选项
    parser.add_argument('--headless', action='store_true',
                        help='启用无头浏览器扫描（增强动态内容检测）')
    parser.add_argument('--browser-type', choices=['chrome'], default='chrome',
                        help='无头浏览器类型（默认 chrome）')
    parser.add_argument('--js-wait', type=int, default=3,
                        help='JavaScript 执行等待时间（秒，默认 3）')
    parser.add_argument('--headless-timeout', type=int, default=60,
                        help='无头浏览器超时时间（秒，默认 60）')
    parser.add_argument('--headless-binary',
                        help=r'Chrome 二进制路径，例如 C:\Program Files\Google\Chrome\Application\chrome.exe')
    parser.add_argument('--headless-driver',
                        help=r'ChromeDriver 路径，例如 C:\drivers\chromedriver.exe')

    parser.epilog = r'''
使用示例：
  # 扫描单个 HTML 文件
  python LinkRecon.py test.html

  # 扫描目录及其子目录（深度 2）
  python LinkRecon.py ./website -d 2

  # 扫描 URL，使用标准模式，保存为 HTML 报告
  python LinkRecon.py https://example.com -m standard -f html

  # 使用自定义关键字文件，禁用彩色输出
  python LinkRecon.py ./website --keyword-file custom_keywords.txt --no-color

  # 对内网站点深度扫描，使用较长超时
  python LinkRecon.py http://192.168.1.100 -d 4 -m deep --timeout 60 -f html -o intranet_reports

  # 扫描时排除特定文件类型
  python LinkRecon.py ./website --exclude "*.log" "temp" "node_modules"

  # 使用无头浏览器增强扫描动态内容
  python LinkRecon.py https://example.com --headless --js-wait 5

  # 批量扫描（两种写法等价）
  python LinkRecon.py --target-file targets.txt -m deep -f html -o reports
  python LinkRecon.py targets.txt -m deep -f html -o reports

退出码：
  0  扫描完成，未发现达到风险门槛的问题
  1  扫描完成，发现问题
  2  参数错误，或扫描过程中出错
'''
    return parser.parse_args()


def _err(msg: str) -> None:
    """错误信息统一走 stderr，避免和正常输出混在一起（--no-color 场景尤其重要）"""
    print(f"错误：{msg}", file=sys.stderr)


def validate_arguments(args) -> bool:
    """验证命令行参数"""
    # target 与 --target-file 至少给一个
    if not args.target and not args.target_file:
        _err("必须指定扫描目标（位置参数 target）或 --target-file 目标列表文件")
        return False

    if args.target and not args.target.startswith(('http://', 'https://')):
        if not os.path.exists(args.target):
            _err(f"目标 '{args.target}' 不存在")
            return False
        if args.target.lower().endswith('.txt') and os.path.isfile(args.target):
            targets, read_err = read_target_list(args.target)
            if read_err:
                _err(f"无法读取目标列表文件：{read_err}")
                return False
            if not targets:
                _err("目标列表文件为空")
                return False

    if args.keyword_file and not os.path.exists(args.keyword_file):
        _err(f"关键字文件 '{args.keyword_file}' 不存在")
        return False

    if args.target_file and not os.path.exists(args.target_file):
        _err(f"目标列表文件 '{args.target_file}' 不存在")
        return False

    if args.threads < 1 or args.threads > 100:
        _err("线程数必须在 1-100 之间")
        return False

    if args.depth < 0:
        _err("扫描深度不能为负数")
        return False

    if args.timeout < 1:
        _err("超时时间必须大于 0")
        return False

    if args.allow_proxy_fake_ip:
        from utils.network_policy import validate_fake_ip_proxy
        try:
            validate_fake_ip_proxy(args.proxy)
        except ValueError as error:
            _err(str(error))
            return False

    return True


def build_config(args, report_dir: str, logger) -> Config:
    """根据命令行参数构造 Config"""
    config = Config()

    config.target = args.target
    config.target_type = detect_target_type(args.target) if args.target else 'unknown'
    config.depth = args.depth      # depth 是 crawl_depth 的 property 别名
    config.mode = args.mode        # mode 是 scan_mode 的 property 别名，赋值会同步刷新模式开关

    config.threads = args.threads
    config.timeout = args.timeout
    # --timeout 必须真正生效。Config 里 internal_timeout / external_timeout 有默认值，
    # 而 Scanner 会无条件用它们覆盖 self.timeout，导致 --timeout 对 URL 目标完全无效。
    config.external_timeout = args.timeout
    config.internal_timeout = args.timeout

    config.proxy = args.proxy
    config.allow_proxy_fake_ip = args.allow_proxy_fake_ip
    config.ua_mode = args.ua_mode
    config.browser_user_agent = args.user_agent
    config.keywords_file = args.keyword_file
    config.exclude = args.exclude or []
    config.report_type = args.format
    config.report_file = new_report_path(report_dir, args.format)
    config.debug = args.verbose
    config.no_color = args.no_color
    config.logger = logger

    # 无头浏览器配置
    config.use_headless_browser = args.headless
    config.headless_browser = args.browser_type
    config.js_wait_time = args.js_wait
    config.headless_timeout = args.headless_timeout
    config.headless_binary = args.headless_binary
    config.headless_driver_path = args.headless_driver
    if args.headless:
        config.headless_auto_download = True

    return config


def resolve_targets(args):
    """
    解析出本次要扫描的目标列表。

    Returns:
        (targets, summary_target, error)
    """
    if args.target_file:
        targets, err = read_target_list(args.target_file)
        if err:
            return [], '', err
        return targets, f"目标列表: {args.target_file} ({len(targets)} 项)", None

    if (args.target
            and not args.target.startswith(('http://', 'https://'))
            and args.target.lower().endswith('.txt')
            and os.path.isfile(args.target)):
        targets, err = read_target_list(args.target)
        if err:
            return [], '', err
        return targets, f"目标列表: {args.target} ({len(targets)} 项)", None

    return [args.target], args.target, None


def main():
    args = parse_arguments()

    if not validate_arguments(args):
        sys.exit(EXIT_ERROR)

    report_dir = args.output or os.path.join(os.getcwd(), 'reports')
    try:
        os.makedirs(report_dir, exist_ok=True)
    except OSError as e:
        _err(f"无法创建报告目录 '{report_dir}': {e}")
        sys.exit(EXIT_ERROR)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(log_dir=report_dir, level=log_level)

    start_time = datetime.now()
    config = build_config(args, report_dir, logger)
    log_config(logger, config.get_config_dict())

    targets, summary_target, err = resolve_targets(args)
    if err:
        _err(f"读取目标列表失败：{err}")
        sys.exit(EXIT_ERROR)

    logger.info(f"开始扫描：{summary_target}")
    logger.info(f"扫描模式：{args.mode}")

    agg = new_aggregate()
    try:
        for tgt in targets:
            target_type = detect_target_type(tgt)
            if target_type == 'unknown':
                # 原实现在这里直接 continue：拼错的目标、Windows 路径在 Linux 上跑，
                # 全部无声消失，而报告仍然显示"共 N 项"。
                logger.warning(f"无法识别的扫描目标，已跳过：{tgt}")
                agg['skipped_targets'].append(tgt)
                continue

            config.target = tgt
            config.target_type = target_type
            merge_result(agg, run_target(config))

        end_time = datetime.now()
        duration = str(end_time - start_time)

        config.target = summary_target
        reporter = Reporter(config)
        report_file = reporter.generate_report(agg, duration)

        log_summary(
            logger,
            total_files=agg.get('total_files', 0),
            scanned_files=agg.get('scanned_files', 0),
            issues_found=agg.get('total_issues', 0),
            scan_time=(end_time - start_time).total_seconds(),
        )

        if agg['skipped_targets']:
            print(f"提示：{len(agg['skipped_targets'])} 个目标无法识别已跳过，详见日志",
                  file=sys.stderr)

        logger.info(f"扫描完成，报告已保存至：{report_file}")
        print(f"\n扫描完成，报告已保存至：{report_file}")
        print(f"共扫描 {agg.get('scanned_files', 0)} 个文件 / "
              f"{agg.get('scanned_urls', 0)} 个 URL，发现 {agg.get('total_issues', 0)} 个问题")

        # Scanner 内部会吞掉异常并照常返回空结果，所以不能只看有没有抛异常。
        # 这里根据 errors / total_issues 给出可供自动化判断的退出码。
        if agg['errors']:
            for msg in agg['errors'][:10]:
                print(f"扫描过程中出现错误：{msg}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        sys.exit(EXIT_FINDINGS if agg.get('total_issues', 0) > 0 else EXIT_OK)

    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"扫描过程中发生错误：{str(e)}", exc_info=True)
        _err(f"扫描过程中发生错误 - {str(e)}")
        sys.exit(EXIT_ERROR)


if __name__ == '__main__':
    main()
