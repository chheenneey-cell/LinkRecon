# -*- coding: utf-8 -*-

"""
报告生成器模块
"""

import os
import json
import csv
import logging
from datetime import datetime
from urllib.parse import urlparse
from utils.common_utils import normalize_risk
from utils.finding_policy import is_reportable, issue_count, unique_findings
from utils.scan_outcome import scan_complete
from utils.link_utils import summarize_link_inventory
from utils.ua_reporting import UA_COLUMNS, comparison_rows

# 进入报告的风险门槛（归一化后的 1-5 量纲），与 core.scanner 保持一致
RISK_REPORT_THRESHOLD = 4

# 报告里允许渲染成可点击链接的协议。
# 其余（javascript:/data:/vbscript: 等）只作为纯文本展示——扫描结果本身
# 就来自不可信页面，不能让分析人员点一下就被反打。
_SAFE_LINK_SCHEMES = {'http', 'https'}


def _safe_href(url) -> str:
    """
    返回可安全放进 href 的值；协议不在白名单内时返回空串（调用方应改为纯文本展示）。
    """
    try:
        scheme = (urlparse(str(url)).scheme or '').lower()
    except Exception:
        return ''
    return _escape_html(url) if scheme in _SAFE_LINK_SCHEMES else ''


def _escape_html(s: str) -> str:
    if s is None:
        return ''
    return (
        str(s)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
    )
from typing import Dict, List

logger = logging.getLogger('LinkRecon.reporter')

class Reporter:
    """报告生成器类"""
    BRAND_NAME = 'LinkRecon'
    
    def __init__(self, config):
        self.config = config

    @staticmethod
    def _behavior_rows(results):
        return [item for item in unique_findings(results, ('js_issues', 'css_issues', 'hidden_elements'))
                if is_reportable(item) or item.get('assessment') == 'needs_review']
    
    def generate_report(self, results: Dict, duration):
        """生成报告"""
        try:
            report_dir = os.path.dirname(self.config.report_file)
            if report_dir and not os.path.exists(report_dir):
                os.makedirs(report_dir, exist_ok=True)
            
            if self.config.report_type == 'txt':
                self._generate_text_report(results, duration)
            elif self.config.report_type == 'html':
                self._generate_html_report(results, duration)
            elif self.config.report_type == 'json':
                self._generate_json_report(results, duration)
            elif self.config.report_type == 'csv':
                self._generate_csv_report(results, duration)
            else:
                raise ValueError(f"不支持的报告类型: {self.config.report_type}")
                
            logger.info(f"报告已成功生成: {self.config.report_file}")
            return self.config.report_file  # 返回报告文件路径
            
        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}", exc_info=True)
            raise
    
    def _generate_text_report(self, results: Dict, duration):
        """生成文本报告"""
        link_stats = summarize_link_inventory(results.get('link_inventory', []), results.get('suspicious_links', []))
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            f.write("========================================\n")
            f.write("         LinkRecon - 暗链扫描报告\n")
            f.write("========================================\n\n")
            
            # 基本信息
            f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描目标: {self.config.target}\n")
            f.write(f"扫描模式: {self.config.scan_mode}\n")
            f.write(f"扫描耗时: {duration}\n")
            f.write(f"扫描文件数: {results.get('scanned_files', 0)}\n")
            f.write(f"扫描URL数: {results.get('scanned_urls', 0)}\n\n")
            
            # 扫描结果概览
            f.write("----------------------------------------\n")
            f.write("扫描结果概览\n")
            f.write("----------------------------------------\n")
            f.write(f"链接总数: {link_stats.get('link_total', 0)}\n")
            f.write(f"唯一链接: {link_stats.get('unique_links', 0)}\n")
            f.write(f"隐藏链接: {link_stats.get('hidden_links', 0)}\n")
            f.write(f"可疑唯一链接: {link_stats.get('suspicious_unique_links', 0)}\n")
            f.write(f"风险命中数: {link_stats.get('suspicious_hits', len(results.get('suspicious_links', [])))}\n")
            f.write(f"发现关键字匹配: {len(results.get('keyword_matches', []))}\n\n")
            if not scan_complete(results):
                f.write("扫描不完整：不能据此给出安全结论。\n")
                for error in results.get('errors', []):
                    f.write(f"检测错误: {error}\n")
            f.write(f"去重高风险证据数: {issue_count(results)}\n\n")
            f.write(f"其中待复核: {sum(m.get('assessment') == 'needs_review' for m in results.get('keyword_matches', []))}\n\n")
            ua_rows = comparison_rows(results.get('ua_comparisons', []))
            if ua_rows:
                f.write("UA 视角对照（差异不等于确认暗链）\n")
                for row in ua_rows:
                    for label, value in zip(UA_COLUMNS, row):
                        f.write(f"{label}: {value}\n")
                    f.write("\n")
            
            # 可疑链接详情
            if results.get('suspicious_links', []):
                f.write("----------------------------------------\n")
                f.write("可疑链接详情\n")
                f.write("----------------------------------------\n\n")
                
                for i, link in enumerate(results['suspicious_links'], 1):
                    link_val = link.get('link') or link.get('url', 'N/A')
                    source_val = link.get('source') or link.get('file_path', 'N/A')
                    f.write(f"[{i}] 链接: {link_val}\n")
                    f.write(f"    来源: {source_val}\n")
                    f.write(f"    类型: {link.get('type', 'N/A')}\n")
                    f.write(f"    检测方式: {link.get('detection_method', 'N/A')}\n")
                    f.write(f"    风险等级: {link.get('risk_level', 'N/A')}\n")
                    if 'context' in link:
                        f.write(f"    上下文: {link['context'][:100]}...\n")
                    f.write("\n")
            
            # 关键字匹配详情
            if results.get('keyword_matches', []):
                f.write("----------------------------------------\n")
                f.write("关键字匹配详情\n")
                f.write("----------------------------------------\n\n")
                
                for i, match in enumerate(results['keyword_matches'], 1):
                    f.write(f"[{i}] 关键字: {match.get('keyword', 'N/A')}\n")
                    f.write(f"    类别: {match.get('category', 'N/A')}\n")
                    f.write(f"    风险权重: {match.get('weight', 'N/A')}\n")
                    f.write(f"    规则原始权重: {match.get('rule_weight', match.get('weight', 'N/A'))}\n")
                    f.write(f"    判定依据: {match.get('reason', '关键词命中，需结合上下文复核')}\n")
                    f.write(f"    来源: {match.get('source', 'N/A')}\n")
                    if 'context' in match:
                        f.write(f"    上下文: {match['context'][:100]}...\n")
                    f.write("\n")
            
            behavior_rows = self._behavior_rows(results)
            if behavior_rows:
                f.write("行为证据与待复核项（结构评分 1-5，不代表确认恶意）\n")
                for item in behavior_rows:
                    f.write(f"{item.get('behavior') or item.get('type')}: "
                            f"{item.get('assessment', 'risk_finding')}\n")
                    f.write(f"来源: {item.get('source') or item.get('file_path', '')}\n")
                    f.write(f"依据: {item.get('reason') or item.get('description', '')}\n")
                    f.write(f"证据: {json.dumps(item.get('evidence', {}), ensure_ascii=False)}\n")
                    f.write(f"上下文: {item.get('context', '')}\n\n")
            # 总结和建议
            f.write("========================================\n")
            f.write("总结与建议\n")
            f.write("========================================\n\n")
            
            if not scan_complete(results):
                f.write("扫描不完整，请处理检测错误后重新扫描，已有发现仅供复核。\n")
            elif issue_count(results):
                f.write("发现潜在的安全问题，请进行以下操作：\n\n")
                f.write("1. 审查所有可疑链接，确认其合法性\n")
                f.write("2. 分析关键字匹配结果，检查相关内容\n")
                f.write("3. 移除或修复发现的暗链\n")
                f.write("4. 加强网站安全措施，防止再次被植入暗链\n")
                f.write("5. 定期使用 LinkRecon 工具进行扫描\n")
            else:
                f.write("未发现明显的暗链问题。建议继续保持警惕，定期进行扫描。\n")
    
    def _generate_html_report(self, results: Dict, duration):
        """生成HTML报告"""
        # 读取对应的log文件内容
        log_content = self._read_log_file()
        review_count = sum(m.get('assessment') == 'needs_review' for m in results.get('keyword_matches', []))
        link_stats = summarize_link_inventory(results.get('link_inventory', []), results.get('suspicious_links', []))
        
        
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkRecon - 暗链扫描报告</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .header {{
            background-color: #3498db;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .section {{
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .table-container {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .risk-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .risk-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .risk-low {{
            color: #3498db;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .context {{
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .log-container {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 400px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>LinkRecon - 暗链扫描报告</h1>
    </div>
    
    <div class="summary">
        <h2>扫描概览</h2>
        <p><strong>扫描时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>扫描目标:</strong> {_escape_html(self.config.target)}</p>
        <p><strong>扫描模式:</strong> {_escape_html(self.config.scan_mode)}</p>
        <p><strong>扫描耗时:</strong> {duration}</p>
        <p><strong>扫描文件数:</strong> {results.get('scanned_files', 0)}</p>
        <p><strong>扫描URL数:</strong> {results.get('scanned_urls', 0)}</p>
        
        <h3>结果统计</h3>
        <p><strong>发现可疑链接:</strong> <span class="risk-high">{link_stats.get('suspicious_unique_links', 0)}</span></p>
        <p><strong>发现关键字匹配:</strong> {len(results.get('keyword_matches', []))}（其中待复核：{review_count}）</p>
        <p><strong>去重高风险证据数:</strong> {issue_count(results)}</p>
    </div>
"""
        
        if not scan_complete(results):
            html_content += '<div class="section"><h2>扫描不完整</h2><p>不能据此给出安全结论，请处理以下错误后重新扫描。</p><ul>'
            html_content += ''.join('<li>' + _escape_html(error) + '</li>' for error in results.get('errors', []))
            html_content += '</ul></div>'
        ua_rows = comparison_rows(results.get('ua_comparisons', []))
        if ua_rows:
            html_content += '<div class="section"><h2>UA 视角对照</h2>'
            html_content += '<p>响应差异仅供复核，不等于确认暗链；模拟 UA 不具有搜索爬虫 IP 身份。</p>'
            html_content += '<div class="table-container"><table><thead><tr>'
            html_content += ''.join('<th>' + _escape_html(label) + '</th>' for label in UA_COLUMNS)
            html_content += '</tr></thead><tbody>'
            for row in ua_rows:
                html_content += '<tr>' + ''.join('<td>' + _escape_html(value).replace('\n', '<br>') + '</td>' for value in row) + '</tr>'
            html_content += '</tbody></table></div></div>'

        # 添加可疑链接表格
        if results.get('suspicious_links', []):
            html_content += """
    <div class="section">
        <h2>可疑链接详情</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>序号</th>
                        <th>链接</th>
                        <th>来源</th>
                        <th>来源类型</th>
                        <th>类型</th>
                        <th>检测方式</th>
                        <th>风险等级</th>
                        <th>位置</th>
                        <th>上下文</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            # 读取日志内容以提取问题详情
            log_content = self._read_log_file()
            suspicious_link_details = []
            if log_content:
                # 从日志中提取可疑链接信息
                import re
                for line in log_content.split('\n'):
                    if '找到可疑链接:' in line:
                        # 使用正则表达式提取完整的URL
                        url_pattern = r'https?://[^\s]+'
                        matches = re.findall(url_pattern, line)
                        if matches:
                            suspicious_link_details.append(matches[0])
            
            # 统一走 normalize_risk。原实现把 '高' 折算成 3，而过滤门槛是 >=4，
            # 结果 SpecialHidingDetector 报出的全部发现（零宽字符、颜色隐藏、
            # 绝对定位隐藏……）在报告里一条都不显示。
            _risk_value = normalize_risk
            filtered_links = list(unique_findings(results, ('suspicious_links',), reportable_only=True))
            sorted_links = sorted(filtered_links, key=lambda x: _risk_value(x.get('risk_level')), reverse=True)
            for i, link in enumerate(sorted_links, 1):
                risk_class = self._get_risk_class(link.get('risk_level', ''))
                # 获取问题详情，如果有日志中的信息就使用
                context_info = (link.get('context', '')[:100] + '...') if link.get('context') else ''
                # 优先显示规范URL；无URL时展示动态表达式短摘
                display_value = link.get('link') or link.get('url')
                if not display_value and link.get('expression'):
                    display_value = (link['expression'][:100] + '...')
                link_val = _escape_html(display_value or 'N/A')
                source_val = _escape_html(link.get('source') or link.get('file_path', 'N/A'))
                source_type_val = _escape_html(link.get('context_type', 'N/A'))
                if suspicious_link_details:
                    # 仅在日志中有完全匹配的链接时使用日志上下文
                    for detail in suspicious_link_details:
                        if link_val and detail and link_val in detail:
                            context_info = f"从日志中检测到: {_escape_html(detail)}"
                            break
                
                pos = link.get('position')
                pos_display = _escape_html(f"{pos[0]}-{pos[1]}" if isinstance(pos, (list, tuple)) and len(pos) == 2 else 'N/A')
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{link_val}</td>
                        <td>{source_val}</td>
                        <td>{source_type_val}</td>
                        <td>{_escape_html(link.get('type', 'N/A'))}</td>
                        <td>{_escape_html(link.get('detection_method', 'N/A'))}</td>
                        <td class="{risk_class}">{link.get('risk_level', 'N/A')}</td>
                        <td>{pos_display}</td>
                        <td><div class="context">{_escape_html(context_info)}</div></td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
"""
        
        # 添加关键字匹配表格
        if results.get('keyword_matches', []):
            html_content += """
    <div class="section">
        <h2>关键字匹配详情</h2>
        <p>类别来自关键词规则，不代表确认违规。低信息量词缺少独立佐证时标记为待复核，评估权重不超过 3。</p>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>序号</th>
                        <th>关键字</th>
                        <th>规则类别（非结论）</th>
                        <th>风险权重</th>
                        <th>判定依据</th>
                        <th>来源</th>
                        <th>链接</th>
                        <th>上下文</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            import re as _re
            for i, match in enumerate(results['keyword_matches'], 1):
                risk_class = self._get_keyword_risk_class(match.get('weight', 0))
                ctx_raw = (match.get('context', '') or '')
                urls = _re.findall(r'https?://[^\s\'"<>]+', ctx_raw)
                links_html = ''
                if urls:
                    links_html = ''.join([f'<div class="context"><a href="{_escape_html(u)}" target="_blank">{_escape_html(u)}</a></div>' for u in urls[:5]])
                else:
                    links_html = '<div class="context">N/A</div>'
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{_escape_html(match.get('keyword', 'N/A'))}</td>
                        <td>{_escape_html(match.get('category', 'N/A'))}</td>
                        <td class="{risk_class}">{match.get('weight', 'N/A')}</td>
                        <td>{'待复核：' if match.get('assessment') == 'needs_review' else ''}{_escape_html(match.get('reason', '关键词命中，需结合上下文复核'))}<br>规则原始权重：{_escape_html(match.get('rule_weight', match.get('weight', 'N/A')))}</td>
                        <td>{_escape_html(match.get('source', 'N/A'))}</td>
                        <td>{links_html}</td>
                        <td><div class="context">{_escape_html(ctx_raw[:200])}{'...' if len(ctx_raw) > 200 else ''}</div></td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
"""
        
        behavior_rows = self._behavior_rows(results)
        if behavior_rows:
            html_content += ('<div class="section"><h2>行为证据与待复核项</h2>'
                             '<p>结构评分使用 1-5 量纲。待复核项不计入高风险；证据支持也不等于确认恶意。</p>'
                             '<div class="table-container"><table><thead><tr><th>行为</th><th>评估</th>'
                             '<th>来源</th><th>依据与证据</th></tr></thead><tbody>')
            for item in behavior_rows:
                evidence = json.dumps(item.get('evidence', {}), ensure_ascii=False)
                html_content += (
                    '<tr><td>' + _escape_html(item.get('behavior') or item.get('type')) + '</td><td>' +
                    _escape_html(item.get('assessment', 'risk_finding')) + '</td><td>' +
                    _escape_html(item.get('source') or item.get('file_path')) + '</td><td>' +
                    _escape_html(item.get('reason') or item.get('description')) +
                    '<pre class="context">' + _escape_html(evidence) + '</pre><div class="context">' +
                    _escape_html(item.get('context')) + '</div></td></tr>')
            html_content += '</tbody></table></div></div>'
        # 添加总结和建议
        html_content += """
    <div class="section">
        <h2>总结与建议</h2>
        <p>感谢使用 LinkRecon 暗链扫描工具。根据扫描结果，我们提供以下分析和建议：</p>
"""
        
        if not scan_complete(results):
            html_content += '<p>扫描不完整，已有发现仅供复核，不能据此判定网站安全。</p>'
        elif issue_count(results):
            html_content += """
        <p style="color: #e74c3c;">发现潜在的安全问题，请进行以下操作：</p>
        <ol>
            <li>审查所有可疑链接，确认其合法性</li>
            <li>分析关键字匹配结果，检查相关内容</li>
            <li>移除或修复发现的暗链</li>
            <li>加强网站安全措施，防止再次被植入暗链</li>
            <li>定期使用 LinkRecon 工具进行扫描</li>
        </ol>
"""
        else:
            html_content += """
        <p style="color: #27ae60;">未发现明显的暗链问题。建议继续保持警惕，定期进行扫描。</p>
"""
        
        html_content += """
    </div>
    
    <div class="footer">
        <p>本报告由 LinkRecon 暗链扫描工具自动生成</p>
        <p>LinkRecon | 暗链扫描工具</p>
    </div>
</body>
</html>
"""
        
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_json_report(self, results: Dict, duration):
        """生成JSON报告"""
        # 丰富context_type字段，保持结构化输出一致性
        link_stats = summarize_link_inventory(results.get('link_inventory', []), results.get('suspicious_links', []))
        enriched_links = []
        for link in results.get('suspicious_links', []):
            item = dict(link)
            if 'context_type' not in item:
                item['context_type'] = 'N/A'
            if 'source_tag' not in item:
                item['source_tag'] = item.get('source_tag', 'N/A')
            enriched_links.append(item)
        report_data = {
            'report_info': {
                'tool': 'LinkRecon 暗链扫描工具',
                'version': '1.0',
                'scan_time': datetime.now().isoformat(),
                'target': self.config.target,
                'target_type': self.config.target_type,
                'scan_mode': self.config.scan_mode,
                'scan_status': 'complete' if scan_complete(results) else 'incomplete',
                'duration': str(duration),
                'scanned_files': results.get('scanned_files', 0),
                'scanned_urls': results.get('scanned_urls', 0)
            },
            'statistics': {
                'link_total': link_stats.get('link_total', 0),
                'unique_links': link_stats.get('unique_links', 0),
                'hidden_links': link_stats.get('hidden_links', 0),
                'suspicious_unique_links': link_stats.get('suspicious_unique_links', 0),
                'suspicious_hits': link_stats.get('suspicious_hits', len(results.get('suspicious_links', []))),
                'suspicious_links_count': link_stats.get('suspicious_unique_links', 0),
                'keyword_matches_count': len(results.get('keyword_matches', [])),
                'keyword_review_count': sum(m.get('assessment') == 'needs_review' for m in results.get('keyword_matches', [])),
                'total_issues': issue_count(results),
                'review_count': sum(i.get('assessment') == 'needs_review' for i in unique_findings(results))
            },
            'suspicious_links': enriched_links,
            'link_inventory': results.get('link_inventory', []),
            'ua_comparisons': results.get('ua_comparisons', []),
            'js_issues': results.get('js_issues', []),
            'css_issues': results.get('css_issues', []),
            'hidden_elements': results.get('hidden_elements', []),
            'errors': results.get('errors', []),
            'keyword_matches': results.get('keyword_matches', [])
        }
        
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    def _generate_csv_report(self, results: Dict, duration):
        """生成CSV报告"""
        # 先写入可疑链接
        def _sanitize_csv_cell(val: str) -> str:
            if val is None:
                return ''
            s = str(val)
            return ("'" + s) if s and s[0] in ('=', '+', '-', '@') else s
        with open(self.config.report_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            
            # 写入报告信息
            writer.writerow(['LinkRecon 暗链扫描报告'])
            writer.writerow(['扫描时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['扫描目标', _sanitize_csv_cell(self.config.target)])
            writer.writerow(['扫描模式', _sanitize_csv_cell(self.config.scan_mode)])
            writer.writerow(['扫描耗时', str(duration)])
            writer.writerow(['扫描状态', '完整' if scan_complete(results) else '扫描不完整，不能给出安全结论'])
            for error in results.get('errors', []):
                writer.writerow(['检测错误', _sanitize_csv_cell(error)])
            writer.writerow([])
            
            # 写入可疑链接
            ua_rows = comparison_rows(results.get('ua_comparisons', []))
            if ua_rows:
                writer.writerow(['UA 视角对照（差异不等于确认暗链）'])
                writer.writerow(UA_COLUMNS)
                for row in ua_rows:
                    writer.writerow([_sanitize_csv_cell(value) for value in row])
                writer.writerow([])
            if results.get('suspicious_links', []):
                writer.writerow(['可疑链接'])
                writer.writerow(['序号', '链接', '来源', '来源类型', '来源标签', '类型', '检测方式', '风险等级', '位置', '上下文'])
                
                for i, link in enumerate(results['suspicious_links'], 1):
                    link_display = link.get('link', '') or link.get('url', '') or (link.get('expression', '')[:100] + '...' if link.get('expression') else '')
                    pos = link.get('position')
                    pos_display = f"{pos[0]}-{pos[1]}" if isinstance(pos, (list, tuple)) and len(pos) == 2 else ''
                    writer.writerow([
                        i,
                        _sanitize_csv_cell(link_display),
                        _sanitize_csv_cell(link.get('source', '')),
                        _sanitize_csv_cell(link.get('context_type', 'N/A')),
                        _sanitize_csv_cell(link.get('source_tag', 'N/A')),
                        _sanitize_csv_cell(link.get('type', '')),
                        _sanitize_csv_cell(link.get('detection_method', '')),
                        link.get('risk_level', ''),
                        _sanitize_csv_cell(pos_display),
                        _sanitize_csv_cell((link.get('context', '') or '')[:200])
                    ])
                writer.writerow([])
            
            behavior_rows = self._behavior_rows(results)
            if behavior_rows:
                writer.writerow(['行为证据与待复核项（结构评分 1-5）'])
                writer.writerow(['行为', '评估', '来源', '风险等级', '依据', '证据', '上下文'])
                for item in behavior_rows:
                    writer.writerow([_sanitize_csv_cell(value) for value in (
                        item.get('behavior') or item.get('type'), item.get('assessment', 'risk_finding'),
                        item.get('source') or item.get('file_path'), item.get('risk_level'),
                        item.get('reason') or item.get('description'),
                        json.dumps(item.get('evidence', {}), ensure_ascii=False), item.get('context'))])
                writer.writerow([])
            # 写入关键字匹配
            if results.get('keyword_matches', []):
                writer.writerow(['关键字匹配'])
                writer.writerow(['序号', '关键字', '类别', '风险权重', '来源', '上下文', '规则原始权重', '判定依据'])
                
                for i, match in enumerate(results['keyword_matches'], 1):
                    writer.writerow([
                        i,
                        _sanitize_csv_cell(match.get('keyword', '')),
                        _sanitize_csv_cell(match.get('category', '')),
                        match.get('weight', ''),
                        _sanitize_csv_cell(match.get('source', '')),
                        _sanitize_csv_cell((match.get('context', '') or '')[:200]),
                        match.get('rule_weight', match.get('weight', '')),
                        _sanitize_csv_cell(match.get('reason', '关键词命中，需结合上下文复核'))
                    ])
    
    def _get_risk_class(self, risk_level):
        """
        根据风险等级返回CSS类名。

        统一走 normalize_risk 折算到 1-5 后再判定。原实现的门槛是 >=8 才算
        高危，而除 headless 外所有检测器最高只给 5，导致真正的高危项永远
        评不到高危色。
        """
        iv = normalize_risk(risk_level)
        if iv >= 4:
            return 'risk-high'
        if iv == 3:
            return 'risk-medium'
        return 'risk-low'
    
    def _get_keyword_risk_class(self, weight):
        """根据关键字风险权重返回CSS类名"""
        try:
            weight = int(weight)
            if weight >= 8:
                return 'risk-high'
            elif weight >= 5:
                return 'risk-medium'
            else:
                return 'risk-low'
        except:
            return 'risk-low'
    
    def _read_log_file(self):
        """读取对应的log文件内容，确保完整读取所有日志"""
        try:
            if not getattr(self.config, 'debug', False):
                return "日志读取未启用（非调试模式）"
            # 添加导入
            import time
            
            # 直接使用固定路径方法，先检查reports目录下是否存在最新的日志文件
            # 优先使用报告所在目录作为日志目录
            reports_dir = os.path.dirname(self.config.report_file) or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
            
            # 查找reports目录下所有日志文件
            if os.path.exists(reports_dir):
                all_log_files = [f for f in os.listdir(reports_dir) if f.startswith('LinkRecon_') and f.endswith('.log')]
                
                if all_log_files:
                    # 按修改时间排序，获取最新的日志文件
                    log_files_with_time = [(f, os.path.getmtime(os.path.join(reports_dir, f))) for f in all_log_files]
                    log_files_with_time.sort(key=lambda x: x[1], reverse=True)
                    latest_log_file = os.path.join(reports_dir, log_files_with_time[0][0])
                    
                    # 为了避免读取日志时写入的调试信息污染结果，先获取文件内容并缓存
                    # 初始化变量存储最佳的读取结果
                    best_content = None
                    best_encoding = None
                    best_lines_count = 0
                    best_has_summary = False
                    
                    # 初始等待时间（参数化）
                    time.sleep((getattr(self.config, 'debug_log_wait_ms', 3000))/1000.0)
                    
                    # 检查文件大小是否稳定，表示写入完成
                    size_stable_count = 0
                    last_size = 0
                    max_size_checks = int(getattr(self.config, 'debug_log_checks', 5))
                    
                    for _ in range(max_size_checks):
                        try:
                            current_size = os.path.getsize(latest_log_file)
                            
                            if current_size == last_size:
                                size_stable_count += 1
                            else:
                                size_stable_count = 0
                                last_size = current_size
                                
                            if size_stable_count >= 3:  # 文件大小连续三次稳定
                                break
                            
                            time.sleep((getattr(self.config, 'debug_log_interval_ms', 800))/1000.0)
                        except Exception:
                            break
                    
                    # 一次性读取文件内容并缓存，避免多次打开文件时内容变化
                    try:
                        with open(latest_log_file, 'rb') as f:
                            binary_content = f.read()
                    except Exception as e:
                        logger.error(f"读取日志文件时出错: {str(e)}")
                        return "无法读取日志文件"
                    
                    # 尝试多次读取，确保获取完整内容
                    max_attempts = 3  # 减少尝试次数，因为已经缓存了文件内容
                    for attempt in range(max_attempts):
                        # 等待一小段时间
                        if attempt > 0:
                            time.sleep(1.0)
                        
                        # 优先使用UTF-8编码，因为日志文件通常使用UTF-8
                        encodings = ['utf-8', 'cp936', 'gbk']
                        for encoding in encodings:
                            try:
                                # 尝试解码
                                try:
                                    content = binary_content.decode(encoding, errors='replace')
                                except:
                                    content = binary_content.decode(encoding, errors='ignore')
                                
                                # 预处理内容，规范化行尾
                                content = content.replace('\r\n', '\n').replace('\r', '\n')
                                
                                # 验证内容完整性
                                if content:
                                    lines = content.split('\n')
                                    # 过滤掉空行，获取有效行数
                                    non_empty_lines = [line for line in lines if line.strip()]
                                    lines_count = len(non_empty_lines)
                                    
                                    # 大幅扩展扫描总结关键词
                                    summary_keywords = [
                                        '扫描总结', '扫描完成', '扫描耗时', '总文件数', '发现问题', 
                                        '已扫描', '扫描结束', '平均速度', '扫描结果', '扫描报告',
                                        '扫描结束时间', '总共扫描', '完成扫描', '结果统计', '耗时统计'
                                    ]
                                    has_summary = any(any(keyword in line for keyword in summary_keywords) for line in non_empty_lines)
                                    
                                    # 更新最佳结果
                                    # 首先处理best_encoding为None的情况
                                    update_best = False
                                    
                                    # 如果当前内容有总结，而最佳结果没有总结，则更新
                                    if has_summary and not best_has_summary:
                                        update_best = True
                                    # 如果两者都有总结或都没有总结
                                    elif has_summary == best_has_summary:
                                        # 如果还没有最佳编码，直接更新
                                        if best_encoding is None:
                                            update_best = True
                                        # 否则按编码优先级和行数比较
                                        else:
                                            # 编码优先级比较（索引越小优先级越高）
                                            current_index = encodings.index(encoding)
                                            best_index = encodings.index(best_encoding)
                                            
                                            if current_index < best_index or (current_index == best_index and lines_count > best_lines_count):
                                                update_best = True
                                    
                                    if update_best:
                                        best_content = content
                                        best_encoding = encoding
                                        best_lines_count = lines_count
                                        best_has_summary = has_summary
                                    
                                    # 如果找到扫描总结，直接返回内容
                                    if has_summary:
                                        return content
                            except Exception:
                                continue
                    
                    # 如果尝试了所有次数后仍然没有找到扫描总结，返回行数最多的内容
                    if best_content:
                        return best_content
                    
                    # 最后的备用方案：使用UTF-8解码
                    try:
                        content = binary_content.decode('utf-8', errors='replace')
                        content = content.replace('\r\n', '\n').replace('\r', '\n')
                        return content
                    except Exception:
                        return "无法获取完整的日志内容"
                else:
                    return "未找到任何日志文件"
            else:
                return f"报告目录不存在: {reports_dir}"
        except Exception as e:
            logger.error(f"读取日志文件异常: {str(e)}", exc_info=True)
            return f"读取日志文件时发生错误: {str(e)}\n详细信息: {repr(e)}"
            
        # 局部_escape_html移除，统一使用文件顶部的全局_escape_html
            

