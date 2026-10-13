# -*- coding: utf-8 -*-
"""UA 对照的中性展示：不能把个性化/动态内容差异直接变成安全告警。"""

from utils.request_profiles import PROFILE_LABELS


ASSESSMENT_LABELS = {
    'same_response': '响应一致', 'response_differs': '响应存在差异（需复核）',
    'comparison_incomplete': '请求/检测失败、HTTP 错误或响应截断，对照不完整',
    'single_profile': '单视角，未进行 UA 对照',
}
UA_COLUMNS = ['目标', '对照结果', '请求身份', 'HTTP 状态', '最终地址', '响应字节数', '说明']


def comparison_rows(comparisons):
    rows = []
    for comparison in comparisons:
        for view in comparison.get('profiles', []):
            profile = view.get('profile', '')
            detail = view.get('error') or comparison.get('note', '')
            if view.get('body_truncated'):
                detail += '\n响应已达到读取上限，对照和检测仅覆盖已读取部分。'
            for suffix, label in (('links', '仅此 UA 的链接'), ('keywords', '仅此 UA 的关键词')):
                values = comparison.get(profile + '_only_' + suffix, [])
                if values:
                    detail += '\n' + label + '：' + '、'.join(values[:50])
                    if len(values) > 50:
                        detail += f'（共 {len(values)} 项，仅展示前 50 项，完整数据见 JSON 报告）'
            rows.append([
                comparison.get('source', ''),
                ASSESSMENT_LABELS.get(comparison.get('assessment'), '未知'),
                PROFILE_LABELS.get(profile, profile),
                str(view.get('status_code') or '失败'), view.get('final_url', ''),
                str(view.get('body_bytes', 0)), detail,
            ])
    return rows
