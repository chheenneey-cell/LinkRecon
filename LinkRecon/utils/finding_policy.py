"""One severity/counting contract for scanners, history and reports."""
import json

from utils.common_utils import normalize_risk


FINDING_KEYS = ('suspicious_links', 'hidden_elements', 'js_issues', 'css_issues', 'keyword_matches')


def is_reportable(item):
    if item.get('assessment') in ('needs_review', 'informational'):
        return False
    if 'keyword' in item and 'weight' in item:
        try:
            return float(item['weight']) >= 7  # keyword scale is 1-10, not 1-5
        except (ValueError, TypeError):
            return False
    return normalize_risk(item.get('risk_level')) >= 4


def finding_key(item):
    if item.get('finding_id'):
        return item['finding_id']
    evidence = {k: item.get(k) for k in ('type', 'keyword', 'category', 'pattern', 'behavior',
                'url', 'link', 'position', 'context', 'reason', 'risk_level', 'weight', 'assessment')}
    evidence['source'] = item.get('source') or item.get('file_path')
    return json.dumps(evidence, sort_keys=True, ensure_ascii=False, default=str)


def unique_findings(results, keys=FINDING_KEYS, reportable_only=False):
    seen = set()
    for key in keys:
        for item in results.get(key, []) or []:
            identity = finding_key(item)
            if identity not in seen and (not reportable_only or is_reportable(item)):
                seen.add(identity)
                yield item


def issue_count(results):
    return sum(1 for _ in unique_findings(results, reportable_only=True))
