"""Failed analysis is not a clean scan, regardless of finding count."""
def scan_complete(results):
    return not results.get('errors') and results.get('scan_status', 'complete') == 'complete'


def scan_error(results):
    return '; '.join(str(e) for e in (results.get('errors') or [])) or '扫描不完整，不能给出安全结论'
