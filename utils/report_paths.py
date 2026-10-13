"""Unique names for automatically generated reports."""
import os
import uuid
from datetime import datetime


def new_report_path(directory, kind, prefix='scan_report'):
    if kind not in ('html', 'txt', 'json', 'csv'):
        raise ValueError(f'不支持的报告类型: {kind}')
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    return os.path.join(directory, f'{prefix}_{stamp}_{uuid.uuid4().hex}.{kind}')
