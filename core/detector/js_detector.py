# -*- coding: utf-8 -*-
"""JavaScript detection based on executable input/operation evidence."""
from typing import List, Dict, Any

from utils.common_utils import get_context_range
from utils.js_evidence import analyze, calls, executable_mask, finding_id
from utils.js_utils import extract_suspicious_patterns


class JSDetector:
    MATCH_POLICY_VERSION = 'bounded-evidence-v1'

    def __init__(self, config):
        self.config = config
        self.logger = config.logger

    def detect(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        # Do not catch analysis failures here: Scanner records them as errors,
        # instead of incorrectly treating a failed analysis as a clean result.
        results = analyze(file_path, content)
        for name, arguments, position in calls(content):
            if name not in ('eval', 'Function', 'execScript', 'window.eval'):
                continue
            if any(item.get('position') == position for item in results):
                continue
            item = {'type': 'js_feature', 'behavior': 'code_execution_call',
                    'file_path': file_path, 'source': file_path, 'position': position,
                    'function_name': name, 'arguments': arguments, 'risk_level': 1,
                    'assessment': 'informational', 'reason': '代码执行调用本身不等于恶意行为',
                    'context': get_context_range(content, *position, 80)}
            item['finding_id'] = finding_id(item)
            results.append(item)
        return results

    def _detect_suspicious_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Legacy structural-hint contract; hints never establish maliciousness."""
        results = []
        for match in extract_suspicious_patterns(executable_mask(content)):
            position = match.get('position', (0, 0))
            results.append({
                'type': 'suspicious_pattern', 'file_path': file_path,
                'pattern': match.get('pattern', 'unknown'), 'position': position,
                'matched_content': content[position[0]:position[1]],
                'risk_level': 1, 'assessment': 'informational',
                'description': '脚本结构提示，不能单独判断恶意行为',
                'context': get_context_range(content, *position, 80),
            })
        return results
