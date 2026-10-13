# -*- coding: utf-8 -*-
"""只读规划 Libra 关键词导入，输出可审查的补丁，不改动源数据库。"""

import argparse
import csv
import io
import json
import re
import sqlite3
import unicodedata
from contextlib import closing
from pathlib import Path


CATEGORY_MAP = {
    '色情': 'porn', '博彩': 'gambling', '政治': 'political',
    '广告': 'other', '道德': 'other', '舆情': 'other',
}


def keyword_key(keyword):
    """当前匹配忽略大小写；去掉边缘空白，但不改写正则或词中空白。"""
    return unicodedata.normalize('NFC', keyword.strip()).casefold()


def plan_libra_import(database, keyword_file):
    existing = []
    with Path(keyword_file).open(encoding='utf-8-sig', newline='') as stream:
        for row in csv.reader(stream):
            if not row or not row[0].strip() or row[0].lstrip().startswith('#'):
                continue
            if len(row) != 3:
                raise ValueError('现有词库存在非三列 CSV 记录，停止导入')
            existing.append((row[0].strip(), row[1].strip(), int(row[2])))
    seen = {keyword_key(row[0]) for row in existing}
    if len(seen) != len(existing):
        raise ValueError('现有词库含重复关键词，请先审查冲突分类与权重')

    path = Path(database).resolve()
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute('SELECT re, mark FROM violativelink_rules ORDER BY rowid').fetchall()
    added, source_keys = [], set()
    duplicates = overlaps = empty = 0
    for keyword, label in rows:
        keyword = (keyword or '').strip()
        if not keyword:
            empty += 1
            continue
        # Libra 用正则匹配。本次库都是字面词；将来出现新正则时拒绝静默改变语义。
        if re.search(r'[\\.*+?()\[\]{}^$|]', keyword):
            raise ValueError('源库出现正则规则，请人工审查：' + keyword)
        key = keyword_key(keyword)
        if key in source_keys:
            duplicates += 1
            continue
        source_keys.add(key)
        if key in seen:
            overlaps += 1
            continue
        label = (label or '').strip()
        if label not in CATEGORY_MAP:
            raise ValueError('未知源分类，请人工映射：' + label)
        # 源库没有严重度，不能把类别直接等同于高危。保留现有弱词复核策略。
        added.append((keyword, CATEGORY_MAP[label], 5))
        seen.add(key)
    return added, {
        'source_rows': len(rows), 'source_unique': len(source_keys),
        'source_duplicates': duplicates, 'existing_overlap': overlaps,
        'empty_skipped': empty, 'added': len(added),
        'previous_total': len(existing), 'merged_total': len(seen),
    }


def render_import_block(added):
    buffer = io.StringIO(newline='')
    buffer.write('# Libra violativelink_rules：去重导入；来源与权重策略见 docs/keyword-library.md\n')
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(added)
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--keywords', default='keywords_example.txt')
    parser.add_argument('--patch', action='store_true', help='输出 apply_patch 补丁；不直接写文件')
    args = parser.parse_args()
    added, stats = plan_libra_import(args.database, args.keywords)
    result = {'statistics': stats}
    if args.patch and added:
        lines = Path(args.keywords).read_text(encoding='utf-8-sig').splitlines()
        anchor = '\n'.join(' ' + line for line in lines[-3:])
        addition = '\n'.join('+' + line for line in render_import_block(added).splitlines())
        result['patch'] = ('*** Begin Patch\n*** Update File: ' + str(Path(args.keywords).resolve())
                           + '\n@@\n' + anchor + '\n' + addition + '\n*** End Patch')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
