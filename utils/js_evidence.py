"""Bounded, non-executing JavaScript evidence analysis.

This is deliberately not a JS interpreter. Unknown expressions stay unknown;
comments, literal documentation and complexity are not executable evidence.
"""
import base64
import hashlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit


MAX_TEXT = 65536
MAX_TOKENS = 100000
_WORD = re.compile(r'[A-Za-z_$][\w$]*|(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)')


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    encoded: bool = False


@dataclass(frozen=True)
class Value:
    text: str = None
    transforms: tuple = ()
    inputs: tuple = ()
    numeric: bool = False


def _string(raw):
    def escape(match):
        value = match.group(1)
        if value.startswith(('x', 'u')):
            try:
                return chr(int(value[1:].strip('{}'), 16))
            except (ValueError, OverflowError):
                return '\ufffd'
        return {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f',
                '\n': '', '\r\n': ''}.get(value, value)
    return re.sub(r'\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])',
                  escape, raw)


def tokenize(code):
    """Preserve offsets, skip comments, keep quoted/regex content opaque."""
    tokens, i = [], 0
    while i < len(code) and len(tokens) < MAX_TOKENS:
        c, start = code[i], i
        if c.isspace():
            i += 1
            continue
        if code.startswith('//', i):
            end = code.find('\n', i + 2)
            i = len(code) if end < 0 else end
            continue
        if code.startswith('/*', i):
            end = code.find('*/', i + 2)
            i = len(code) if end < 0 else end + 2
            continue
        if c in "\"'`":
            quote = c
            i += 1
            while i < len(code):
                if code[i] == '\\':
                    i += 2
                elif code[i] == quote:
                    break
                else:
                    i += 1
            closed = i < len(code)
            raw = code[start + 1:i]
            i = min(len(code), i + 1)
            kind = 'string' if closed and not (quote == '`' and '${' in raw) else 'unknown'
            tokens.append(Token(kind, _string(raw) if kind == 'string' else raw, start, i,
                                bool(re.search(r'\\(?:x|u)', raw))))
            continue
        # A slash in expression-start position is a regex literal, not a call.
        if c == '/' and (not tokens or tokens[-1].value in
                         ('=', '(', '[', ',', ':', 'return', '!', '&&', '||', ';', '{', '=>')):
            i += 1
            in_class = False
            while i < len(code) and code[i] not in '\r\n':
                if code[i] == '\\':
                    i += 2
                    continue
                if code[i] == '[':
                    in_class = True
                elif code[i] == ']':
                    in_class = False
                elif code[i] == '/' and not in_class:
                    i += 1
                    while i < len(code) and code[i].isalpha():
                        i += 1
                    break
                i += 1
            tokens.append(Token('regex', code[start:i], start, i))
            continue
        match = _WORD.match(code, i)
        if match:
            value = match.group()
            i += len(value)
            tokens.append(Token('number' if value[0].isdigit() else 'name', value, start, i))
            continue
        operator = next((op for op in ('===', '!==', '??=', '&&=', '||=', '=>', '+=', '-=', '*=', '/=', '%=', '==', '!=', '&&', '||',
                                      '?.', '++', '--', '**') if code.startswith(op, i)), c)
        i += len(operator)
        tokens.append(Token('punct', operator, start, i))
    if i < len(code):
        raise ValueError('JavaScript token budget exceeded; analysis incomplete')
    return tokens


def executable_mask(code):
    chars = ['\n' if c == '\n' else ' ' for c in code]
    for token in tokenize(code):
        if token.kind not in ('string', 'regex', 'unknown'):
            chars[token.start:token.end] = code[token.start:token.end]
    return ''.join(chars)


def javascript_url_code(value, html_encoded=False):
    """Decode a JS URL without executing it; None distinguishes other protocols."""
    # HTML attributes may contain entities, leading whitespace or URL tabs/newlines.
    from html import unescape
    normalized = (unescape(value or '') if html_encoded else value or '').strip(
        ''.join(chr(i) for i in range(33)))
    normalized = normalized.replace('\t', '').replace('\r', '').replace('\n', '')
    if not normalized.lower().startswith('javascript:'):
        return None
    return unquote(normalized[11:])


def script_blocks(html, mask_only=False):
    """Executable inline scripts/handlers with original HTML offsets, not JSON data."""
    class Scripts(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.blocks, self.ranges, self.pending = [], [], None
            self.lines = [0] + [m.end() for m in re.finditer('\n', html)]

        def absolute_offset(self):
            line, column = self.getpos()
            return self.lines[line - 1] + column

        def handle_starttag(self, tag, attrs):
            raw, pos = self.get_starttag_text(), self.absolute_offset()
            values = dict(attrs)
            if tag == 'script':
                kind = (values.get('type') or '').strip().lower().split(';')[0]
                executable = kind in ('', 'module', 'text/javascript', 'application/javascript',
                                      'text/ecmascript', 'application/ecmascript')
                self.pending = (pos + len(raw), executable and 'src' not in values)
            from html import unescape
            for attr in re.finditer(r'''([^\s=<>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''', raw):
                name = attr[1].lower()
                group = next((g for g in (2, 3, 4) if attr[g] is not None), None)
                text, start = attr[group], pos + attr.start(group)
                if name.startswith('on'):
                    self.blocks.append((unescape(text), start, 'event_handler'))
                    self.ranges.append((start, start + len(text)))
                elif name in ('href', 'src') and javascript_url_code(text, html_encoded=True) is not None:
                    prefix_end = text.find(':') + 1 if ':' in text else 11
                    self.blocks.append((javascript_url_code(text, html_encoded=True), start + prefix_end, 'javascript_attribute'))
                    self.ranges.append((start, start + len(text)))

        def handle_endtag(self, tag):
            if tag == 'script' and self.pending:
                start, executable = self.pending
                if executable:
                    self.blocks.append((html[start:self.absolute_offset()], start, 'inline_script'))
                self.ranges.append((start, self.absolute_offset()))
                self.pending = None

        def handle_comment(self, data):
            start = self.absolute_offset()
            end = html.find('-->', start)
            self.ranges.append((start, len(html) if end < 0 else end + 3))

    parser = Scripts()
    parser.feed(html)
    if mask_only:
        chars = list(html)
        if parser.pending:
            parser.ranges.append((parser.pending[0], len(html)))
        for start, end in parser.ranges:
            chars[start:end] = ['\n' if c == '\n' else ' ' for c in html[start:end]]
        return ''.join(chars)
    return sorted(parser.blocks, key=lambda block: block[1])


def _matching(tokens):
    stack, pairs = [], {}
    for i, token in enumerate(tokens):
        if token.value in ('(', '[', '{') and token.kind == 'punct':
            stack.append(i)
        elif token.value in (')', ']', '}') and token.kind == 'punct':
            expected = {')': '(', ']': '[', '}': '{'}[token.value]
            if stack and tokens[stack[-1]].value == expected:
                start = stack.pop()
                pairs[start] = i
                pairs[i] = start
    return pairs


def _split(tokens, delimiter=','):
    groups, start, depth = [], 0, 0
    for i, t in enumerate(tokens):
        if t.kind == 'punct':
            if t.value in ('(', '[', '{'):
                depth += 1
            elif t.value in (')', ']', '}'):
                depth -= 1
            elif t.value == delimiter and depth == 0:
                groups.append(tokens[start:i])
                start = i + 1
    groups.append(tokens[start:])
    return groups


def _name(tokens):
    if not tokens or tokens[0].kind != 'name':
        return None
    parts, i = [tokens[0].value], 1
    while i < len(tokens):
        if i + 1 < len(tokens) and tokens[i].value in ('.', '?.') and tokens[i + 1].kind == 'name':
            parts.append(tokens[i + 1].value)
            i += 2
        elif (i + 2 < len(tokens) and tokens[i].value == '[' and tokens[i + 1].kind == 'string'
              and tokens[i + 2].value == ']'):
            parts.append(tokens[i + 1].value)
            i += 3
        else:
            return None
    return '.'.join(parts)


def _target_start(tokens, end, pairs):
    start = end - 1
    while start > 0:
        if tokens[start].value == ']' and start in pairs:
            start = pairs[start] - 1
        elif tokens[start].value == ')' and start in pairs:
            start = pairs[start] - 1
        elif tokens[start - 1].value in ('.', '?.'):
            start -= 2
        else:
            break
    return max(0, start)


def calls(code):
    """Balanced calls; no substring matches inside evaluate, strings or comments."""
    tokens = tokenize(code)
    pairs = _matching(tokens)
    for i, token in enumerate(tokens):
        if token.value != '(' or token.kind != 'punct' or i not in pairs:
            continue
        start = _target_start(tokens, i, pairs)
        name = _name(tokens[max(0, start):i])
        if name and not (start > 0 and tokens[start - 1].value == 'function'):
            end = pairs[i]
            yield name, code[token.end:tokens[end].start], (tokens[max(0, start)].start, tokens[end].end)


def resolve(tokens, env, depth=0):
    if not tokens or depth > 12:
        return Value()
    pairs = _matching(tokens)
    if tokens[0].value == '(' and pairs.get(0) == len(tokens) - 1:
        return resolve(tokens[1:-1], env, depth + 1)
    if len(tokens) == 1:
        t = tokens[0]
        if t.kind == 'string':
            encoded = ('escape',) if t.encoded else ()
            return Value(t.value[:MAX_TEXT], encoded) if len(t.value) <= MAX_TEXT else Value()
        if t.kind == 'number':
            # Preserve JS type during concatenation. Do not fabricate a string
            # value for unsupported arithmetic, octal or imprecise large numbers.
            try:
                number = int(t.value, 16 if t.value.lower().startswith('0x') else 10)
                valid = abs(number) <= 2 ** 53 and (not t.value.startswith('0') or len(t.value) == 1 or t.value.lower().startswith('0x'))
                return Value(str(number) if valid else None, numeric=True)
            except ValueError:
                return Value(numeric=True)
        if t.value in ('true', 'false'):
            return Value(t.value)
        return env.get(t.value, Value())
    parts = _split(tokens, '+')
    if len(parts) > 1:
        values = [resolve(p, env, depth + 1) for p in parts]
        # JS adds leading numbers before switching to string concatenation.
        # Arithmetic is outside this resolver: mark it unknown, not "1"+"2"="12".
        numeric_prefix = len(values) > 1 and values[0].numeric and values[1].numeric
        text = ''.join(v.text for v in values) if not numeric_prefix and all(v.text is not None for v in values) else None
        return Value(text if text is None or len(text) <= MAX_TEXT else None,
                     tuple(dict.fromkeys(x for v in values for x in v.transforms)),
                     tuple(dict.fromkeys(x for v in values for x in v.inputs)))
    name = _name(tokens)
    if name:
        if name in env:
            return env[name]
        if name.split('.')[0] in env:
            return Value()  # shadowed location/document/window is not browser input
        if name in ('location.hash', 'location.search', 'location.href', 'window.location.hash',
                    'window.location.search', 'window.location.href', 'document.URL',
                    'document.cookie', 'document.referrer'):
            return Value(inputs=(name,))
        return Value()
    opening = next((i for i, t in enumerate(tokens) if t.value == '(' and t.kind == 'punct'), -1)
    if opening > 0 and pairs.get(opening) == len(tokens) - 1:
        function = _name(tokens[:opening])
        args = [resolve(p, env, depth + 1) for p in _split(tokens[opening + 1:-1])]
        value = args[0] if args else Value()
        if function and function.split('.')[0] not in env and function in ('atob', 'window.atob', 'unescape', 'decodeURI', 'decodeURIComponent',
                        'String.fromCharCode'):
            transforms = value.transforms + (function,)
            try:
                if function == 'String.fromCharCode':
                    text = ''.join(chr(int(v.text, 0) & 0xffff) for v in args)
                elif value.text is None:
                    text = None
                elif function in ('atob', 'window.atob'):
                    text = base64.b64decode(value.text, validate=True).decode('latin1')
                elif function == 'unescape':
                    text = unquote(re.sub(r'%u([0-9a-fA-F]{4})',
                                         lambda m: chr(int(m[1], 16)), value.text))
                else:
                    text = unquote(value.text, errors='strict')
                return Value(text if text is None or len(text) <= MAX_TEXT else None, transforms, value.inputs)
            except (ValueError, TypeError, UnicodeError):
                return Value(transforms=transforms, inputs=value.inputs)
    # Carry known input provenance through unresolved operations (e.g. hash.slice).
    inputs = tuple(dict.fromkeys(x for t in tokens if t.kind == 'name'
                                for x in env.get(t.value, Value()).inputs))
    # Exact member-token sequences, not substring hits (mylocation.hash is not location.hash).
    for i, token in enumerate(tokens):
        if token.kind != 'name' or token.value in env or i and tokens[i - 1].value == '.':
            continue
        end = i + 1
        while end + 1 < len(tokens) and tokens[end].value == '.' and tokens[end + 1].kind == 'name':
            end += 2
        candidate = _name(tokens[i:end])
        for origin in ('location.hash', 'location.search', 'location.href',
                       'window.location.hash', 'window.location.search', 'window.location.href',
                       'document.cookie', 'document.referrer', 'document.URL'):
            if candidate == origin or candidate and candidate.startswith(origin + '.'):
                inputs += (origin,)
    return Value(inputs=tuple(dict.fromkeys(inputs)))


def _external(url, source):
    try:
        target = urlsplit(urljoin(source, url))
        base = urlsplit(source)
        return target.scheme in ('http', 'https') and bool(target.hostname) and target.hostname != base.hostname
    except ValueError:
        return False


def _hidden(attrs):
    from utils.html_utils import is_visually_hidden
    return is_visually_hidden(attrs)


class _MarkupEvidence(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.source, self.stack, self.links = source, [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hidden = any(h for _, h in self.stack) or _hidden(attrs)
        url = attrs.get('href' if tag == 'a' else 'src', '')
        if tag in ('a', 'iframe', 'script') and _external(url, self.source):
            self.links.append((urljoin(self.source, url), tag, hidden))
        if tag not in ('area', 'base', 'br', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'wbr'):
            self.stack.append((tag, hidden))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


def finding_id(item):
    block = (item.get('script_fingerprint'), item.get('script_kind'), item.get('script_occurrence'))
    key = (item.get('source') or item.get('file_path'), item.get('behavior'),
           item.get('script_position', item.get('position')), block,
           item.get('url'), item.get('reason'), item.get('evidence'))
    return hashlib.sha256(repr(key).encode('utf-8')).hexdigest()[:24]


def mark_script_finding(item, code, kind, occurrence):
    item.update(script_fingerprint=hashlib.sha256(code.encode('utf-8')).hexdigest(),
                script_kind=kind, script_occurrence=occurrence, script_position=item.get('position'))
    item['finding_id'] = finding_id(item)


def _scope_bindings(tokens, pairs, start, end):
    """Hoisted/local declarations shadow outer names even before their first assignment."""
    names, i = set(), start
    while i < end:
        if tokens[i].value in ('var', 'let', 'const', 'function') and i + 1 < end and tokens[i + 1].kind == 'name':
            names.add(tokens[i + 1].value)
        if tokens[i].value == '{' and i in pairs:
            i = pairs[i] + 1
        else:
            i += 1
    return names


def analyze(source, code, nesting=0):
    """Return supported behaviors and unresolved dangerous sinks, never execute JS.

    Constant propagation is local to one script and lexical block; assignments
    in function bodies do not leak into another function or following script.
    """
    tokens, env, objects, frames, results = tokenize(code), {}, {}, [], []
    pairs = _matching(tokens)
    env.update({name: Value() for name in _scope_bindings(tokens, pairs, 0, len(tokens))})

    def emit(behavior, value, start, end, reason, url=None, supported=True):
        item = {'type': 'js_behavior', 'behavior': behavior, 'file_path': source, 'source': source,
                'position': (start, end), 'risk_level': 4 if supported else 3,
                'assessment': 'evidence_supported' if supported else 'needs_review',
                'reason': reason, 'description': reason, 'context': code[max(0, start - 80):end + 80],
                'evidence': {'operation': code[start:end], 'decoded_value': value.text,
                             'transforms': list(value.transforms), 'input_sources': list(value.inputs)}}
        if url:
            item.update(url=url, link=url)
        item['finding_id'] = finding_id(item)
        results.append(item)

    def markup(value, start, end):
        if value.text is None:
            if value.inputs or value.transforms:
                emit('dynamic_markup', value, start, end, '动态 HTML 输入无法静态确认，需复核', supported=False)
            return
        parser = _MarkupEvidence(source)
        parser.feed(value.text)
        for url, tag, hidden in parser.links:
            if hidden or nesting or (value.transforms and tag in ('script', 'iframe')):
                emit('hidden_external_link' if hidden else 'executed_external_injection' if nesting
                     else 'encoded_resource_injection', value, start, end,
                     'HTML 写入包含隐藏外链' if hidden else '执行代码向页面写入外部链接/资源' if nesting
                     else '解码内容写入外部脚本/iframe', url)

    def end_expression(start):
        j = start
        while j < len(tokens):
            if tokens[j].value in (';', ',', '}') and tokens[j].kind == 'punct':
                break
            if j in pairs and tokens[j].value in ('(', '['):
                j = pairs[j] + 1
            else:
                if j > start and '\n' in code[tokens[j - 1].end:tokens[j].start] and tokens[j].value in ('var', 'let', 'const'):
                    break
                j += 1
        return j

    for i, t in enumerate(tokens):
        if t.value == 'function' and i + 1 < len(tokens) and tokens[i + 1].kind == 'name':
            env[tokens[i + 1].value] = Value()
        if t.kind == 'punct' and t.value == '{':
            previous = i - 1
            parameter_end = previous - 1 if previous >= 0 and tokens[previous].value == '=>' else previous
            opening = pairs.get(parameter_end) if parameter_end >= 0 and tokens[parameter_end].value == ')' else None
            before_parens = tokens[opening - 1].value if opening is not None and opening else ''
            function = (previous >= 0 and tokens[previous].value == '=>') or (
                opening is not None and before_parens not in ('if', 'for', 'while', 'switch', 'catch', 'with'))
            frames.append({'env': dict(env), 'objects': {k: dict(v) for k, v in objects.items()},
                           'function': function, 'changed': set(), 'locals': set()})
            env.update({name: Value() for name in _scope_bindings(tokens, pairs, i + 1, pairs.get(i, len(tokens)))})
            # Parameter shadowing: a parameter must not reuse an outer constant.
            if function:
                if opening is not None:
                    for parameter in tokens[opening + 1:parameter_end]:
                        if parameter.kind == 'name':
                            env[parameter.value] = Value()
                            objects.pop(parameter.value, None)
                elif previous > 0 and tokens[previous].value == '=>' and tokens[previous - 1].kind == 'name':
                    env[tokens[previous - 1].value] = Value()
        elif t.kind == 'punct' and t.value == '}' and frames:
            frame = frames.pop()
            env, objects = frame['env'], frame['objects']
            if not frame['function']:
                # A conditional write is not a proven post-block constant. Do
                # not resurrect the old encoded value after a reassignment.
                for name in frame['changed'] - frame['locals']:
                    env[name] = Value()
                    objects.pop(name, None)
                    if frames:
                        frames[-1]['changed'].add(name)
        if t.value in ('++', '--') and i:
            env[tokens[i - 1].value] = Value()
            if frames:
                frames[-1]['changed'].add(tokens[i - 1].value)
        if t.value in ('=', '+=', '-=', '*=', '/=', '%=', '??=', '||=', '&&=') and t.kind == 'punct':
            start = _target_start(tokens, i, pairs)
            target = _name(tokens[max(0, start):i])
            # A browser getter receiver is still a DOM sink, e.g.
            # document.getElementById("x").innerHTML = decodedMarkup.
            if target is None and i >= 2 and tokens[i - 1].value in ('innerHTML', 'outerHTML') and tokens[i - 2].value == '.':
                opening = next((j for j in range(start, i - 2) if tokens[j].value == '('), None)
                getter = _name(tokens[start:opening]) if opening is not None else None
                if getter in ('document.getElementById', 'document.querySelector') and 'document' not in env:
                    target = 'document.' + tokens[i - 1].value
            j = end_expression(i + 1)
            expr = tokens[i + 1:j]
            value = resolve(expr, env)
            if t.value not in ('=', '+='):
                value = Value()  # unsupported compound operations invalidate, never reuse constants
            root = target.split('.')[0] if target else None
            declaration = start > 0 and tokens[start - 1].value in ('let', 'const', 'var')
            if root and frames:
                frames[-1]['changed'].add(root)
                if declaration and tokens[start - 1].value in ('let', 'const'):
                    frames[-1]['locals'].add(root)
            builtin = root not in env and not declaration
            if builtin and target in ('location', 'window.location', 'document.location', 'location.href',
                          'window.location.href', 'document.location.href'):
                if value.text and value.transforms and _external(value.text, source):
                    emit('encoded_redirect', value, tokens[start].start, tokens[j - 1].end,
                         '解码外部地址后写入页面跳转目标', urljoin(source, value.text))
                elif value.text is None and (value.transforms or value.inputs):
                    emit('dynamic_redirect', value, tokens[start].start, tokens[j - 1].end,
                         '动态跳转目标无法静态解析，需复核', supported=False)
            if target and '.' not in target:
                if t.value == '+=':
                    old = env.get(target, Value())
                    value = Value(old.text + value.text if old.text is not None and value.text is not None
                                  and len(old.text) + len(value.text) <= MAX_TEXT else None,
                                  old.transforms + value.transforms, old.inputs + value.inputs)
                env[target] = value
                objects.pop(target, None)
                factory = _name(expr[:3]) if len(expr) >= 4 and expr[3].value == '(' else None
                if factory in ('document.createElement', 'document.getElementById', 'document.querySelector') and 'document' not in env:
                    tag = resolve(expr[4:-1], env).text
                    objects[target] = {'tag': tag if factory == 'document.createElement' else None,
                                       'hidden': False, 'dom': True}
            elif target:
                if target.endswith(('.innerHTML', '.outerHTML')):
                    root = target.split('.')[0]
                    known_dom = (root == 'document' and root not in env) or objects.get(root, {}).get('dom')
                    if known_dom:
                        markup(value, tokens[start].start, tokens[j - 1].end)
                    elif value.transforms or value.inputs or value.text and '<' in value.text:
                        emit('unresolved_dom_receiver', value, tokens[start].start, tokens[j - 1].end,
                             '无法确认接收对象是否为 DOM 元素，需复核', supported=False)
                root, _, prop = target.partition('.')
                if root in objects:
                    obj = objects[root]
                    if prop in ('href', 'src'):
                        obj['url_value'] = value
                    elif prop == 'hidden':
                        obj['hidden'] = bool(value.text) and value.text not in ('false', '0')
                    elif prop in ('style.display', 'style.visibility', 'style.opacity', 'style.cssText'):
                        obj['hidden'] = value.text in ('none', 'hidden', '0') or _hidden({'style': value.text or ''})
        if t.value != '(' or t.kind != 'punct' or i not in pairs:
            continue
        start = _target_start(tokens, i, pairs)
        name = _name(tokens[max(0, start):i])
        end = pairs[i]
        if not name or start > 0 and tokens[start - 1].value == 'function':
            continue
        args = _split(tokens[i + 1:end])
        value = resolve(args[0], env) if args else Value()
        if name.split('.')[0] in env and name in ('eval', 'window.eval', 'execScript', 'Function',
                'setTimeout', 'setInterval', 'document.write', 'document.writeln', 'location.assign',
                'location.replace', 'window.location.assign', 'window.location.replace'):
            emit('shadowed_operation', value, tokens[start].start, tokens[end].end,
                 '同名标识符遮蔽浏览器操作，无法确认其行为', supported=False)
            continue
        if name in ('eval', 'window.eval', 'execScript', 'Function', 'setTimeout', 'setInterval'):
            # Function uses its last argument as the executable body; callable timers are safe here.
            if name == 'Function':
                value = resolve(args[-1], env)
            if value.inputs:
                emit('untrusted_code_execution', value, tokens[start].start, tokens[end].end,
                     '不可信页面输入流入代码执行操作')
            elif value.text is not None and nesting < 2 and len(value.text) <= MAX_TEXT:
                nested = analyze(source, value.text, nesting + 1)
                for item in nested:
                    item['position'] = (tokens[start].start, tokens[end].end)
                    item['context'] = code[max(0, tokens[start].start - 80):tokens[end].end + 80]
                    item['evidence']['execution_sink'] = name
                    item['evidence']['transforms'] = list(value.transforms) + item['evidence']['transforms']
                    item['finding_id'] = finding_id(item)
                    results.append(item)
                if not nested and name not in ('setTimeout', 'setInterval') and not re.fullmatch(r'[\d\s+*/().%-]+', value.text):
                    emit('dynamic_code_execution', value, tokens[start].start, tokens[end].end,
                         '代码执行调用尚无可确认的恶意行为，需复核', supported=False)
            elif name not in ('setTimeout', 'setInterval') or value.transforms:
                emit('dynamic_code_execution', value, tokens[start].start, tokens[end].end,
                     '代码执行输入无法静态解析，需复核', supported=False)
        elif name in ('document.write', 'document.writeln'):
            for arg in args:
                markup(resolve(arg, env), tokens[start].start, tokens[end].end)
        elif name.endswith('.insertAdjacentHTML') and len(args) > 1:
            markup(resolve(args[1], env), tokens[start].start, tokens[end].end)
        elif name in ('location.assign', 'location.replace', 'window.location.assign', 'window.location.replace'):
            if value.text and value.transforms and _external(value.text, source):
                emit('encoded_redirect', value, tokens[start].start, tokens[end].end,
                     '解码外部地址后执行页面跳转', urljoin(source, value.text))
            elif value.text is None and (value.transforms or value.inputs):
                emit('dynamic_redirect', value, tokens[start].start, tokens[end].end,
                     '动态跳转目标无法静态解析，需复核', supported=False)
        elif name.endswith(('.appendChild', '.insertBefore', '.replaceChild')) and args:
            obj = objects.get(_name(args[0]), {})
            url_value = obj.get('url_value', Value())
            if obj.get('tag') in ('a', 'iframe', 'script') and url_value.text and _external(url_value.text, source):
                if obj.get('hidden') or (url_value.transforms and obj['tag'] in ('script', 'iframe')):
                    emit('hidden_external_link' if obj.get('hidden') else 'encoded_resource_injection',
                         url_value, tokens[start].start, tokens[end].end,
                         '创建并插入隐藏外链' if obj.get('hidden') else '解码外部资源地址并插入页面',
                         urljoin(source, url_value.text))
    return list({item['finding_id']: item for item in results}.values())
