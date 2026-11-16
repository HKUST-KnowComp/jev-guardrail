"""Bounded static descriptions of known actions, never an execution sandbox.

Unknown syntax and effects remain explicit uncertainties. No files, commands,
network endpoints, variable expressions or decoded programs are executed here.
"""
import ast
import base64
import hashlib
import os
import posixpath
import re
import shlex
from urllib.parse import urlsplit
from .python_effects import describe_python
from .protocol import search_request

MAX_BYTES = 32768
MAX_DECODED_BYTES = 8192
MAX_DEPTH = 4
MAX_TOKENS = 2048
MAX_EFFECTS = 128
MAX_AST_NODES = 512
MAX_STATIC_DEPTH = 32
MAX_INTEGER_BITS = 256
PYTHON_STARTUP_REVIEW = 'Known Python operations require isolated standard-library startup'


def normalize(value):
    value = posixpath.normpath(value.replace('\\', '/'))
    if os.name == 'nt':
        match = re.match(r'^/([a-zA-Z])(?:/|$)', value)
        if match:
            value = match.group(1) + ':/' + value[match.end():]
        value = value.casefold()
    return value


def absolute(path, cwd):
    path, cwd = normalize(path), normalize(cwd)
    if path.startswith('/') or re.fullmatch(r'[A-Za-z]:/.*', path):
        return path
    return posixpath.normpath(posixpath.join(cwd, path))


class _HereDoc:
    def __init__(self, strip_tabs=False, fd=0):
        self.strip_tabs, self.fd = strip_tabs, fd
        self.delimiter, self.quoted, self.body = None, False, None


def _bounded(value):
    if value is None:
        return None
    if type(value) is int and value.bit_length() <= MAX_INTEGER_BITS:
        return value
    if isinstance(value, (str, bytes)):
        size = len(value.encode('utf-8')) if isinstance(value, str) else len(value)
        if size <= MAX_DECODED_BYTES:
            return value
    raise ValueError('Static value is outside the supported type or size budget')


def _expression(text):
    if len(text.encode('utf-8')) > MAX_DECODED_BYTES:
        raise ValueError('Static expression byte budget exceeded')
    tree = ast.parse(text, mode='eval')
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        raise ValueError('Static expression node budget exceeded')
    return tree.body


def _literal(node, env, call=None, depth=0, shell=False):
    """Interpret only a small constant grammar; never eval/exec user code."""
    if depth > MAX_STATIC_DEPTH:
        raise ValueError('Static expression depth exceeded')
    child = lambda item: _literal(item, env, call, depth + 1, shell)
    if isinstance(node, ast.Constant):
        return _bounded(node.value)
    if isinstance(node, ast.Name) and node.id in env:
        return _bounded(env[node.id])
    if isinstance(node, ast.UnaryOp):
        value = child(node.operand)
        if type(value) is int:
            if isinstance(node.op, ast.UAdd): return value
            if isinstance(node.op, ast.USub): return _bounded(-value)
            if isinstance(node.op, ast.Invert): return _bounded(~value)
    if isinstance(node, ast.BinOp):
        left, right = child(node.left), child(node.right)
        if isinstance(node.op, ast.Add) and type(left) is type(right) and isinstance(left, (str, bytes)):
            if len(left) + len(right) > MAX_DECODED_BYTES:
                raise ValueError('Static concatenation budget exceeded')
            return _bounded(left + right)
        if type(left) is int and type(right) is int:
            if isinstance(node.op, ast.Add): return _bounded(left + right)
            if isinstance(node.op, ast.Sub): return _bounded(left - right)
            if isinstance(node.op, ast.Mult): return _bounded(left * right)
            if isinstance(node.op, ast.FloorDiv) and right: return _bounded(left // right)
            if isinstance(node.op, ast.Div) and shell and right:
                return _bounded((abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1))
            if isinstance(node.op, ast.Mod) and right:
                quotient = (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)
                return _bounded(left - quotient * right if shell else left % right)
            if isinstance(node.op, ast.BitAnd): return _bounded(left & right)
            if isinstance(node.op, ast.BitOr): return _bounded(left | right)
            if isinstance(node.op, ast.BitXor): return _bounded(left ^ right)
            if isinstance(node.op, (ast.LShift, ast.RShift)) and 0 <= right <= MAX_INTEGER_BITS:
                return _bounded(left << right if isinstance(node.op, ast.LShift) else left >> right)
    if isinstance(node, ast.Call) and call is not None:
        return _bounded(call(node, child))
    raise ValueError('Expression is not a supported known constant')


def _arithmetic(text, env):
    values = {}
    for key, value in env.items():
        if isinstance(value, str) and re.fullmatch(r'[+-]?(?:0|[1-9][0-9]*)', value):
            values[key] = _bounded(int(value))
    # Assignment, increment, shell base notation and implicit octal stay unknown.
    text = re.sub(r'\$([A-Za-z_]\w*)|\$\{([A-Za-z_]\w*)\}', lambda match: match.group(1) or match.group(2), text)
    result = _literal(_expression(text.strip()), values, shell=True)
    if type(result) is not int: raise ValueError('Shell arithmetic requires integers')
    return str(result)


def _substitution_end(command, start):
    """Keep substitutions opaque so their inner punctuation is not shell syntax here."""
    level, quote, i = 1, None, start + 2
    while i < len(command):
        ch = command[i]
        if ch == '\\' and quote != "'":
            i += 2; continue
        if quote:
            if ch == quote: quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == '(':
            level += 1
        elif ch == ')':
            level -= 1
            if level == 0: return i + 1
        i += 1
    raise ValueError('Unclosed shell substitution')


def _lex(command):
    """Preserve quotes and consume heredoc bodies before parsing command words."""
    tokens, pieces, buf, documents = [], [], [], []
    mode, active, quoted, awaiting = 'plain', False, False, None

    def flush_piece():
        if buf:
            pieces.append((''.join(buf), mode)); buf.clear()

    def flush_token():
        nonlocal active, quoted, awaiting
        flush_piece()
        if active:
            if awaiting is not None:
                awaiting.delimiter = ''.join(text for text, _ in pieces)
                awaiting.quoted = quoted
                awaiting = None
            else:
                tokens.append(tuple(pieces))
            pieces.clear(); active = False; quoted = False
        if len(tokens) > MAX_TOKENS:
            raise ValueError('Shell token budget exceeded')

    i = 0
    while i < len(command):
        ch = command[i]
        if mode == 'literal':
            if ch == "'":
                flush_piece(); mode = 'plain'
            else:
                buf.append(ch)
        elif command.startswith('$(', i):
            end = _substitution_end(command, i)
            text = command[i:end]
            if awaiting is None and text.startswith('$((') and text.endswith('))'):
                flush_piece(); pieces.append((text[3:-2], 'arithmetic'))
            else:
                buf.append(text)
            active = True; i = end; continue
        elif ch == '`':
            end = i + 1
            while end < len(command):
                if command[end] == '\\': end += 2; continue
                if command[end] == '`': break
                end += 1
            if end >= len(command): raise ValueError('Unclosed shell command substitution')
            buf.append(command[i:end + 1]); active = True; i = end + 1; continue
        elif ch == '"':
            flush_piece(); mode = 'plain' if mode == 'double' else 'double'; active = True; quoted = True
        elif ch == "'" and mode == 'plain':
            flush_piece(); mode = 'literal'; active = True; quoted = True
        elif ch == '\\':
            if i + 1 >= len(command): raise ValueError('Incomplete shell escape')
            nxt = command[i + 1]
            if mode == 'double' and nxt not in '$`"\\\n':
                buf.append(ch)
            else:
                flush_piece()
                if nxt != '\n': pieces.append((nxt, 'literal')); active = True; quoted = True
                i += 1
        elif mode == 'plain' and ch in ' \t\r':
            flush_token()
        elif mode == 'plain' and ch == '#' and not active:
            while i < len(command) and command[i] != '\n': i += 1
            continue
        elif mode == 'plain' and ch in ';&|()<>\n':
            fd = 0
            if command.startswith('<<', i) and not pieces and buf and ''.join(buf).isdigit():
                fd = int(''.join(buf)); buf.clear(); active = False
            flush_token()
            if awaiting is not None: raise ValueError('Missing heredoc delimiter')
            if command.startswith('<<<', i):
                raise ValueError('Here-string syntax requires review')
            if command.startswith('<<', i):
                strip_tabs = command.startswith('<<-', i)
                awaiting = _HereDoc(strip_tabs, fd)
                documents.append(awaiting); tokens.append(awaiting)
                i += 3 if strip_tabs else 2
                continue
            op = ch
            if i + 1 < len(command) and command[i + 1] == ch and ch in '&|<>':
                op += ch; i += 1
            tokens.append(op)
            if ch == '\n' and documents:
                i += 1
                for document in documents:
                    body = []
                    while i < len(command):
                        end = command.find('\n', i)
                        end = len(command) if end < 0 else end + 1
                        line = command[i:end]; i = end
                        candidate = line[:-1] if line.endswith('\n') else line
                        if document.strip_tabs: candidate = candidate.lstrip('\t')
                        if candidate == document.delimiter: break
                        body.append(line.lstrip('\t') if document.strip_tabs else line)
                    else:
                        raise ValueError('Unclosed heredoc')
                    document.body = ''.join(body)
                documents.clear()
                continue
        else:
            buf.append(ch); active = True
        i += 1
    if mode != 'plain': raise ValueError('Unclosed shell quote')
    flush_token()
    if awaiting is not None or documents: raise ValueError('Unclosed heredoc')
    return tokens


def _word(token, env):
    value, unknown, splitting = [], False, False
    expansion_left = MAX_BYTES
    for text, mode in token:
        if mode == 'literal':
            value.append(text); continue
        if mode == 'arithmetic':
            try:
                value.append(_arithmetic(text, env))
            except (ValueError, SyntaxError, RecursionError):
                unknown = True; value.append('$((unresolved))')
            continue
        if '`' in text or '$(' in text:
            unknown = True
        def replace(match):
            nonlocal unknown, splitting, expansion_left
            name = match.group(1) or match.group(2)
            if name not in env:
                unknown = True
                return match.group(0)
            val = env[name]
            size = len(val.encode('utf-8'))
            if size > expansion_left:
                unknown = True
                return match.group(0)
            expansion_left -= size
            if mode == 'plain' and any(ch.isspace() for ch in val):
                splitting = True
            return val
        expanded = re.sub(r'\$([A-Za-z_]\w*)|\$\{([A-Za-z_]\w*)\}', replace, text)
        # Other parameter, arithmetic and substitution syntax is not evaluated.
        without_simple = re.sub(r'\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}', '', text)
        if '$' in without_simple:
            unknown = True
        value.append(expanded)
    joined = ''.join(value)
    if len(joined.encode('utf-8')) > MAX_BYTES:
        return joined[:MAX_BYTES], True, splitting
    return joined, unknown, splitting


class _Description:
    def __init__(self, state):
        self.state = state
        self.tool = state.get('proposed_tool_name', '')
        context = state.get('execution_context')
        self.context = context if isinstance(context, dict) else {}
        self.cwd = self.context.get('effective_cwd') or state.get('cwd') or '/workspace/task'
        self.effects, self.uncertainties = [], []
        if context is not None and (not isinstance(context, dict) or context.get('context_known') is not True):
            self.uncertain('Execution context is not known')
        if not isinstance(self.cwd, str):
            self.uncertain('Execution working directory is invalid')
            self.cwd = '/workspace/task'
        self.bytes_left = MAX_BYTES
        self.python_isolation_required = False

    def uncertain(self, reason):
        if reason not in self.uncertainties:
            self.uncertainties.append(reason)

    def effect(self, kind, path=None, cwd=None, **extra):
        item = {'kind': kind, **extra}
        if path is not None:
            if not isinstance(path, str) or not path or '\x00' in path:
                self.uncertain('Missing or invalid file target'); return
            if any(x in path for x in ('$','`','*','?','[')) or path.startswith('~'):
                self.uncertain('Dynamic file target requires review')
            lexical = absolute(path, cwd or self.cwd)
            item['path'] = lexical
            item['lexical_path'] = lexical
            resolved = self.context.get('resolved_effect_paths', {})
            if not isinstance(resolved, dict):
                self.uncertain('Resolved effect paths must be a trusted mapping')
            elif lexical in resolved:
                canonical = resolved[lexical]
                if (not isinstance(canonical, str) or not canonical or '\x00' in canonical
                        or not (canonical.startswith('/') or re.fullmatch(r'[A-Za-z]:/.*', canonical))):
                    self.uncertain('Resolved effect path must be absolute')
                else:
                    item['path'] = normalize(canonical)
        if kind == 'network' or item not in self.effects:
            if len(self.effects) >= MAX_EFFECTS:
                self.uncertain('Action effect budget exceeded'); return
            self.effects.append(item)

    def shell(self, command, cwd, env=None, depth=0):
        if not isinstance(command, str):
            self.uncertain('Shell command must be text'); return
        size = len(command.encode('utf-8'))
        if depth > MAX_DEPTH or size > self.bytes_left or '\x00' in command:
            self.uncertain('Shell expansion depth or byte budget exceeded'); return
        self.bytes_left -= size
        try:
            tokens = _lex(command)
        except ValueError as exc:
            self.uncertain(str(exc)); return
        env = dict(env or {})
        segments, segment = [], []
        for token in tokens + [';']:
            if isinstance(token, str) and token in (';', '\n', '|', '||', '&&', '&', '(', ')'):
                if token not in (';', '\n', '|'):
                    self.uncertain('Conditional, background or grouped shell requires review')
                if segment:
                    segments.append((segment, token)); segment = []
            else:
                segment.append(token)
        stream = None
        for segment, connector in segments:
            words, redirects, documents = [], [], []
            bad_expansion = False
            i = 0
            while i < len(segment):
                token = segment[i]
                if isinstance(token, _HereDoc):
                    documents.append(token); i += 1; continue
                if isinstance(token, str):
                    if token in ('>', '>>', '<') and i + 1 < len(segment) and isinstance(segment[i+1], tuple):
                        target, unknown, split = _word(segment[i+1], env)
                        if unknown or split:
                            self.uncertain('Unresolved shell redirect')
                        # Remove an adjacent fd operand; over-approximation is safe.
                        if words and words[-1].isdigit(): words.pop()
                        redirects.append((token, target)); i += 2; continue
                    self.uncertain('Unsupported shell redirection or heredoc'); i += 1; continue
                val, unknown, split = _word(token, env)
                bad_expansion |= unknown
                if split:
                    simple_eval_variable = (words == ['eval'] and len(token) == 1 and token[0][1] == 'plain'
                                            and re.fullmatch(r'\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}', token[0][0]))
                    if simple_eval_variable and not any(ch in val for ch in '*?['):
                        # eval joins its argv using spaces after the shell has
                        # split a plain variable on default IFS whitespace.
                        words.extend(val.split()); i += 1; continue
                    self.uncertain('Unquoted variable field splitting requires review')
                words.append(val); i += 1
            input_stream = stream
            if documents:
                if len(documents) != 1 or documents[0].fd != 0 or any(op == '<' for op, _ in redirects):
                    self.uncertain('Multiple or non-stdin heredoc inputs require review')
                    input_stream = None
                else:
                    document = documents[0]
                    body = document.body
                    if not document.quoted and any(ch in body for ch in ('$', '`', '\\')):
                        self.uncertain('Expanding heredoc input requires review')
                        input_stream = None
                    else:
                        input_stream = body.encode('utf-8')
            for op, target in redirects:
                self.effect('read' if op == '<' else 'write', target, cwd)
            if bad_expansion:
                self.uncertain('Unresolved variable or command substitution')
            if not words:
                stream = None; continue
            assignments = {}
            while words and re.match(r'^[A-Za-z_]\w*=', words[0]):
                key, val = words.pop(0).split('=', 1); assignments[key] = val
            if any(key in {'PATH', 'IFS', 'ENV', 'BASH_ENV', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'LD_PRELOAD', 'LD_LIBRARY_PATH'} for key in assignments):
                self.uncertain('Shell environment assignment may change executable or startup behavior')
            if not words:
                if not bad_expansion: env.update(assignments)
                else:
                    for key in assignments: env.pop(key, None)
                stream = None; continue
            if assignments:
                self.uncertain('Per-command environment assignments require review')
            name = posixpath.basename(words[0]); args = words[1:]
            if '/' in words[0] and words[0] not in ('/bin/'+name, '/usr/bin/'+name):
                self.effect('execute', words[0], cwd)
                self.uncertain('Executable outside known system command paths')
            if name in ('command', 'builtin') and args and not args[0].startswith('-'):
                executable = args[0]
                name, args = posixpath.basename(executable), args[1:]
                if '/' in executable and executable not in ('/bin/' + name, '/usr/bin/' + name):
                    self.effect('execute', executable, cwd)
                    self.uncertain('Wrapped executable outside known system command paths')
            output = None
            if name in ('printf', 'echo'):
                if name == 'printf' and args and args[0] in ('%s', '%s\n'):
                    output = (('' if args[0] == '%s' else '\n').join(args[1:]) + ('\n' if args[0] == '%s\n' and args[1:] else '')).encode()
                elif name == 'echo' and not any(x.startswith('-') for x in args):
                    output = (' '.join(args) + '\n').encode()
                elif name == 'printf' and len(args) == 1 and '%' not in args[0] and '\\' not in args[0]:
                    output = args[0].encode()
            elif name == 'base64':
                decode, paths, options_known = False, [], True
                j = 0
                while j < len(args):
                    arg = args[j]
                    if arg in ('-d', '--decode'): decode = True
                    elif arg in ('-w', '--wrap'):
                        j += 1
                        if j >= len(args) or not args[j].isdigit(): options_known = False
                    elif re.fullmatch(r'(?:-w|--wrap=)[0-9]+', arg): pass
                    elif arg.startswith('-') and arg != '-': options_known = False
                    elif arg != '-': paths.append(arg)
                    j += 1
                for path in paths: self.effect('read', path, cwd)
                if not options_known: self.uncertain('Unsupported base64 option')
                if decode and input_stream is not None and not paths and options_known:
                    try:
                        if len(input_stream) > MAX_DECODED_BYTES * 2:
                            raise ValueError('Decoded input budget exceeded')
                        output = _bounded(base64.b64decode(b''.join(input_stream.split()), validate=True))
                    except (ValueError, TypeError):
                        self.uncertain('Base64 stream cannot be decoded within budget')
            elif name in ('sh','bash','dash'):
                code = None
                if len(args) >= 2 and args[0] in ('-c','-lc'):
                    code = args[1]
                    if len(args) > 2: self.uncertain('Shell positional parameters require review')
                elif (not args or args in (['-s'], ['-'])) and input_stream is not None:
                    try: code = input_stream.decode('utf-8')
                    except UnicodeError: self.uncertain('Decoded shell is not UTF-8')
                else:
                    for arg in args:
                        if not arg.startswith('-'):
                            self.effect('read', arg, cwd); self.effect('execute', arg, cwd); break
                    self.uncertain('Shell input program is not statically available')
                if code is not None and not bad_expansion:
                    self.shell(code, cwd, env, depth+1)
            elif name == 'eval':
                if args and not bad_expansion:
                    nested = self.shell(' '.join(args), cwd, env, depth+1)
                    if nested is not None: cwd, env = nested['cwd'], nested['env']
                else: self.uncertain('Eval input is not a known literal')
            elif name == 'cd':
                if len(args) == 1 and not args[0].startswith('-') and not bad_expansion:
                    self.effect('read', args[0], cwd); cwd = absolute(args[0], cwd)
                else: self.uncertain('Dynamic working directory')
            elif name in ('cat','head','tail','wc','stat','nl','less','more','tee','touch','mkdir','truncate','rm','unlink','rmdir','shred','cp','mv','install'):
                operands, target_dir = [], None
                value_options = {'-n','-c','--lines','--bytes'} if name in ('head','tail') else set()
                if name == 'truncate': value_options |= {'-s','--size','-r','--reference'}
                if name in ('cp','mv','install'): value_options |= {'-t','--target-directory','--suffix'}
                if name in ('mkdir','install'): value_options |= {'-m','--mode','-o','--owner','-g','--group'}
                # Only options with known effects may be silently accepted.
                safe_options = {
                    'cat': {'-n','-b','-s','-v','-E','-T','-A','--number','--number-nonblank','--squeeze-blank'},
                    'head': {'-q','-v','--quiet','--verbose'}, 'tail': {'-q','-v','--quiet','--verbose'},
                    'wc': {'-l','-w','-c','-m','-L','--lines','--words','--bytes','--chars','--max-line-length'},
                    'stat': {'-L','--dereference'}, 'nl': set(), 'less': set(), 'more': set(),
                    'tee': {'-a','--append','-i','--ignore-interrupts'},
                    'touch': {'-a','-m','-c','--no-create'},
                    'mkdir': {'-p','--parents','-v','--verbose'}, 'truncate': {'-c','--no-create'},
                    'rm': {'-r','-R','-f','-rf','-fr','-i','-I','-v','--recursive','--force','--verbose','--one-file-system','--preserve-root'},
                    'unlink': set(), 'rmdir': {'-p','--parents','-v','--verbose'},
                    'shred': {'-u','-z','-v','--remove','--zero','--verbose'},
                    'cp': {'-r','-R','-a','-f','-i','-n','-v','-T','--recursive','--archive','--force','--interactive','--no-clobber','--verbose','--no-target-directory'},
                    'mv': {'-f','-i','-n','-v','-T','--force','--interactive','--no-clobber','--verbose','--no-target-directory'},
                    'install': {'-v','--verbose'}
                }[name]
                end_options = False; j = 0
                while j < len(args):
                    arg = args[j]
                    if not end_options and arg == '--': end_options=True; j+=1; continue
                    if not end_options and arg in value_options:
                        if j+1 >= len(args): self.uncertain('Missing command option value'); break
                        if arg in ('-t','--target-directory'): target_dir=args[j+1]
                        if arg in ('-r','--reference'): self.effect('read', args[j+1], cwd)
                        j+=2; continue
                    if not end_options and arg.startswith('--target-directory='):
                        target_dir=arg.split('=',1)[1]; j+=1; continue
                    if not end_options and arg.startswith('-') and arg != '-':
                        if arg not in safe_options:
                            self.uncertain('Unsupported ' + name + ' option requires review')
                        j+=1; continue
                    if arg != '-': operands.append(arg)
                    j+=1
                recursive = name == 'mv' or any(a in ('-r','-R','--recursive','-rf','-fr','-a','--archive') for a in args)
                if name in ('cp','mv','install'):
                    sources = operands if target_dir else operands[:-1]
                    dest = target_dir or (operands[-1] if len(operands)>=2 else None)
                    if not dest or not sources: self.uncertain('Copy/move operands unresolved')
                    for src in sources:
                        self.effect('read',src,cwd,recursive=recursive)
                        if name=='mv': self.effect('delete',src,cwd,recursive=recursive)
                        if dest:
                            self.effect('write',dest,cwd,recursive=recursive)
                            self.effect('write',posixpath.join(dest,posixpath.basename(src)),cwd,recursive=recursive)
                else:
                    kind = 'delete' if name in ('rm','unlink','rmdir','shred') else 'write' if name in ('tee','touch','mkdir','truncate') else 'read'
                    for path in operands: self.effect(kind,path,cwd,recursive=recursive)
            elif name == 'curl':
                self.curl(args,cwd)
            elif name == 'expr':
                try:
                    if not args or not all(re.fullmatch(r'[+-]?[0-9]+|[+*/%()-]', arg) for arg in args):
                        raise ValueError('Unsupported expr syntax')
                    output = (_arithmetic(' '.join(args), {}) + '\n').encode('utf-8')
                except (ValueError, SyntaxError, RecursionError):
                    self.uncertain('Expr is not bounded fixed integer arithmetic')
            elif name == 'sort' and all(arg in ('-n', '-r', '-u', '-nr', '-rn', '--numeric-sort', '--reverse', '--unique') for arg in args):
                # Sorting stdin has no file effect. Its output is not reconstructed.
                pass
            elif name in ('true','false',':','pwd','sleep'):
                pass
            elif re.fullmatch(r'python(?:[23](?:\.\d+)?)?', name):
                pyargs = list(args)
                startup_flags = set()
                while pyargs and pyargs[0] in ('-I', '-S', '-B', '-E', '-s', '-u'):
                    startup_flags.add(pyargs.pop(0))
                isolated = {'-I','-S','-B'}.issubset(startup_flags)
                if pyargs[:3] == ['-m', 'zipfile', '-c'] and len(pyargs) > 4:
                    self.effect('write', pyargs[3], cwd)
                    for path in pyargs[4:]: self.effect('read', path, cwd, recursive=True)
                elif len(pyargs) >= 2 and pyargs[0] == '-c' and not bad_expansion:
                    output = self.python(pyargs[1], cwd, depth + 1, isolated=isolated)
                elif (not pyargs or pyargs[0] == '-') and input_stream is not None and not bad_expansion:
                    try: output = self.python(input_stream.decode('utf-8'), cwd, depth + 1, isolated=isolated)
                    except UnicodeError: self.uncertain('Python input is not UTF-8')
                else:
                    if pyargs and pyargs[0] != '-' and not pyargs[0].startswith('-'):
                        self.effect('read', pyargs[0], cwd); self.effect('execute', pyargs[0], cwd)
                    self.uncertain('Python input or interpreter options are not statically supported')
            else:
                if args and name in ('source','.'):
                    self.effect('read',args[0],cwd); self.effect('execute',args[0],cwd)
                self.uncertain('Unknown program effects: '+name[:60])
            stream = output if connector == '|' and not bad_expansion else None
        return {'cwd': cwd, 'env': env}

    def python(self, code, cwd, depth, *, isolated=False):
        before = list(self.uncertainties)
        output = self._python_constants(code, cwd, depth)
        if depth <= MAX_DEPTH and describe_python(code, cwd, self.effect):
            # Keep exact constant output when the old bounded evaluator knew it;
            # otherwise only describe effects, never invent a computed value.
            # Only remove the old constant evaluator's unsupported-statement
            # notices. Path, effect-capacity and static-budget gaps must survive.
            self.uncertainties = list(dict.fromkeys(before + [reason for reason in self.uncertainties
                if not reason.startswith('Python statement effects are not fully known: ')]))
            if not isolated:
                self.python_isolation_required = True
                self.uncertain(PYTHON_STARTUP_REVIEW)
        return output

    def _python_constants(self, code, cwd, depth):
        """Describe a bounded straight-line subset; all other Python remains unknown."""
        if depth > MAX_DEPTH or len(code.encode('utf-8')) > self.bytes_left:
            self.uncertain('Python static depth or byte budget exceeded'); return None
        self.bytes_left -= len(code.encode('utf-8'))
        try:
            tree = ast.parse(code)
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError('Python static node budget exceeded')
        except (ValueError, SyntaxError, RecursionError):
            self.uncertain('Python source is not parseable within the static budget'); return None
        values, aliases, printed = {}, {}, []
        supported = True
        calls_left = MAX_AST_NODES

        def callable_name(node, child):
            if isinstance(node, ast.Name):
                return aliases.get(node.id, node.id if node.id not in values else '')
            if isinstance(node, ast.Attribute):
                root = callable_name(node.value, child)
                return root + '.' + node.attr if root else ''
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'getattr' and len(node.args) == 2 and not node.keywords:
                root, attr = callable_name(node.args[0], child), child(node.args[1])
                return root + '.' + attr if root and isinstance(attr, str) else ''
            return ''

        def known_call(node, child):
            nonlocal calls_left
            calls_left -= 1
            if calls_left < 0: raise ValueError('Python static call budget exceeded')
            name = callable_name(node.func, child)
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('decode', 'encode'):
                value = child(node.func.value)
                if node.keywords or len(node.args) > 1: raise ValueError('Unknown codec arguments')
                codec = child(node.args[0]) if node.args else 'utf-8'
                if codec not in ('utf-8', 'utf8', 'ascii'): raise ValueError('Unsupported static codec')
                if node.func.attr == 'decode' and isinstance(value, bytes): return value.decode(codec)
                if node.func.attr == 'encode' and isinstance(value, str): return value.encode(codec)
                raise ValueError('Codec value is not a known string')
            if name in ('base64.b64decode', 'base64.standard_b64decode'):
                if len(node.args) != 1 or node.keywords: raise ValueError('Unknown base64 arguments')
                data = child(node.args[0])
                if isinstance(data, str): data = data.encode('ascii')
                if not isinstance(data, bytes) or len(data) > MAX_DECODED_BYTES * 2:
                    raise ValueError('Base64 input budget exceeded')
                # Runtime decoding without validate ignores non-alphabet bytes. Do
                # not infer stricter/different semantics from an invalid literal.
                return _bounded(base64.b64decode(data, validate=True))
            if name in ('len', 'str', 'int') and len(node.args) == 1 and not node.keywords:
                value = child(node.args[0])
                if name == 'len' and isinstance(value, (str, bytes)): return len(value)
                if name == 'str' and isinstance(value, (str, int)): return str(value)
                if name == 'int' and isinstance(value, str) and re.fullmatch(r'[+-]?[0-9]+', value): return _bounded(int(value))
                raise ValueError('Unsupported static builtin argument')
            if name == 'print' and not node.keywords:
                parts = [child(arg) for arg in node.args]
                if any(not isinstance(value, (str, int)) for value in parts): raise ValueError('Unsupported print value')
                printed.append(_bounded(' '.join(str(value) for value in parts) + '\n'))
                return None
            if name in ('eval', 'exec') and len(node.args) == 1 and not node.keywords:
                source = child(node.args[0])
                if isinstance(source, bytes): source = source.decode('utf-8')
                if not isinstance(source, str): raise ValueError('Dynamic Python input')
                if name == 'eval': return _literal(_expression(source), values, known_call)
                # Nested execution may mutate bindings; do not reuse stale names.
                self.python(source, cwd, depth + 1)
                values.clear(); aliases.clear()
                raise ValueError('Nested exec bindings require review')
            if name in ('os.system',) and len(node.args) == 1 and not node.keywords:
                source = child(node.args[0])
                if isinstance(source, str): self.shell(source, cwd, depth=depth + 1)
                raise ValueError('Python subprocess return and environment require review')
            if name in ('open', 'builtins.open'):
                if not node.args: raise ValueError('Unknown file target')
                target = child(node.args[0])
                mode = child(node.args[1]) if len(node.args) > 1 else 'r'
                for keyword in node.keywords:
                    if keyword.arg == 'mode': mode = child(keyword.value)
                if not isinstance(target, str) or not isinstance(mode, str): raise ValueError('Dynamic file open')
                if not re.fullmatch(r'[rwax][bt]?\+?|[rwax]\+[bt]?', mode): raise ValueError('Unsupported open mode')
                if mode.startswith('r') or '+' in mode: self.effect('read', target, cwd)
                if mode[0] in 'wax' or '+' in mode: self.effect('write', target, cwd)
                raise ValueError('File content and subsequent handle operations require review')
            if isinstance(node.func, ast.Attribute):
                try: child(node.func.value)
                except (ValueError, TypeError, UnicodeError, SyntaxError, RecursionError): pass
            # Inspect arguments for concrete nested effects, but never execute an
            # unrecognized function or resolve an attribute on a live object.
            for arg in node.args:
                try: child(arg)
                except (ValueError, TypeError, UnicodeError, SyntaxError, RecursionError): pass
            for keyword in node.keywords:
                try: child(keyword.value)
                except (ValueError, TypeError, UnicodeError, SyntaxError, RecursionError): pass
            raise ValueError('Unknown Python call')

        for statement in tree.body:
            try:
                if isinstance(statement, ast.Import):
                    for item in statement.names:
                        if item.name not in ('base64', 'builtins', 'os'):
                            raise ValueError('Unknown Python import')
                        aliases[item.asname or item.name] = item.name
                elif isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module in ('base64', 'builtins'):
                    for item in statement.names:
                        if item.name == '*': raise ValueError('Star import requires review')
                        aliases[item.asname or item.name] = statement.module + '.' + item.name
                elif isinstance(statement, ast.Assign) and all(isinstance(target, ast.Name) for target in statement.targets):
                    value = _literal(statement.value, values, known_call)
                    for target in statement.targets:
                        values[target.id] = value; aliases.pop(target.id, None)
                elif isinstance(statement, ast.Expr):
                    _literal(statement.value, values, known_call)
                elif isinstance(statement, ast.Pass):
                    pass
                else:
                    raise ValueError('Unsupported Python statement')
            except (ValueError, TypeError, UnicodeError, SyntaxError, RecursionError):
                supported = False
                self.uncertain('Python statement effects are not fully known: ' + type(statement).__name__)
                # Unknown statements may change names; later constant inference
                # must not use bindings from before that statement.
                values.clear(); aliases.clear()
        if supported:
            try: return _bounded(''.join(printed)).encode('utf-8')
            except ValueError: self.uncertain('Python output budget exceeded')
        return None

    def curl(self, args, cwd):
        if not args or args[0] not in ('--disable', '-q'):
            self.uncertain('Curl default config is unknown; use --disable as the first argument')
        urls, source_paths, payloads, content_types = [], [], [], []
        explicit_method, default_method, output = None, 'GET', None
        transfer, get, redirects_followed, payload_unknown = False, False, False, False
        header_unknown = False
        data_opts = {'-d', '--data', '--data-binary', '--data-raw', '--data-urlencode', '--json', '-F', '--form', '-T', '--upload-file'}
        ordinary = {'-H', '--header', '-A', '--user-agent', '-u', '--user', '--connect-timeout', '--max-time', '-m', '--retry', '--cacert', '--cert', '--key', '-e', '--referer', '-w', '--write-out', '--max-redirs', '--noproxy'}
        switches = {'--disable', '-q', '--fail', '-f', '--silent', '-s', '--show-error', '-S', '--compressed', '--no-progress-meter', '-i', '--include'}
        i = 0
        while i < len(args):
            arg, inline = args[i], None
            opt = arg
            if arg.startswith('--') and '=' in arg:
                opt, inline = arg.split('=', 1)
            elif len(arg) > 2 and arg[:2] in ('-X', '-d', '-T', '-F', '-o', '-H', '-u', '-w'):
                opt, inline = arg[:2], arg[2:]
            needs = opt in data_opts | ordinary | {'-X', '--request', '-o', '--output', '--url', '-K', '--config', '--proxy', '-x', '--resolve', '--connect-to'}
            if needs:
                if inline is None:
                    i += 1
                    if i >= len(args):
                        self.uncertain('Missing curl option value'); break
                    val = args[i]
                else:
                    val = inline
                if opt in data_opts:
                    transfer = True
                    default_method = 'PUT' if opt in ('-T', '--upload-file') else 'POST'
                    path = None
                    if opt in ('-T', '--upload-file'):
                        path = val
                    elif opt in ('-F', '--form'):
                        payload_unknown = True
                        if re.search(r'=[@<]', val):
                            path = re.split(r'=[@<]', val, maxsplit=1)[1].split(';', 1)[0]
                    elif opt == '--data-urlencode':
                        payload_unknown = True
                        if '@' in val: path = val.split('@', 1)[1]
                    elif val.startswith('@') and opt != '--data-raw':
                        path = val[1:]
                    if path is not None:
                        if opt not in ('--data-binary', '-T', '--upload-file'):
                            payload_unknown = True
                            self.uncertain('File payload is not explicitly sent as unchanged bytes')
                        if path in ('', '-'):
                            payload_unknown = True
                        else:
                            self.effect('read', path, cwd)
                            source_paths.append(absolute(path, cwd))
                        payloads.append(('file', None, opt))
                    else:
                        payloads.append(('inline', val, opt))
                elif opt in ('-X', '--request'):
                    explicit_method = val.upper()
                    if val != explicit_method: self.uncertain('Noncanonical curl method requires review')
                elif opt in ('-o', '--output'):
                    output = val
                elif opt == '--url':
                    urls.append(val)
                elif opt in ('-K', '--config'):
                    self.effect('read', val, cwd); payload_unknown = True; header_unknown = True
                    self.uncertain('Curl config may change network effects')
                elif opt in ('-w', '--write-out'):
                    # Status formatting is output only. Format files and curl's
                    # output redirection language are not covered by this case.
                    if val.startswith('@'):
                        if val[1:] not in ('', '-'):
                            self.effect('read', val[1:], cwd)
                        self.uncertain('Curl write-out format source requires review')
                    else:
                        plain = re.sub(r'%(?:%|\{(?:http_code|response_code|url_effective|http_version|content_type|size_download|time_total|time_connect|num_redirects|exitcode|errormsg)\})', '', val)
                        if '%' in plain:
                            self.uncertain('Unsupported curl write-out control requires review')
                elif opt == '--max-redirs':
                    # This option alone does not enable redirects; -L still
                    # requires a separate review of unknown destinations.
                    if not re.fullmatch(r'-1|[0-9]{1,6}', val):
                        self.uncertain('Invalid curl redirect limit')
                elif opt == '--noproxy':
                    # This value selects hosts that bypass an existing proxy;
                    # it is not another URL and grants no destination access.
                    # The actual URL still receives the normal network checks.
                    if any(ord(ch) < 32 or ord(ch) == 127 for ch in val):
                        self.uncertain('Invalid curl proxy exclusion list')
                elif opt == '--retry':
                    if val != '0': self.uncertain('Curl retry may send more than one request')
                elif opt in ('--cacert', '--cert', '--key'):
                    self.effect('read', val, cwd)
                    if opt in ('--cert', '--key'): self.uncertain('TLS client credential use requires review')
                elif opt in ('-A', '--user-agent', '-e', '--referer'):
                    self.uncertain('Custom request metadata is outside the fixed payload grant')
                elif opt in ('-u', '--user'):
                    self.uncertain('Credential-bearing network request requires review')
                elif opt in ('-H', '--header'):
                    if val.startswith('@'):
                        self.effect('read', val[1:], cwd); header_unknown = True
                        self.uncertain('Header file content requires review')
                    elif val.lower().startswith('content-type:'):
                        content_types.append(val.split(':', 1)[1].strip())
                        if any(ord(ch) < 32 or ord(ch) == 127 for ch in val): header_unknown = True
                    elif val.lower().startswith(('authorization:', 'proxy-authorization:', 'cookie:')):
                        self.uncertain('Credential-bearing network header requires review')
                    elif val.lower().startswith('content-type;'):
                        header_unknown = True
                    else:
                        self.uncertain('Custom request header is outside the fixed payload grant')
                elif opt in ('--proxy', '-x', '--resolve', '--connect-to'):
                    self.uncertain('Curl destination override requires review')
            elif opt in ('-I', '--head'):
                default_method = 'HEAD'
            elif opt in ('-G', '--get'):
                get = True
            elif opt in ('-L', '--location', '--location-trusted'):
                redirects_followed = True
                self.uncertain('Redirect destinations require review')
            elif opt in ('-O', '--remote-name'):
                self.uncertain('Remote output filename requires review')
            elif re.fullmatch(r'-[fsSL]+', opt):
                if 'L' in opt:
                    redirects_followed = True
                    self.uncertain('Redirect destinations require review')
            elif opt.startswith('-') and opt not in switches:
                self.uncertain('Unsupported curl option')
            elif opt not in switches:
                urls.append(arg)
            i += 1
        if output and output != '-': self.effect('write', output, cwd)
        method = explicit_method or ('GET' if get else default_method)
        if get and transfer:
            payload_unknown = True
            self.uncertain('Curl query serialization is not statically reconstructed')
        if len(payloads) > 1:
            payload_unknown = True
            self.uncertain('Multiple curl payload parts require review')
        if payload_unknown:
            transfer_mode, body_sha256 = 'unknown', None
        elif not payloads:
            transfer_mode, body_sha256 = 'none', hashlib.sha256(b'').hexdigest()
        elif payloads[0][0] == 'file':
            transfer_mode, body_sha256 = 'file', None
        else:
            transfer_mode = 'inline'
            body_sha256 = hashlib.sha256(payloads[0][1].encode('utf-8')).hexdigest()
        if header_unknown or len(content_types) > 1:
            content_type = None
            self.uncertain('Curl content type is not unambiguous')
        elif content_types:
            content_type = content_types[0]
        elif payloads and payloads[0][2] == '--json':
            content_type = 'application/json'
        elif payloads and payloads[0][2] not in ('-T', '--upload-file', '-F', '--form'):
            content_type = 'application/x-www-form-urlencoded'
        elif payloads and payloads[0][2] in ('-F', '--form'):
            content_type = None
        else:
            content_type = ''
        if transfer_mode == 'unknown': self.uncertain('Curl request payload is not statically bounded to one source')
        if not urls: self.uncertain('Network destination is unresolved')
        for url in urls:
            try:
                parts = urlsplit(url)
                if parts.scheme not in ('https', 'http') or not parts.hostname or parts.username or parts.password:
                    self.uncertain('Unsupported or credential-bearing network URL')
                if any(ch in url for ch in '{}') or any(ch in parts.path + parts.query + parts.fragment for ch in '[]'):
                    self.uncertain('Curl URL globbing may send more than one request')
            except ValueError:
                self.uncertain('Invalid network URL')
            self.effect('network', url=url, method=method, transfer=transfer,
                        transfer_mode=transfer_mode, source_paths=list(source_paths),
                        redirects_followed=redirects_followed, content_type=content_type,
                        body_sha256=body_sha256)

    def describe(self):
        args=self.state.get('proposed_tool_args',{})
        if not isinstance(args,dict):
            self.uncertain('Tool arguments must be an object')
        elif self.tool=='terminal':
            cwd=self.context.get('effective_cwd') or args.get('workdir') or args.get('cwd') or self.cwd
            if not isinstance(cwd,str):self.uncertain('Invalid command working directory')
            else:self.shell(args.get('command'),absolute(cwd,self.cwd))
        elif self.tool == 'write_file':
            contract = self.state.get('host_tool_contract')
            if not isinstance(contract, dict):
                self.uncertain('Write effects require the installed host write contract')
            else:
                effects = contract.get('effects')
                if not isinstance(effects, list) or not effects:
                    self.uncertain('Host write effect list is missing')
                else:
                    for item in effects:
                        if not isinstance(item, dict) or item.get('kind') not in ('read', 'write') or not isinstance(item.get('path'), str):
                            self.uncertain('Host write effect is invalid'); continue
                        self.effect(item['kind'], item['path'])
                if contract.get('complete') is not True:
                    self.uncertain('Host write effects are incomplete')
                for reason in contract.get('uncertainties', []) if isinstance(contract.get('uncertainties'), list) else []:
                    if isinstance(reason, str): self.uncertain(reason)
        elif self.tool in ('read_file','search_files','patch','edit_file','apply_patch','delete_file'):
            kind='read' if self.tool in ('read_file','search_files') else 'delete' if self.tool=='delete_file' else 'write'
            path=args.get('path',args.get('file_path'))
            if isinstance(path,str):self.effect(kind,path,recursive=self.tool == 'search_files')
            elif self.tool in ('patch','apply_patch'):
                patch=args.get('patch',args.get('patch_text',args.get('input')))
                if not isinstance(patch,str) or len(patch.encode())>MAX_BYTES:self.uncertain('Patch target is unresolved')
                else:
                    found=False
                    for line in patch.splitlines():
                        match=re.match(r'^\*\*\* (?:Add|Update|Delete|Move to) File: (.+)$',line)
                        if not match:match=re.match(r'^\*\*\* Move to: (.+)$',line)
                        if match:self.effect('write',match.group(1));found=True
                        elif line.startswith(('--- ','+++ ')):
                            target=line[4:].split('\t')[0]
                            if target!='/dev/null':
                                if target.startswith(('a/','b/')):target=target[2:]
                                self.effect('write',target);found=True
                    if not found:self.uncertain('Patch target is unresolved')
            else:self.uncertain('File target is unresolved')
        elif self.tool in ('skill_view', 'skills_list'):
            contract = self.state.get('host_tool_contract', {})
            if not isinstance(contract, dict) or contract.get('effect') != 'read_only':
                self.uncertain('Installed skill inspection needs a trusted host read-only contract')
            if self.tool == 'skill_view' and args.get('inspect_only') is not True:
                self.uncertain('Skill view must use the host inspect-only mode; normal loading may execute commands or configure credentials')
            for path in contract.get('read_paths', []) if isinstance(contract, dict) else []:
                if isinstance(path, str): self.effect('read', path)
            # This contract only describes the installed-document/index tool.
            # Instructions returned by it never authorize a subsequent action.
        elif self.tool in ('clarify', 'todo_list'):
            contracts = {'clarify': 'user_interaction', 'todo_list': 'session_state'}
            effect = contracts[self.tool]
            if self.state.get('host_tool_contract', {}).get('effect') != effect:
                self.uncertain('Native session operation needs its host-owned contract')
            else:
                self.effect(effect)
        elif self.tool == 'web_search':
            try:
                query, limit = search_request(args)
            except (ValueError, TypeError) as exc:
                # Invalid arguments do not erase this tool's known effect.
                # Explicit search prohibitions still dominate uncertainty.
                self.effect('network_search')
                self.uncertain(str(exc))
            else:
                self.effect('network_search', query=query, limit=limit)
        elif self.tool == 'web_extract':
            # Native tools/web_tools.py accepts only urls and char_limit, and
            # dispatches at most five URLs. This declares webpage reading, not
            # an observed HTTP GET at the remote site or the provider transport.
            urls = args.get('urls')
            if not isinstance(urls, list) or not urls or len(urls) > 5:
                self.uncertain('Web extraction needs one to five explicit URLs')
            if isinstance(urls, list):
                for url in urls[:5]:
                    if not isinstance(url, str) or not url.strip() or len(url.encode('utf-8')) > MAX_BYTES:
                        self.uncertain('Web extraction URL is invalid'); continue
                    try:
                        parts = urlsplit(url)
                        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
                            self.uncertain('Unsupported or credential-bearing extraction URL')
                    except ValueError:
                        self.uncertain('Web extraction URL is invalid')
                    self.effect('network', url=url, operation='read', method=None,
                                transfer=False, transfer_mode='none', source_paths=[])
            contract=self.state.get('host_tool_contract',{})
            if contract.get('source')!='polarbear_web_adapter' or contract.get('complete') is not True:
                self.uncertain('Web cache effects need the profile-owned complete contract')
            else:
                for item in contract.get('effects',[]):
                    if item.get('kind')=='write' and isinstance(item.get('path'),str):
                        self.effect('write',item['path'])
        elif self.tool=='delegate_task':
            contract=self.state.get('host_tool_contract',{})
            if contract.get('source')!='polarbear_delegation_adapter':
                self.uncertain('Delegation needs verified host parent/child authorization')
            else:self.effect('delegation')
        elif self.tool in ('web_fetch','fetch_url','browse'):
            url=args.get('url')
            if isinstance(url,str):self.effect('network',url=url,method='GET',transfer=False)
            else:self.uncertain('Network destination is unresolved')
        else:
            self.uncertain('Unrecognized tool effects: '+str(self.tool)[:60])
        return {'tool_name':self.tool,'cwd':self.cwd,'effects':self.effects,
                'uncertainties':self.uncertainties,'complete':not self.uncertainties,
                'python_isolation_required':self.python_isolation_required}


def describe_action(state):
    return _Description(state).describe()


def isolate_known_python(command):
    """Normalize only already-understood inline Python, preserving its source.

    -I -S -B prevent task-local import shadowing, site startup and bytecode writes.
    Complex shell syntax is left unchanged and retains its review requirement.
    """
    if not isinstance(command,str):return None
    program=r'(?:/usr/bin/|/bin/)?python(?:[23](?:\.\d+)?)?'
    match=re.match(r'^(\s*)('+program+r')(?=\s|$)',command)
    if match:
        prefix=command[match.end():].lstrip().split()
        flags=set()
        for arg in prefix:
            if arg not in {'-I','-S','-B','-E','-s','-u'}:break
            flags.add(arg)
        if not {'-I','-S','-B'}.issubset(flags):
            return command[:match.end()]+' -I -S -B'+command[match.end():]
    try:
        segments=[[]]
        for token in _lex(command):
            if token=='|':segments.append([])
            elif isinstance(token,tuple):
                value,unknown,splitting=_word(token,{})
                if unknown or splitting:return None
                segments[-1].append(value)
            else:return None
        changed=False
        for words in segments:
            if not words:return None
            if re.fullmatch(program,words[0]):
                flags=set()
                for arg in words[1:]:
                    if arg not in {'-I','-S','-B','-E','-s','-u'}:break
                    flags.add(arg)
                if not {'-I','-S','-B'}.issubset(flags):
                    words[1:1]=['-I','-S','-B'];changed=True
        return ' | '.join(shlex.join(words) for words in segments) if changed else None
    except (ValueError,TypeError):return None
