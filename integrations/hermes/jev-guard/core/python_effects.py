"""Describe a limited Python data-processing subset without executing it.

Only built-in data and named standard-library operations are understood. Files
must have statically known paths. Dynamic imports, user functions, eval/exec,
unknown methods and data-derived file names remain unresolved.
"""
import ast
import posixpath
from dataclasses import dataclass


class Unknown(ValueError):
    pass


@dataclass(frozen=True)
class Value:
    kind: str = 'data'
    name: str = ''
    literal: object = None
    known: bool = False
    owner: object = None


DATA = Value()
MODULES = {
    'base64': {'b64decode', 'standard_b64decode', 'b64encode', 'standard_b64encode'},
    'decimal': {'Decimal'},
    'unicodedata': {'name', 'category', 'normalize', 'combining', 'decimal', 'digit', 'numeric'},
    'math': {'ceil', 'floor', 'sqrt', 'isclose', 'isfinite', 'fabs', 'fsum', 'prod', 'log', 'log10'},
    'statistics': {'mean', 'median', 'stdev', 'pstdev'},
    'csv': {'reader', 'DictReader'},
    'io': {'StringIO', 'BytesIO'},
    'json': {'loads', 'dumps', 'load', 'dump'},
    'pathlib': {'Path', 'PosixPath', 'PurePath', 'PurePosixPath'},
    'zipfile': {'ZipFile'},
    're': {'compile', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'sub', 'escape'},
    'html': {'escape', 'unescape'},
    'collections': {'Counter'},
    'sys': {'exit'},
}
BUILTINS = {'print', 'len', 'sum', 'min', 'max', 'sorted', 'reversed', 'list', 'tuple', 'set',
            'dict', 'str', 'int', 'float', 'bool', 'bytes', 'bytearray', 'abs', 'round', 'all',
            'any', 'enumerate', 'zip', 'range', 'iter', 'next', 'repr', 'ord', 'chr', 'format',
            'map', 'open', 'ValueError', 'RuntimeError', 'TypeError', 'Exception'}
PURE_CALLBACKS = {'str', 'int', 'float', 'bool', 'repr', 'len', 'abs', 'round', 'ord', 'chr'}
DATA_METHODS = {'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines', 'join', 'replace',
                'lower', 'upper', 'casefold', 'startswith', 'endswith', 'count', 'find', 'index',
                'encode', 'decode', 'isdigit', 'isalpha', 'isspace',
                'append', 'extend', 'insert', 'pop', 'remove', 'sort', 'reverse', 'copy', 'clear',
                'get', 'items', 'keys', 'values', 'update', 'setdefault', 'add', 'discard',
                'group', 'groups', 'groupdict', 'search', 'match', 'fullmatch', 'findall', 'sub'}


def literal(value):
    return Value(literal=value, known=True)


class Analyzer:
    def __init__(self, effect, cwd):
        self.effect, self.cwd, self.env = effect, cwd, {}
        self.remaining = 4096

    def step(self):
        self.remaining -= 1
        if self.remaining < 0:
            raise Unknown('Python analysis budget exceeded')

    def target(self, value):
        if value.kind == 'path':
            return value.name
        if value.kind == 'data' and value.known and isinstance(value.literal, str):
            return value.literal
        raise Unknown('File target is not a known path')

    def file_effect(self, kind, value):
        self.effect(kind, self.target(value), self.cwd)

    def attr(self, value, name):
        if name.startswith('_'):
            raise Unknown('Python internals are not data operations')
        if value.kind == 'module':
            if name in MODULES[value.name]:
                return Value('function', value.name + '.' + name)
            if value.name == 'sys' and name in {'stdin', 'stdout', 'stderr'}:
                return Value(name)
            if value.name == 're' and name in {'I','S','M','X','A','U','IGNORECASE','DOTALL','MULTILINE','VERBOSE','ASCII','UNICODE'}:
                return DATA
            if value.name == 'zipfile' and name in {'ZIP_STORED','ZIP_DEFLATED','ZIP_BZIP2','ZIP_LZMA'}:
                return DATA
            if value.name == 'math' and name in {'pi','e','tau','inf','nan'}:
                return DATA
            raise Unknown('Unknown module attribute')
        if value.kind == 'path':
            if name == 'parent':
                return Value('path', posixpath.dirname(value.name))
            if name in {'name','stem','suffix'}:
                base = posixpath.basename(value.name)
                return literal(base if name=='name' else posixpath.splitext(base)[0 if name=='stem' else 1])
            if name in {'read_text','read_bytes','write_text','write_bytes','open','joinpath','resolve',
                        'absolute','as_posix','is_symlink','exists','is_file','is_dir','stat'}:
                return Value('method', name, owner=value)
        elif value.kind in {'file','memory','stdin','stdout','stderr'}:
            if value.kind in {'stdin','stdout','stderr'} and name == 'buffer':
                return value
            if name in {'read','readline','readlines','write','writelines','close','flush','seek','tell'}:
                return Value('method', name, owner=value)
        elif value.kind == 'archive' and name in {'write','writestr','namelist','read','close','testzip'}:
            return Value('method', name, owner=value)
        elif value.kind == 'csv_reader' and name in {'fieldnames','line_num'}:
            return DATA
        elif value.kind == 'data' and name in DATA_METHODS:
            return Value('method', name, owner=value)
        raise Unknown('Unknown Python object attribute')

    @staticmethod
    def arg(args, keywords, n, key, default=None):
        return args[n] if len(args)>n else keywords.get(key, default)

    def opened(self, path, mode):
        target = self.target(path)
        if not mode.known or not isinstance(mode.literal,str) or mode.literal not in {
                'r','rb','rt','w','wb','wt','a','ab','at','x','xb','xt',
                'r+','rb+','r+b','w+','wb+','w+b','a+','ab+','a+b'}:
            raise Unknown('Unknown file mode')
        if mode.literal.startswith('r') or '+' in mode.literal:
            self.effect('read',target,self.cwd)
        if mode.literal[0] in 'wax' or '+' in mode.literal:
            self.effect('write',target,self.cwd)
        return Value('file',target)

    def call(self, function, args, keywords):
        self.step()
        for key,value in keywords.items():
            if value.kind in {'function','method','module','unknown'} and not (
                    function.kind=='function' and function.name in {'sorted','min','max'} and key=='key'
                    and value.kind=='function' and value.name in PURE_CALLBACKS):
                raise Unknown('Executable callback in data operation')
        if function.kind == 'method':
            owner, name = function.owner, function.name
            if owner.kind == 'data':
                if any(v.kind != 'data' for v in args+list(keywords.values())):
                    raise Unknown('Data method received a capability')
                return DATA
            if owner.kind == 'path':
                if name in {'read_text','read_bytes','write_text','write_bytes'}:
                    self.effect('read' if name.startswith('read') else 'write',owner.name,self.cwd)
                    return DATA
                if name == 'open':
                    return self.opened(owner,self.arg(args,keywords,0,'mode',literal('r')))
                if name == 'joinpath':
                    return Value('path',posixpath.join(owner.name,*(self.target(a) for a in args)))
                if name in {'resolve','absolute','as_posix'}:
                    return literal(owner.name) if name=='as_posix' else owner
                self.effect('read',owner.name,self.cwd)
                return DATA
            if owner.kind in {'file','memory','stdin','stdout','stderr'}:
                if owner.kind=='file' and name.startswith('read'):
                    self.effect('read',owner.name,self.cwd)
                elif owner.kind=='file' and name.startswith('write'):
                    self.effect('write',owner.name,self.cwd)
                return DATA
            if owner.kind == 'archive':
                if name == 'write':
                    self.file_effect('read',self.arg(args,keywords,0,'filename'))
                    self.effect('write',owner.name,self.cwd)
                elif name == 'writestr':
                    self.effect('write',owner.name,self.cwd)
                elif name in {'read','namelist','testzip'}:
                    self.effect('read',owner.name,self.cwd)
                return DATA
        if function.kind != 'function':
            raise Unknown('Dynamic Python call')
        name = function.name
        if name == 'open':
            # A custom opener is executable code, not an ordinary file open.
            if 'opener' in keywords:
                raise Unknown('Custom file opener')
            return self.opened(self.arg(args,keywords,0,'file'),self.arg(args,keywords,1,'mode',literal('r')))
        if name.startswith('pathlib.'):
            return Value('path',posixpath.join(*(self.target(a) for a in args)) if args else '.')
        if name == 'zipfile.ZipFile':
            path=self.arg(args,keywords,0,'file');mode=self.arg(args,keywords,1,'mode',literal('r'))
            if not mode.known or mode.literal not in {'r','w','x','a'}:
                raise Unknown('Unknown archive mode')
            self.file_effect('read' if mode.literal=='r' else 'write',path)
            if mode.literal=='a':self.file_effect('read',path)
            return Value('archive',self.target(path))
        if name in {'io.StringIO','io.BytesIO'}:
            return Value('memory')
        if name in {'csv.reader','csv.DictReader','json.load'}:
            stream=self.arg(args,keywords,0,'fp')
            if stream is None or stream.kind not in {'file','memory','stdin','data'}:
                raise Unknown('Unknown input stream')
            if stream.kind=='file':self.effect('read',stream.name,self.cwd)
            return Value('csv_reader') if name.startswith('csv.') else DATA
        if name == 'json.dump':
            stream=self.arg(args,keywords,1,'fp')
            if stream is None or stream.kind not in {'file','memory','stdout','stderr'}:
                raise Unknown('Unknown output stream')
            if stream.kind=='file':self.effect('write',stream.name,self.cwd)
            return DATA
        if name == 'print':
            stream=keywords.get('file')
            if stream and stream.kind=='file':self.effect('write',stream.name,self.cwd)
            elif stream and stream.kind not in {'stdout','stderr','memory'}:raise Unknown('Unknown print stream')
            return DATA
        if name == 'str' and len(args)==1 and args[0].kind=='path':
            return literal(args[0].name)
        if name == 'map':
            if not args or args[0].kind!='function' or args[0].name not in PURE_CALLBACKS:
                raise Unknown('Unknown mapping function')
            args=args[1:]
        if name in {'sorted','min','max'} and 'key' in keywords:
            key=keywords['key']
            if key.kind!='function' or key.name not in PURE_CALLBACKS:
                raise Unknown('Unknown ordering function')
            keywords={k:v for k,v in keywords.items() if k!='key'}
        if any(v.kind in {'path','function','method','module','unknown'} for v in args+list(keywords.values())):
            raise Unknown('Executable value passed to data operation')
        if name in BUILTINS or any(name == module+'.'+f for module,fs in MODULES.items() for f in fs):
            return DATA
        raise Unknown('Unknown Python function')

    def expr(self,node):
        self.step()
        if isinstance(node,ast.Constant):return literal(node.value)
        if isinstance(node,ast.Name):
            if node.id in self.env:return self.env[node.id]
            if node.id in BUILTINS:return Value('function',node.id)
            raise Unknown('Unknown name')
        if isinstance(node,ast.Attribute):return self.attr(self.expr(node.value),node.attr)
        if isinstance(node,ast.Call):
            if any(isinstance(a,ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                raise Unknown('Unpacked call arguments')
            return self.call(self.expr(node.func),[self.expr(a) for a in node.args],{k.arg:self.expr(k.value) for k in node.keywords})
        if isinstance(node,(ast.List,ast.Tuple,ast.Set)):
            for element in node.elts:
                if self.expr(element).kind!='data':raise Unknown('Capability container')
            return DATA
        if isinstance(node,ast.Dict):
            for key,value in zip(node.keys,node.values):
                if key is None or self.expr(key).kind!='data' or self.expr(value).kind!='data':raise Unknown('Dynamic dictionary')
            return DATA
        if isinstance(node,ast.BinOp):
            left,right=self.expr(node.left),self.expr(node.right)
            if left.kind=='path' and isinstance(node.op,ast.Div):return Value('path',posixpath.join(left.name,self.target(right)))
            if left.kind!='data' or right.kind!='data':raise Unknown('Unknown operator operand')
            if isinstance(node.op,ast.Add) and left.known and right.known and isinstance(left.literal,str) and isinstance(right.literal,str):
                text=left.literal+right.literal
                if len(text)>8192:raise Unknown('String budget exceeded')
                return literal(text)
            return DATA
        if isinstance(node,(ast.UnaryOp,ast.BoolOp,ast.Compare,ast.JoinedStr,ast.FormattedValue,ast.Slice)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child,ast.expr) and self.expr(child).kind not in {'data','path'}:raise Unknown('Unknown data operand')
            return DATA
        if isinstance(node,ast.Subscript):
            base=self.expr(node.value);self.expr(node.slice)
            if base.kind!='data':raise Unknown('Unknown subscript target')
            return DATA
        if isinstance(node,ast.IfExp):
            self.expr(node.test);a,b=self.expr(node.body),self.expr(node.orelse)
            return self.merge_value(a,b)
        if isinstance(node,(ast.ListComp,ast.SetComp,ast.DictComp,ast.GeneratorExp)):
            previous=self.env.copy()
            try:
                for g in node.generators:
                    if g.is_async:raise Unknown('Async comprehension')
                    self.iteration(self.expr(g.iter));self.assign(g.target,DATA)
                    for condition in g.ifs:self.expr(condition)
                values = [self.expr(node.key), self.expr(node.value)] if isinstance(node,ast.DictComp) else [self.expr(node.elt)]
                if any(v.kind != 'data' for v in values):raise Unknown('Capability comprehension')
            finally:self.env=previous
            return DATA
        raise Unknown('Unsupported expression: '+type(node).__name__)

    def iteration(self,value):
        if value.kind=='file':self.effect('read',value.name,self.cwd)
        elif value.kind not in {'data','csv_reader','memory','stdin'}:raise Unknown('Unknown iterator')

    def assign(self,node,value):
        if isinstance(node,ast.Name):self.env[node.id]=value
        elif isinstance(node,(ast.Tuple,ast.List)):
            if value.kind!='data':raise Unknown('Capability unpacking')
            for target in node.elts:self.assign(target,DATA)
        elif isinstance(node,ast.Subscript):
            if self.expr(node.value).kind!='data' or value.kind!='data':raise Unknown('Capability mutation')
            self.expr(node.slice)
        else:raise Unknown('Unknown assignment target')

    @staticmethod
    def merge_value(a,b):
        if a==b:return a
        return DATA if a.kind==b.kind=='data' else Value('unknown')

    def block(self,statements):
        for node in statements:
            self.step()
            if isinstance(node,ast.Import):
                for item in node.names:
                    if item.name not in MODULES:raise Unknown('Non-whitelisted import')
                    self.env[item.asname or item.name]=Value('module',item.name)
            elif isinstance(node,ast.ImportFrom):
                if node.level or node.module not in MODULES:raise Unknown('Non-whitelisted import')
                for item in node.names:self.env[item.asname or item.name]=self.attr(Value('module',node.module),item.name)
            elif isinstance(node,ast.Assign):
                value=self.expr(node.value)
                for target in node.targets:self.assign(target,value)
            elif isinstance(node,ast.AugAssign):
                if self.expr(node.target).kind!='data' or self.expr(node.value).kind!='data':raise Unknown('Unknown augmented assignment')
                self.assign(node.target,DATA)
            elif isinstance(node,ast.Expr):self.expr(node.value)
            elif isinstance(node,ast.With):
                for item in node.items:
                    value=self.expr(item.context_expr)
                    if value.kind not in {'file','memory','archive'}:raise Unknown('Unknown context manager')
                    if item.optional_vars:self.assign(item.optional_vars,value)
                self.block(node.body)
            elif isinstance(node,(ast.If,ast.For)):
                if isinstance(node,ast.If):self.expr(node.test)
                else:self.iteration(self.expr(node.iter))
                before=self.env.copy()
                if isinstance(node,ast.For):self.assign(node.target,DATA)
                self.block(node.body);left=self.env.copy();self.env=before.copy()
                self.block(node.orelse);right=self.env.copy()
                self.env={k:self.merge_value(left.get(k,Value('unknown')),right.get(k,Value('unknown'))) for k in left.keys()|right.keys()}
            elif isinstance(node,ast.Assert):
                self.expr(node.test)
                if node.msg:self.expr(node.msg)
            elif isinstance(node,ast.Raise):
                if node.exc:self.expr(node.exc)
                if node.cause:self.expr(node.cause)
            elif not isinstance(node,(ast.Pass,ast.Break,ast.Continue)):
                raise Unknown('Unsupported statement: '+type(node).__name__)


def describe_python(code,cwd,effect):
    try:
        tree=ast.parse(code)
        if len(code.encode('utf-8'))>32768 or sum(1 for _ in ast.walk(tree))>512:
            return False
        Analyzer(effect,cwd).block(tree.body)
        return True
    except (ValueError,TypeError,AttributeError,KeyError,RecursionError,SyntaxError):
        return False
