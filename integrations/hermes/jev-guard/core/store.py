"""Operator-owned, validated routing configuration with optimistic revisions."""
import copy
import hashlib
import json
import math
import os
import re
import threading
from pathlib import Path
from .execution_policy import validate_execution_rule


def validate(config):
    if config.get('schema_version') != 1 or config.get('model') not in ('jev-v3.1-2b', 'jev-v3.2-2b'):
        raise ValueError('Unsupported schema or model')
    tree = config['tree']; nodes = tree['nodes']; root = tree['root']
    if root != 'root' or root not in nodes or not 1 <= len(nodes) <= 512:
        raise ValueError('Invalid root/node count')
    if not isinstance(config['default_policy'], str) or not config['default_policy'].strip():
        raise ValueError('Default audit policy required')
    if len(config['default_policy']) > 20000:
        raise ValueError('Policy too long')
    for key in ('route_probability', 'route_margin', 'decision_probability', 'unsafe_threshold'):
        value = config['thresholds'].get(key) if key == 'unsafe_threshold' else config['thresholds'][key]
        # An absent/null request threshold preserves the existing admission rule.
        if key == 'unsafe_threshold' and value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1 or not math.isfinite(value):
            raise ValueError('Invalid threshold: ' + key)
    parents = {}; visited = set()
    for nid, node in nodes.items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', nid) or node.get('id') != nid:
            raise ValueError('Invalid node id: ' + str(nid))
        for key in ('label', 'description', 'review_policy'):
            if not isinstance(node.get(key), str) or not node[key].strip() or len(node[key]) > 20000:
                raise ValueError('Invalid ' + key + ' at ' + nid)
        if 'execution_rule' in node:
            validate_execution_rule(node['execution_rule'])
        children = node['children']
        if not isinstance(children, list) or len(children) > 128:
            raise ValueError('Invalid children')
        labels = set()
        for child in children:
            cid = child['id']
            if cid not in nodes or cid == root or cid in parents:
                raise ValueError('Missing/duplicate parent or cyclic root: ' + cid)
            parents[cid] = nid
            for key in ('label', 'description'):
                if child.get(key) != nodes[cid][key]:
                    raise ValueError('Child metadata differs from its node: ' + cid)
            if child['label'] in labels:
                raise ValueError('Duplicate sibling choice labels')
            labels.add(child['label'])
        if node.get('category_mode', 'single') not in ('single', 'multi', 'score'):
            raise ValueError('Invalid category mode')
        for kind, group in node.get('taxonomy', {}).items():
            if kind not in ('category', 'score'):
                raise ValueError('Only category/score taxonomies are supported')
            opts = group['labels']
            if not isinstance(opts, list) or not 1 <= len(opts) <= 512 or any(not isinstance(o, str) or not o.strip() or len(o) > 2000 for o in opts) or len(set(opts)) != len(opts):
                raise ValueError('Invalid taxonomy at ' + nid)
            if kind == 'score' and opts != ['low', 'medium', 'high', 'critical']:
                raise ValueError('Ordinal head supports low/medium/high/critical only')
        if not children and not node.get('taxonomy') and not node.get('native_safety_only'):
            raise ValueError('Leaf requires a taxonomy: ' + nid)
    def visit(nid, depth=0):
        if depth > 16 or nid in visited:
            raise ValueError('Cycle or depth exceeds 16')
        visited.add(nid)
        for child in nodes[nid]['children']: visit(child['id'], depth + 1)
    visit(root)
    if visited != set(nodes): raise ValueError('Disconnected nodes')
    return config


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class Store:
    def __init__(self, directory, initial=None):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'config.json'; self.lock = threading.RLock()
        if not self.path.exists():
            self._write(validate(json.loads(Path(initial).read_text(encoding='utf-8'))))

    def _write(self, config):
        # Panel is the only writer; a revision snapshot is also saved atomically.
        history = self.directory / 'history'; history.mkdir(exist_ok=True)
        payload = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
        (history / (str(config['revision']) + '.json')).write_text(payload, encoding='utf-8')
        tmp = self.path.with_suffix('.tmp'); tmp.write_text(payload, encoding='utf-8')
        os.replace(tmp, self.path)

    def read(self):
        with self.lock: return validate(json.loads(self.path.read_text(encoding='utf-8')))

    def save(self, config, expected_revision):
        with self.lock:
            old = self.read()
            if old['revision'] != expected_revision:
                raise RuntimeError('Revision conflict: reload before saving')
            new = copy.deepcopy(config); new['revision'] = old['revision'] + 1
            validate(new); self._write(new)
            return new
