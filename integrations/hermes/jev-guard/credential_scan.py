"""Local, value-free classification of the exact, already-scoped read targets.

This is an extra check for plaintext credential records, not a claim that every
possible secret encoding can be detected. No file values enter review evidence.
"""
import json
import os
import re
import stat
from pathlib import Path

from .core.constraints import file_checks

_LIMIT = 1024 * 1024
_FIELDS = re.compile(r'^(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|'
                     r'[A-Z0-9_]+_(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY))$')
_PAIR = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$')
_TEMPLATES = {'.env.example', '.env.sample', '.env.template', '.env.dist'}


def _labels(text):
    """Recognize actual key/value records, not prose or code mentioning keys."""
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        value = None
    if isinstance(value, dict):
        pairs = list(value.items())
    else:
        lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        matches = [_PAIR.fullmatch(line) for line in lines]
        if not matches or not all(matches):
            return []
        pairs = [(m.group(1), m.group(2).strip().strip('\"\'')) for m in matches]
    labels = [str(key).upper() for key, value in pairs if isinstance(value, str) and value.strip()
              and _FIELDS.fullmatch(str(key).upper())]
    # A lone generic KEY is common in harmless business data. Strong names or
    # several credential fields are needed; file names are never the sole test.
    return sorted(set(labels)) if any(key != 'KEY' for key in labels) else []


def inspect_reads(description, scope):
    if scope.get('credential_access') != 'denied':
        return []
    records = []
    seen = set()
    for effect in description.get('effects', []):
        path = effect.get('path')
        if effect.get('kind') != 'read' or not path or path in seen or effect.get('recursive'):
            continue
        seen.add(path)
        # Never use this check to fetch an out-of-scope or already forbidden file.
        if file_checks(path, description['cwd'], scope) or Path(path).name in _TEMPLATES:
            continue
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > _LIMIT:
                    continue
                data = stream.read(_LIMIT + 1)
                after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise PermissionError('Read target changed during local credential inspection')
            if len(data) > _LIMIT:
                raise PermissionError('Read target grew during local credential inspection')
            labels = _labels(data.decode('utf-8-sig'))
        except (FileNotFoundError, IsADirectoryError, UnicodeError):
            continue
        if labels:
            records.append({'path': path, 'classification': 'plaintext_credential_record',
                            'credential_fields': labels[:16], 'source': 'polarbear_local_inspection'})
    return records
