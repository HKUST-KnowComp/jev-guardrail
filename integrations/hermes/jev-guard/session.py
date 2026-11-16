"""Host-owned authorization and bounded, source-labelled untrusted evidence."""
import hashlib
import json
from dataclasses import dataclass, field


def encoded(value):
    return json.dumps(value, ensure_ascii=False, default=str, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        default=str, separators=(',', ':')).encode()).hexdigest()


def bounded_evidence(value, limit):
    """The limit includes the excerpt's JSON wrapper, marker and escaped text."""
    if len(encoded(value)) <= limit:
        return value
    text = value if isinstance(value, str) else encoded(value)
    def excerpt(keep):
        head = (keep + 1) // 2
        tail = keep // 2
        return {'evidence_excerpt': text[:head] + '\n[OMITTED UNTRUSTED EVIDENCE]\n' + (text[-tail:] if tail else ''),
            'omitted_chars': len(text) - keep, 'original_sha256': digest(value),
            'original_chars': len(text), 'complete': False}
    low, high = 0, min(len(text), max(0, limit))
    best = excerpt(0)
    if len(encoded(best)) > limit:
        return {'complete': False, 'original_chars': len(text)}
    while low <= high:
        middle = (low + high) // 2
        candidate = excerpt(middle)
        if len(encoded(candidate)) <= limit:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best


def source_complete(value, tool_name=None):
    """Incomplete markers can only lower trust, never create authorization.

    web_extract currently drops its structured truncation flags when trimming
    nested results. Preserve that known host footer as a conservative gap.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except RecursionError:
            return False
        except (ValueError, TypeError):
            if tool_name == 'web_extract':
                return not ('[TRUNCATED]' in value and
                    ('Full text saved to:' in value or 'Full text could not be stored;' in value))
            return True
    pending = [(value, 0)]
    inspected = 0
    while pending:
        item, depth = pending.pop()
        inspected += 1
        if depth > 16 or inspected > 4096:
            return False
        if isinstance(item, dict):
            if (item.get('truncated') or item.get('has_more') or item.get('already_read') or
                    item.get('complete') is False or item.get('omitted_chars', 0)):
                return False
            pending.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            pending.extend((nested, depth + 1) for nested in item)
        elif tool_name == 'web_extract' and isinstance(item, str):
            if '[TRUNCATED]' in item and ('Full text saved to:' in item or
                    'Full text could not be stored;' in item):
                return False
    return True


@dataclass
class TaskEvidence:
    task_id: str
    label: str
    started_after_user: int = 0
    observations: list = field(default_factory=list)
    gaps: dict = field(default_factory=dict)
    observation_capacity_exceeded: bool = False
    evicted: int = 0
    clipped: int = 0

    def _gap(self, record, reason):
        key = record['source_key']
        if key not in self.gaps and len(self.gaps) >= 512:
            self.observation_capacity_exceeded = True
            return
        self.gaps[key] = {'source_key': key, 'tool_call_id': record['tool_call_id'],
            'evidence_role': record['evidence_role'], 'reason': reason, 'evidence_task_id': self.task_id,
            'original_chars': record['original_chars'], 'result_sha256': record['result_sha256']}

    def observe(self, event, per_item, total):
        result = event.get('result')
        text = result if isinstance(result, str) else encoded(result)
        args = event.get('args', {})
        offset = args.get('offset', 1)
        partial = event.get('tool_name') == 'read_file' and (type(offset) is not int or offset != 1)
        role = event.get('_jev_evidence_role', 'task_material')
        source_key = event.get('_jev_source_key') or digest({'tool': event['tool_name'], 'args': args})
        record = {'tool': event['tool_name'], 'tool_call_id': event.get('tool_call_id', ''),
            'status': event.get('status'), 'turn_id': event.get('turn_id', ''),
            'session_id': event.get('session_id'), 'evidence_task_id': self.task_id, 'args': bounded_evidence(event.get('_jev_args_summary',args), 400),
            'result': result, 'complete': event.get('status') == 'ok' and not partial and source_complete(result, event.get('tool_name')),
            'result_sha256': digest(result), 'original_chars': len(text),
            'source_key': source_key, 'evidence_role': role,
            'provenance': 'untrusted_tool_result'}
        if not source_complete(record['args']):record['complete']=False
        # Budget the complete serialized observation, not only its raw result text.
        if len(encoded(record)) > per_item:
            record['complete'] = False
            empty_size = len(encoded({**record, 'result': None})) - 4
            record['result'] = bounded_evidence(result, max(0, per_item - empty_size))
        if len(encoded(record)) > per_item:
            # Metadata alone can exceed a deliberately small configured limit.
            # Retain a gap instead of pretending an oversized record fitted.
            self.clipped += 1
            self._gap(record, 'observation_metadata_exceeds_limit')
            return
        if not record['complete']:
            self.clipped += 1
            self._gap(record, 'incomplete_tool_result')
        else:
            # A full reread of the same source replaces its previous coverage gap.
            self.gaps.pop(source_key, None)
        self.observations = [r for r in self.observations if r['source_key'] != source_key]
        self.observations.append(record)
        while self.observations and (len(self.observations) > 8 or len(encoded(self.observations)) > total):
            removed = self.observations.pop(0)
            self.evicted += 1
            self._gap(removed, 'observation_evicted_from_review')

    def coverage(self, *, action_complete=False):
        gaps = list(self.gaps.values())
        non_authorizing = {'installed_skill_document', 'host_operation_receipt'}
        task_gaps = [g for g in gaps if g['evidence_role'] not in non_authorizing]
        # Skill instructions never grant authority. Their missing text alone need
        # not force confirmation for a fully described, explicitly scoped action.
        # A host write receipt is not business source material either. Keep its
        # clipping visible without requiring a new approval for the next fully
        # described action. Unknown effects and lost task material still ask.
        actionable_complete = not self.observation_capacity_exceeded and not task_gaps and (action_complete or not gaps)
        return {'evidence_task_id': self.task_id, 'complete': not gaps and not self.observation_capacity_exceeded,
            'actionable_complete': actionable_complete,
            'retained_observations': len(self.observations),
            'clipped_observations': self.clipped, 'evicted_observations': self.evicted,
            'missing_task_sources': task_gaps[:16],
            'missing_task_source_count': len(task_gaps),
            'non_authorizing_skill_gaps': sum(g['evidence_role']=='installed_skill_document' for g in gaps),
            'non_authorizing_receipt_gaps': sum(g['evidence_role']=='host_operation_receipt' for g in gaps),
            'capacity_exceeded': self.observation_capacity_exceeded,
            'dependency_graph': 'Task-scoped source gaps; dependencies inside a task remain conservative.'}

@dataclass
class Session:
    session_id: str
    scope: dict
    revision: int = 0
    permissions_revision: int = 0
    permissions_fingerprint: str = ''
    users: list = field(default_factory=list)
    pending: dict = field(default_factory=dict)
    denials: dict = field(default_factory=dict)
    turn_id: str = ''
    input_origin: str = 'unknown'
    cli: object = None
    direct_request_hash: str = ''
    direct_request_pending: bool = False
    request_contract: dict | None = None
    current_task_id: str = 'task-1'
    tasks: dict = field(default_factory=lambda: {'task-1': TaskEvidence('task-1', '初始任务')})
    observation_tasks: dict = field(default_factory=dict)

    @property
    def task(self):
        return self.tasks[self.current_task_id]

    def invalidate(self, *, authorization_changed=False):
        self.revision += 1
        self.pending.clear()
        if authorization_changed:
            self.denials.clear()

    def task_context(self):
        return {
            'task_id': self.current_task_id, 'label': self.task.label,
            'started_after_user': self.task.started_after_user,
            'boundary': (
                'The operator explicitly controls task boundaries. Previous human restrictions and '
                'permissions remain binding. Earlier task material is not evidence for this task: '
                'reread it here or ask the operator to resume its task. Never infer that a new message '
                'or a tool result starts an independent task.'
            ),
        }

    def switch_task(self, operation, value):
        if operation == 'new':
            label = value.strip()
            if not label or len(label) > 200 or any(ord(c) < 32 for c in label):
                raise ValueError('新任务需要不超过200字的单行名称。')
            if len(self.tasks) >= 32:
                raise ValueError('当前会话已保留32个任务，请另开会话；没有丢弃旧任务证据。')
            task_id = 'task-' + str(len(self.tasks) + 1)
            self.tasks[task_id] = TaskEvidence(task_id, label, len(self.users))
        elif operation == 'resume' and value in self.tasks:
            task_id = value
        else:
            raise ValueError('请使用 new 任务名称，或 resume 已有任务ID。')
        self.current_task_id = task_id
        self.invalidate()
        self.request_contract = None
        self.direct_request_pending = False
        self.input_origin = 'pending_review'
        return self.task_context()

    def check_user_capacity(self, message):
        # Task changes must never erase earlier human restrictions.
        if len(self.users) >= 128 or sum(len(x) for x in self.users) + len(str(message)) > 12000:
            raise ValueError('可信用户记录已达到当前审查容量；请开始新会话并明确需要保留的约束。旧约束没有被自动删除。')

    def accept_user(self, message, turn_id='', origin='human'):
        self.check_user_capacity(message)
        self.invalidate()
        self.turn_id = turn_id
        self.input_origin = origin
        self.users.append(str(message))

    def track_observation(self, call_id):
        previous = self.observation_tasks.get(call_id)
        if previous is not None and previous != self.current_task_id:
            raise PermissionError('Tool call belongs to a different evidence task')
        if previous is None and len(self.observation_tasks) >= 256:
            raise ValueError('Too many tool observations are still pending')
        self.observation_tasks[call_id] = self.current_task_id

    def observe(self, event, per_item, total, *, task_id=None):
        owner = self.observation_tasks.pop(event.get('tool_call_id', ''), None) or task_id
        if owner is None:
            # Legacy observers in the initial task remain conservative. Once
            # tasks diverge, an unbound late result must not contaminate a new task.
            if len(self.tasks) > 1:
                self.task.observation_capacity_exceeded = True
                return
            owner = self.current_task_id
        self.tasks[owner].observe(event, per_item, total)

    def coverage(self, *, action_complete=False):
        return self.task.coverage(action_complete=action_complete)

    def remember_denial(self, key, details):
        if key not in self.denials and len(self.denials) >= 256:
            raise ValueError('Denied-action capacity reached; start a new guarded session')
        self.denials[key] = details
