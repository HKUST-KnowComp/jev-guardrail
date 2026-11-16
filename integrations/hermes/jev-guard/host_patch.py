"""Profile-bound host adapters; never change shared Hermes source files.

Installed explicitly from this plugin's register(). Only the owning manager's
Jev policy callbacks are queued. The write override uses Hermes' native scoped
registration (and therefore requires the operator's tools.override permission).
"""
from __future__ import annotations

import contextvars
import copy
import json
import logging
import os
import threading
import time
import types
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

def _owner_home():
    source = Path(__file__).resolve().parent
    if source.name == 'jev-guard' and source.parent.name == 'plugins':
        return source.parent.parent
    try:
        from hermes_constants import get_hermes_home
        return get_hermes_home().resolve()
    except ImportError:
        return Path(os.environ.get('HERMES_HOME', str(Path.home()/'.hermes'))).expanduser().resolve()


PROFILE_HOME = _owner_home()
_POLICY_CALL = contextvars.ContextVar('jev_policy_callback', default=None)
_EVENT_LOCK = threading.Lock()
_GAPS_LOCK = threading.Lock()
_OBSERVER_GAPS = {}
_OBSERVER_GAP_OVERFLOW = False
_OBSERVER_HOOKS = frozenset({'post_tool_call', 'pre_llm_call', 'post_approval_decision'})
_LOG = logging.getLogger(__name__)
_MODES = frozenset({'default', 'no_verify', 'write_only'})


def _profile_active():
    raw = os.environ.get('HERMES_HOME')
    if raw and Path(raw).expanduser().resolve() != PROFILE_HOME:
        return False
    from hermes_constants import get_hermes_home
    return get_hermes_home().resolve() == PROFILE_HOME


def _record(event, **fields):
    """Host-owned metadata only: never include request text or file contents."""
    row = {'time': time.time(), 'event': event, 'profile': str(PROFILE_HOME), **fields}
    try:
        with _EVENT_LOCK:
            with (PROFILE_HOME / 'jev-guard' / 'host-events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(row, ensure_ascii=False, default=str) + '\n')
    except OSError as exc:
        _LOG.error('Jev host metadata logging failed: %s', type(exc).__name__)


def _mark_observer_gap(ticket, reason):
    global _OBSERVER_GAP_OVERFLOW
    if ticket.hook not in _OBSERVER_HOOKS:
        return
    with _GAPS_LOCK:
        if not ticket.session_id:
            # No trustworthy session identity means no later session may assume
            # this dropped callback was unrelated to its own evidence.
            _OBSERVER_GAP_OVERFLOW = True
            return
        if ticket.session_id not in _OBSERVER_GAPS:
            if len(_OBSERVER_GAPS) >= 128:
                _OBSERVER_GAP_OVERFLOW = True
                return
            _OBSERVER_GAPS[ticket.session_id] = {}
        gaps = _OBSERVER_GAPS[ticket.session_id]
        if ticket.id not in gaps:
            if len(gaps) >= 128:
                _OBSERVER_GAP_OVERFLOW = True
            else:
                gaps[ticket.id] = {**ticket.identity(), 'reason': reason, 'time': time.time()}


def observer_gaps(session_id):
    """Read-only continuity evidence; no implicit reset after a dropped callback."""
    with _GAPS_LOCK:
        events = copy.deepcopy(list(_OBSERVER_GAPS.get(str(session_id), {}).values()))
        overflow = _OBSERVER_GAP_OVERFLOW
    counts = {hook: sum(event['hook'] == hook for event in events) for hook in sorted(_OBSERVER_HOOKS)}
    return {'complete': not events and not overflow,
            'trusted_task_continuity': not counts['pre_llm_call'] and not overflow,
            'counts': counts, 'events': events, 'overflow': overflow}


@dataclass(eq=False)
class PolicyTicket:
    hook: str
    session_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    deadline: float
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: float = field(default_factory=time.monotonic)
    lock: object = field(default_factory=threading.RLock, repr=False)
    done: object = field(default_factory=threading.Event, repr=False)
    cancelled: bool = False
    cancel_reason: str = ''
    finished: bool = False
    result: object = field(default=None, repr=False)
    failure: object = field(default=None, repr=False)

    def identity(self):
        return {'ticket_id': self.id, 'hook': self.hook, 'session_id': self.session_id,
                'turn_id': self.turn_id, 'tool_call_id': self.tool_call_id,
                'tool_name': self.tool_name}

    def valid(self):
        with self.lock:
            return not self.cancelled and self.failure is None and (self.finished or time.monotonic() < self.deadline)

    def cancel(self, reason):
        with self.lock:
            # A result completed within its deadline remains valid after the
            # waiting caller is scheduled again. Expiration does not undo it.
            if self.finished:
                return False
            self.cancelled = True
            self.cancel_reason = self.cancel_reason or reason
            return True


def current_policy_ticket():
    """Keep this object in pending state, not JSON, to fence a late worker."""
    return _POLICY_CALL.get()


def policy_ticket_valid(ticket):
    # None belongs to direct synchronous entrypoints, not an abandoned worker.
    # A pending review must have actually completed before it may authorize use.
    if ticket is None:
        return True
    if not isinstance(ticket, PolicyTicket):
        return False
    with ticket.lock:
        return ticket.finished and ticket.valid()


def policy_guard_active():
    ticket = current_policy_ticket()
    return ticket is None or isinstance(ticket, PolicyTicket) and ticket.valid()


def ensure_policy_guard_active():
    if not policy_guard_active():
        raise PermissionError('Jev policy callback expired; its result cannot authorize execution')


@contextmanager
def policy_commit_guard():
    """Use only around short state commits/receipt consumption, never inference."""
    ticket = current_policy_ticket()
    if ticket is None:
        yield
        return
    with ticket.lock:
        ensure_policy_guard_active()
        yield


class _PolicyQueue:
    """One bounded FIFO per callback; a timed-out worker is not duplicated."""
    def __init__(self, manager, invoker):
        self.manager = manager
        self.invoker = invoker
        self.condition = threading.Condition()
        self.waiting = deque()
        self.running = None
        self.retired = False

    def retire(self):
        with self.condition:
            self.retired = True
            for ticket in self.waiting:
                ticket.cancel('adapter_retired')
            if self.running:
                self.running.cancel('adapter_retired')
            self.condition.notify_all()

    @staticmethod
    def _blocked(ticket, reason):
        _mark_observer_gap(ticket, reason)
        if ticket.hook not in ('pre_tool_call', 'pre_tool_execution'):
            return None
        return {'action': 'block', 'message': 'Jev policy hook blocked: ' + reason,
                'reason_code': 'jev_policy_' + reason, 'policy_ticket_id': ticket.id}

    def run(self, hook, callback, payload, timeout):
        ticket = PolicyTicket(hook=hook, session_id=str(payload.get('session_id') or ''),
            turn_id=str(payload.get('turn_id') or ''), tool_call_id=str(payload.get('tool_call_id') or ''),
            tool_name=str(payload.get('tool_name') or ''), deadline=time.monotonic() + timeout)
        requires_tool_identity = hook != 'pre_llm_call'
        if not ticket.session_id or (requires_tool_identity and not ticket.tool_call_id):
            ticket.cancel('missing_call_identity')
            _record('policy_rejected', **ticket.identity(), reason='missing_call_identity')
            return self._blocked(ticket, 'missing_call_identity')
        with self.condition:
            if self.retired or len(self.waiting) >= 128:
                reason = 'adapter_retired' if self.retired else 'queue_full'
                ticket.cancel(reason)
                _record('policy_rejected', **ticket.identity(), reason=reason)
                return self._blocked(ticket, reason)
            self.waiting.append(ticket)
            _record('policy_queued', **ticket.identity(), queue_depth=len(self.waiting))
            while self.running is not None or self.waiting[0] is not ticket:
                remaining = ticket.deadline - time.monotonic()
                if self.retired or remaining <= 0:
                    self.waiting.remove(ticket)
                    reason = 'adapter_retired' if self.retired else 'queue_timeout'
                    ticket.cancel(reason)
                    self.condition.notify_all()
                    _record('policy_rejected', **ticket.identity(), reason=reason)
                    return self._blocked(ticket, reason)
                self.condition.wait(remaining)
            if self.retired or time.monotonic() >= ticket.deadline:
                self.waiting.popleft()
                reason = 'adapter_retired' if self.retired else 'queue_timeout'
                ticket.cancel(reason)
                self.condition.notify_all()
                _record('policy_rejected', **ticket.identity(), reason=reason)
                return self._blocked(ticket, reason)
            self.waiting.popleft()
            self.running = ticket
        _record('policy_started', **ticket.identity(), queue_ms=round((time.monotonic()-ticket.created)*1000, 3))
        context = contextvars.copy_context()

        def invoke():
            token = _POLICY_CALL.set(ticket)
            try:
                ensure_policy_guard_active()
                return self.invoker(callback, payload)
            finally:
                _POLICY_CALL.reset(token)

        def runner():
            value = None
            error = None
            try:
                value = context.run(invoke)
            except BaseException as exc:
                error = exc
            finally:
                with ticket.lock:
                    if ticket.cancelled or time.monotonic() >= ticket.deadline:
                        ticket.cancelled = True
                        ticket.cancel_reason = ticket.cancel_reason or 'execution_timeout'
                        late = True
                    else:
                        ticket.result = value
                        ticket.failure = error
                        ticket.finished = True
                        late = False
                    # Publish lost-observation evidence before waking a caller or
                    # releasing the next callback. No gap-reader acquires a
                    # ticket lock, so this preserves the ticket -> gaps order.
                    if late:
                        _mark_observer_gap(ticket, ticket.cancel_reason)
                    elif error is not None:
                        _mark_observer_gap(ticket, 'callback_exception_' + type(error).__name__)
                    ticket.done.set()
                with self.condition:
                    if self.running is ticket:
                        self.running = None
                    self.condition.notify_all()
                _record('policy_late_result_discarded' if late else 'policy_finished',
                    **ticket.identity(), reason=ticket.cancel_reason if late else None,
                    error_type=type(error).__name__ if error else None,
                    elapsed_ms=round((time.monotonic()-ticket.created)*1000, 3))

        worker = threading.Thread(target=runner, name='jev-policy-' + ticket.id[:12], daemon=True)
        try:
            worker.start()
        except RuntimeError as exc:
            ticket.cancel('worker_start_failure')
            with self.condition:
                self.running = None
                self.condition.notify_all()
            _record('policy_rejected', **ticket.identity(), reason='worker_start_failure', error_type=type(exc).__name__)
            return self._blocked(ticket, 'worker_start_failure')
        ticket.done.wait(max(0.0, ticket.deadline - time.monotonic()))
        with ticket.lock:
            if not ticket.finished:
                ticket.cancel('execution_timeout')
                _record('policy_rejected', **ticket.identity(), reason=ticket.cancel_reason)
                return self._blocked(ticket, ticket.cancel_reason)
            if ticket.failure is not None:
                return self._blocked(ticket, 'callback_exception_' + type(ticket.failure).__name__)
            return ticket.result


class _ManagerAdapter:
    def __init__(self, manager, callbacks, original, original_invoke):
        self.manager = manager
        self.callbacks = dict(callbacks)
        self.original = original
        self.original_invoke = original_invoke
        self.queues = {name: _PolicyQueue(manager, original_invoke) for name in callbacks}

    def retire(self):
        for queue in self.queues.values():
            queue.retire()

    def bounded(self, hook, callback, payload, timeout):
        if self.callbacks.get(hook) is not callback:
            return self.original(hook, callback, payload, timeout)
        if not _profile_active():
            ticket = PolicyTicket(hook=hook, session_id=str(payload.get('session_id') or ''),
                turn_id=str(payload.get('turn_id') or ''), tool_call_id=str(payload.get('tool_call_id') or ''),
                tool_name=str(payload.get('tool_name') or ''), deadline=0.0)
            ticket.cancel('profile_mismatch')
            _record('policy_rejected', **ticket.identity(), reason='profile_mismatch')
            return _PolicyQueue._blocked(ticket, 'profile_mismatch')
        return self.queues[hook].run(hook, callback, payload, timeout)

    def invoke(self, callback, payload):
        # Unbounded native hooks (approval) and explicit zero-timeout settings
        # otherwise bypass _run_hook_callback_bounded. Route only our callbacks.
        hook = next((name for name, cb in self.callbacks.items() if cb is callback), None)
        if hook is None:
            return self.original_invoke(callback, payload)
        from hermes_cli.plugins import _resolve_hook_callback_timeout
        timeout = _resolve_hook_callback_timeout()
        if timeout <= 0:
            timeout = 30.0
        return self.bounded(hook, callback, payload, timeout)


def _write_mode(args):
    mode = args.get('write_mode', 'default')
    if not isinstance(mode, str) or mode not in _MODES:
        raise ValueError('write_mode must be default, no_verify or write_only')
    return mode


def write_effect_contract(args, execution_context=None):
    """Declared host implementation effects, NOT a record of executed actions."""
    context = execution_context or {}
    mode = _write_mode(args)
    path = context.get('resolved_paths', {}).get('path') or args.get('path')
    effects = []
    uncertainties = []
    if not isinstance(path, str) or not path:
        uncertainties.append('Write target is unresolved')
    else:
        effects.append({'kind': 'write', 'path': path})
        if mode != 'write_only':
            effects.append({'kind': 'read', 'path': path})
    return {'effect': 'file_write', 'source': 'polarbear_host_adapter', 'write_mode': mode,
        'effects': effects, 'complete': not uncertainties, 'uncertainties': uncertainties,
        'record_kind': 'declared_implementation_contract',
        'internal_operations': {
            'old_content_probe': mode != 'write_only',
            'whole_file_rewrite_hint_may_read_old_content': False,
            'target_metadata_read': True, 'ensure_parent_directories': True,
            'same_directory_temporary_write': True, 'atomic_replace_target': True,
            'failed_atomic_write_temporary_cleanup': True,
            'post_write_content_read': mode == 'default',
            'lint_and_lsp': False, 'in_memory_lint': mode == 'default',
            'project_verification_tracking': False,
            'candidate_in_memory_syntax_validation': True,
            'metadata_bookkeeping': True},
        'content_read_paths': [path] if mode != 'write_only' and isinstance(path, str) and path else [],
        'restricted_extensions': ['external_lint', 'lsp', 'project_scan', 'whole_file_rewrite_hint'],
        'extension_policy': 'Use separate explicitly reviewed tool calls for project-wide checks.'}


def _native_execution_context(args):
    from tools.tool_execution_context import _EXECUTION_SCOPE, tool_args_digest
    active = _EXECUTION_SCOPE.get()
    if active is None:
        raise PermissionError('Profile write adapter requires the native final execution gate')
    # New hosts append a one-use dispatch handoff; only the host consumes it.
    name, digest, identity, context = active[:4]
    if name != 'write_file' or digest != tool_args_digest(args):
        raise PermissionError('Write mode arguments do not match the reviewed native call')
    if (context.get('profile_key') != str(PROFILE_HOME) or
            context.get('context_known') is not True or context.get('backend') != 'local' or
            context.get('path_semantics') != 'local'):
        raise PermissionError('Profile write adapter requires the verified local profile context')
    return context, {'session_id': identity[1], 'turn_id': identity[2], 'tool_call_id': identity[3]}


def _restricted_write(args, kw):
    """Reuse native path guards/atomic writing, without hidden target-content reads."""
    from tools import file_tools as ft
    from tools.file_operations import get_write_denied_error
    from tools.file_operations_common import _normalize_line_endings, _has_bom, _UTF8_BOM
    context, ids = _native_execution_context(args)
    mode = _write_mode(args)
    path = args['path']
    content = args['content']
    tid = kw.get('task_id') or 'default'
    if (str(tid) != str(context.get('task_id') or 'default') or
            str(kw.get('session_id') or '') != str(context.get('session_id') or '')):
        raise PermissionError('Write task/session does not match the native execution context')
    stages = []
    lint = {'status': 'skipped', 'message': 'Explicit write mode does not run lint or LSP'}
    verified = None
    verification = {'status': 'skipped_by_explicit_write_mode'}
    verification_error = None

    def observed(stage, **details):
        stages.append({'stage': stage, **details})
        _record('write_internal_stage', **ids, write_mode=mode, path=path, stage=stage, **details)

    err = (ft._check_sensitive_path(path, tid)
        or ft._check_binary_document_write(path, tid)
        or ft._check_protected_instruction_write([path], tid)
        or ft._check_approval_required_write([path], tid)
        or (None if bool(args.get('cross_profile', False)) else ft._check_cross_profile_path(path, tid)))
    if not err and ft._is_internal_file_tool_content(content):
        err = 'Refusing to write internal read_file display text as file content.'
    if err:
        return ft.tool_error(err)
    resolved = ft._resolve_or_none(path, tid)
    if not resolved or resolved != context.get('resolved_paths', {}).get('path'):
        raise PermissionError('Write target changed after the native final gate')
    with ft.file_state.lock_path(resolved):
        from tools.tool_execution_context import _path_fingerprint
        if _path_fingerprint(resolved) != context.get('path_fingerprints', {}).get(resolved):
            raise PermissionError('Write target identity changed before internal writing')
        observed('native_path_guards_and_metadata_check_completed')
        ops = ft._get_file_ops(tid)
        if type(ops) is not ft.ShellFileOperations:
            raise PermissionError('Unsupported file operations backend for profile write adapter')
        err = get_write_denied_error(resolved)
        if err:
            return ft.tool_error(err)
        refused = ops._reject_unencodable(resolved, content)
        if refused is None:
            refused = ops._fail_closed_syntax_error(resolved, os.path.splitext(resolved)[1].lower(), content)
        if refused is not None:
            return json.dumps(refused.to_dict(), ensure_ascii=False)
        observed('candidate_in_memory_validation_completed')
        if mode == 'default':
            # These host functions parse only supplied text. Do not call the
            # mixin's _check_lint: its fallback can inspect projects/run tools.
            from tools.file_operations_lint import LINTERS_INPROC
            in_memory_linter = LINTERS_INPROC.get(os.path.splitext(resolved)[1].lower())
            if in_memory_linter is None:
                lint = {'status': 'skipped', 'message': 'No in-memory syntax checker for this extension; external checks need a separate reviewed tool call.'}
            else:
                observed('candidate_in_memory_lint_started')
                lint_ok, lint_error = in_memory_linter(content)
                lint = {'status': 'skipped' if lint_error == '__SKIP__' else ('passed' if lint_ok else 'failed'),
                    'scope': 'supplied_content_only', 'success': lint_ok and lint_error != '__SKIP__',
                    'output': '' if lint_error == '__SKIP__' else lint_error}
                observed('candidate_in_memory_lint_returned', status=lint['status'])
        if mode != 'write_only':
            observed('old_content_probe_started', content_read_path=resolved)
            has_bom, _, ending = ops._probe_write_target(resolved, None, False)
            # The helper may retry its probes. This records its return, not an
            # invented count of lower-level head/base64 subprocesses.
            observed('old_content_probe_returned', content_read_path=resolved)
            if ending == '\r\n':
                content = _normalize_line_endings(content, '\r\n')
            if has_bom and not _has_bom(content):
                content = _UTF8_BOM + content
        encoded = content.encode('utf-8', 'surrogateescape')
        observed('native_atomic_write_started')
        written = ops._atomic_write(resolved, content)
        observed('native_atomic_write_returned', exit_code=written.exit_code)
        if written.exit_code != 0:
            return ft.tool_error('Failed to write file: ' + written.stdout)
        if mode == 'default':
            observed('post_write_verification_started', content_read_path=resolved, algorithm='sha256')
            verified, verify_error = ops._verify_written_hash(resolved, encoded)
            verification = {'status': 'verified' if verified is True else ('mismatch' if verified is False else 'unavailable'),
                'algorithm': 'sha256', 'content_read_path': resolved}
            observed('post_write_verification_returned', status=verification['status'], verified=verified,
                content_read_path=resolved, algorithm='sha256')
            if verify_error is not None:
                verification_error = verify_error.to_dict().get('error') or 'Write completed but target hash verification failed.'
            elif verified is not True:
                verification_error = 'Write completed but target hash verification was unavailable; the write must not be treated as verified.'
        # _note_edited is NOT metadata-only: its verification-stale helper
        # discovers project facts and can read manifests/context files. Avoid
        # that path; these two native helpers only stat and update in-memory
        # read/write tracking. They do not inspect the target's contents.
        ft._update_read_timestamp(path, tid)
        ft.file_state.note_write(tid, resolved)
        observed('native_metadata_bookkeeping_completed')
    result = {'bytes_written': len(encoded),
        'resolved_path': resolved, 'files_modified': [resolved], 'write_mode': mode,
        'verified': verified, 'verification': verification,
        'project_verification_tracking': {'status': 'skipped_to_avoid_project_content_reads'},
        'lint': lint,
        'extended_checks': {'status': 'require_separate_reviewed_tool_call',
            'disabled': ['external_lint', 'lsp', 'project_scan', 'whole_file_rewrite_hint']},
        'host_internal_operations': {'record_kind': 'observed_adapter_stages', 'stages': stages,
            'native_subcommands_individually_observed': False,
            'declaration': write_effect_contract(args, context)}}
    if verification_error:
        result['error'] = verification_error
    return json.dumps(result, ensure_ascii=False)


def _register_write(ctx):
    from tools import file_tools as ft
    from tools.registry import registry
    entry = registry.get_entry('write_file', scope=str(PROFILE_HOME))
    if entry is None:
        raise RuntimeError('Native write_file is unavailable')
    schema = copy.deepcopy(ft.WRITE_FILE_SCHEMA)
    schema['parameters']['properties']['write_mode'] = {'type': 'string',
        'enum': ['default', 'no_verify', 'write_only'],
        'description': 'default读取目标以保留BOM/换行，写后读取目标做SHA256验证，并对提供文本做可用的内存语法检查。no_verify允许写前探测，禁止写后回读。write_only不读取旧内容、不回读验证，按提供内容写入。所有模式仍做候选内容基础检查、路径元数据检查、创建父目录及同目录临时写入后原子替换；均不隐式运行外部lint、LSP或扫描项目，扩展检查需单独授权工具调用。'}
    schema['description'] += ' 当前 profile 支持write_mode；明确禁止回读时使用no_verify，仅写不读时使用write_only。模式不授予文件权限。'

    def handler(args, **kw):
        if not _profile_active():
            return ft.tool_error('Polarbear write adapter profile mismatch')
        try:
            mode = _write_mode(args)
            if not isinstance(args.get('path'), str) or not args.get('path') or not isinstance(args.get('content'), str):
                return ft._handle_write_file(args, **kw)
            return _restricted_write(args, kw)
        except Exception as exc:
            _LOG.warning('Polarbear write adapter rejected: %s', type(exc).__name__)
            return ft.tool_error(str(exc))

    handle = ctx.register_tool(name='write_file', toolset=entry.toolset, schema=schema,
        handler=handler, check_fn=entry.check_fn, requires_env=entry.requires_env,
        description=schema['description'], emoji=entry.emoji, override=True)
    if handle is None:
        raise RuntimeError('Polarbear write_file override was not registered')
    scoped = registry.get_entry('write_file', scope=str(PROFILE_HOME))
    if scoped is None or scoped.handler is not handler:
        raise RuntimeError('Polarbear write_file override identity mismatch')
    scoped.max_result_size_chars = entry.max_result_size_chars
    return handle


def patch_attribute(ctx, target, name, replacement):
    """Restore a process-local patch on failed loading, reload or unload."""
    missing = object()
    previous = vars(target).get(name, missing)
    lock = threading.RLock()
    active = True

    def restore():
        nonlocal active
        with lock:
            active = False
            if vars(target).get(name, missing) is replacement:
                if previous is missing:
                    delattr(target, name)
                else:
                    setattr(target, name, previous)

    handle = ctx.on_unload(restore)
    with lock:
        # A timed-out loader may already have disposed the cleanup registration.
        if not active or handle is None or not handle.active:
            raise RuntimeError('Host adapter registration was cancelled')
        setattr(target, name, replacement)


def _install_ordered_batches(ctx):
    from run_agent import AIAgent
    from tools.registry import registry
    original = AIAgent._execute_tool_calls

    def execute(agent, assistant_message, messages, effective_task_id, api_call_count=0):
        if not _profile_active() or registry.current_scope_key() != str(PROFILE_HOME):
            return original(agent, assistant_message, messages, effective_task_id, api_call_count)
        # A later read may depend on instructions returned by an earlier read in
        # the same batch. Publish its observation before reviewing the next call.
        _record('ordered_tool_batch', session_id=getattr(agent, 'session_id', None),
                tool_call_ids=[getattr(call, 'id', '') for call in assistant_message.tool_calls])
        agent._executing_tools = True
        try:
            return agent._execute_tool_calls_sequential(assistant_message, messages, effective_task_id, api_call_count)
        finally:
            agent._executing_tools = False

    patch_attribute(ctx, AIAgent, '_execute_tool_calls', execute)


def install(ctx, *, policy_callbacks):
    """Called after registering the supplied Jev callbacks on this manager."""
    if not _profile_active() or Path(__file__).resolve().parent != PROFILE_HOME / 'plugins' / 'jev-guard':
        raise RuntimeError('Host adapters may only be installed from the owning profile plugin')
    manager = ctx._manager
    if str(manager.scope_key) != str(PROFILE_HOME):
        raise RuntimeError('Plugin manager is not scoped to the owning profile')
    allowed_hooks = {'pre_tool_call', 'pre_tool_execution', 'post_tool_call', 'pre_llm_call', 'post_approval_decision'}
    if (not {'pre_tool_call', 'pre_tool_execution'}.issubset(policy_callbacks) or
            not set(policy_callbacks).issubset(allowed_hooks) or
            not all(callable(cb) for cb in policy_callbacks.values())):
        raise ValueError('Both Jev policy callbacks and only supported Jev observer callbacks are required')
    _register_write(ctx)
    _install_ordered_batches(ctx)
    original = manager._run_hook_callback_bounded
    original_invoke = manager._invoke_hook_callback
    adapter = _ManagerAdapter(manager, policy_callbacks, original, original_invoke)

    def bounded(self, hook_name, cb, kwargs, timeout):
        return adapter.bounded(hook_name, cb, kwargs, timeout)

    def invoke(self, callback, payload):
        return adapter.invoke(callback, payload)

    patch_attribute(ctx, manager, '_run_hook_callback_bounded', types.MethodType(bounded, manager))
    patch_attribute(ctx, manager, '_invoke_hook_callback', types.MethodType(invoke, manager))
    patch_attribute(ctx, manager, '_jev_host_adapter', adapter)
    ctx.on_unload(adapter.retire)
    _record('host_adapter_installed', hooks=sorted(policy_callbacks), write_modes=sorted(_MODES))
    return adapter
