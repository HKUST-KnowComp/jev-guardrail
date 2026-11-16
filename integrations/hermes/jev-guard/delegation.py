"""Host-object-bound child authorization, restricted to the owning profile."""
import copy
import functools
import inspect
import weakref
from .host_patch import PROFILE_HOME, _profile_active, observer_gaps, _record, patch_attribute
from .session import bounded_evidence


class DelegationAuthority:
    def __init__(self, runtime):
        self.runtime = runtime
        self.bindings = {}
        self.notifications = {}

    def check(self, session, seen=None):
        """Caller holds runtime.lock; return the child-to-root authorization chain."""
        if session is None or not session.users:
            raise PermissionError('No admitted human task for this session')
        if session.input_origin in ('human', 'host_continuation') and session.session_id not in self.bindings:
            return []
        binding = self.bindings.get(session.session_id)
        if binding is None or session.input_origin != 'host_delegated':
            raise PermissionError('Auxiliary task has no verified parent authorization')
        seen = set() if seen is None else set(seen)
        if session.session_id in seen or len(seen) >= 8:
            raise PermissionError('Invalid or over-deep delegation lineage')
        seen.add(session.session_id)
        child, parent = binding['child'](), binding['parent']()
        if child is None or parent is None or getattr(child,'session_id',None)!=session.session_id:
            raise PermissionError('Delegation object identity is no longer live')
        parent_ref = getattr(child,'_delegate_parent_ref',None)
        if not callable(parent_ref) or parent_ref() is not parent or getattr(child,'_parent_session_id',None)!=binding['parent_session_id']:
            raise PermissionError('Host parent/child ownership changed')
        if getattr(parent,'session_id',None)!=binding['parent_session_id']:
            raise PermissionError('Parent session rotated; create a newly authorized child')
        ps = self.runtime.session(binding['parent_session_id'],False)
        chain = self.check(ps,seen)
        if ps.revision!=binding['parent_revision'] or ps.scope.get('all_permissions_revoked'):
            raise PermissionError('Parent authorization changed or was revoked; child authorization expired')
        if not observer_gaps(ps.session_id)['trusted_task_continuity']:
            raise PermissionError('Parent trusted-task continuity was lost')
        return [binding]+chain

    def capture(self, parent):
        sid = str(getattr(parent,'session_id','') or '')
        with self.runtime.lock:
            ps = self.runtime.session(sid,False)
            self.check(ps)
            existing = self.bindings.get(sid)
            if existing:
                actual = existing['child']()
            else:
                actual = getattr(ps.cli,'agent',None)
            if actual is not parent:
                raise PermissionError('Parent object is not the admitted native conversation')
            if ps.scope.get('all_permissions_revoked'):
                raise PermissionError('Delegation cannot restore revoked permissions')
            return sid, ps.revision

    def register(self, child, parent, captured, goal):
        sid, revision = captured
        child_sid = str(getattr(child,'session_id','') or '')
        with self.runtime.lock:
            ps = self.runtime.session(sid,False)
            self.check(ps)
            if ps.revision!=revision or not child_sid or child_sid in self.runtime.sessions:
                raise PermissionError('Delegation authorization changed during child creation')
            parent_ref = getattr(child,'_delegate_parent_ref',None)
            if not callable(parent_ref) or parent_ref() is not parent or getattr(child,'_parent_session_id',None)!=sid:
                raise PermissionError('Child was not attached to the captured native parent')
            cs = self.runtime.session(child_sid)
            cs.scope = copy.deepcopy(ps.scope)
            # Consumable receipts are never copied into multiple children.
            cs.scope['network_grants'] = []
            cs.users = copy.deepcopy(ps.users)
            cs.current_task_id = ps.current_task_id
            cs.tasks = {ps.current_task_id: copy.deepcopy(ps.task)}
            cs.denials = copy.deepcopy(ps.denials)
            cs.input_origin = 'host_delegated'
            cs.delegated_goal = bounded_evidence(str(goal),2000)
            binding = {'parent_session_id':sid,'parent_revision':revision,
                'child_session_id':child_sid,'subagent_id':str(getattr(child,'_subagent_id','')),
                'parent':weakref.ref(parent),'child':weakref.ref(child),
                'progress_identity':getattr(child,'_progress_identity_ref',{})}
            self.bindings[child_sid] = binding
        _record('delegation_authority_bound', session_id=child_sid, parent_session_id=sid,
            parent_revision=revision, subagent_id=binding['subagent_id'],
            network_grants_inherited=False, goal_is_human_authorization=False)

    def capture_notification(self, message, event):
        # The native constructor supplies this event; text alone cannot create
        # a stored object capability. Bind completion to its original revision.
        sid = str(event.get('session_key') or '')
        delegation_id = event.get('delegation_id')
        with self.runtime.lock:
            matching = [b for b in self.bindings.values() if b['parent_session_id']==sid and
                b['progress_identity'].get('delegation_id')==delegation_id]
            if event.get('type')!='async_delegation' or not delegation_id or not matching:
                return
            if len(self.notifications)>=128:
                return
            self.notifications[id(message)] = (message, copy.deepcopy(event),
                tuple((b['parent_session_id'],b['parent_revision']) for b in matching))

    def consume_notification(self, message, cli):
        with self.runtime.lock:
            saved = self.notifications.pop(id(message),None)
            if saved is None or saved[0] is not message:
                raise PermissionError('Unverified auxiliary result notification')
            _, event, parents = saved
            sid = str(getattr(cli,'session_id','') or '')
            session = self.runtime.session(sid,False)
            self.check(session)
            if not cli._owns_process_notification(event) or any(parent!=sid or revision!=session.revision for parent,revision in parents):
                raise PermissionError('Auxiliary result belongs to another or expired parent task')
            session.continuation_material=bounded_evidence(str(message),2000)
        _record('delegation_result_admitted_as_evidence', session_id=sid,
            delegation_id=event.get('delegation_id'), human_authorization=False)

    def evidence(self, session):
        chain = self.check(session)
        return [{'parent_session_id':b['parent_session_id'],'parent_revision':b['parent_revision'],
            'child_session_id':b['child_session_id'],'subagent_id':b['subagent_id'],
            'host_observer_gaps':observer_gaps(b['parent_session_id']),
            'parent_evidence_coverage':self.runtime.session(b['parent_session_id'],False).coverage()}
            for b in chain]

    def denied(self, session, key):
        chain = self.check(session)
        return key in session.denials or any(key in self.runtime.session(b['parent_session_id'],False).denials for b in chain)


def notification_type():
    from tools import process_registry_notifications as notifications
    current = getattr(notifications, 'TimelineNotification', None)
    return current if current is not None else notifications.SubagentNotification


def install(ctx):
    if not _profile_active() or str(ctx._manager.scope_key)!=str(PROFILE_HOME):
        raise RuntimeError('Delegation adapter is restricted to the owning profile')
    from tools import delegate_tool as native
    from tools import delegate_tool_child_run as child_runs
    notification_class = notification_type()
    factory_name = 'for_delegation' if hasattr(notification_class, 'for_delegation') else '__new__'
    factory_descriptor = inspect.getattr_static(notification_class, factory_name)
    original_factory = factory_descriptor.__func__
    original = native._build_child_agent
    signature = inspect.signature(original)
    original_worktree = child_runs._create_isolated_worktree

    @functools.wraps(original)
    def build(*args,**kwargs):
        if not _profile_active(): return original(*args,**kwargs)
        from .runtime import get_runtime
        runtime = get_runtime()
        values = signature.bind(*args,**kwargs).arguments
        parent = values.get('parent_agent')
        captured = runtime.delegation.capture(parent)
        if values.get('override_acp_command'):
            raise PermissionError('External ACP children have no verified local tool gates')
        child = original(*args,**kwargs)
        try:
            if getattr(child,'provider',None)=='acp' or getattr(child,'acp_command',None):
                raise PermissionError('External ACP children cannot inherit local authorization')
            runtime.delegation.register(child,parent,captured,values.get('goal',''))
        except BaseException:
            try: child.close()
            except Exception: pass
            raise
        return child
    patch_attribute(ctx, native, '_build_child_agent', build)
    # Native worktree creation happens outside the child's tool gate. Keep the
    # inherited authorized paths; do not silently create an unreviewed checkout.
    @functools.wraps(original_worktree)
    def worktree(*args,**kwargs):
        if _profile_active(): return None
        return original_worktree(*args,**kwargs)
    patch_attribute(ctx, child_runs, '_create_isolated_worktree', worktree)

    def notification_factory(cls, text, event):
        message = original_factory(cls, text, event)
        if _profile_active():
            from .runtime import get_runtime
            get_runtime().delegation.capture_notification(message,event)
        return message
    patch_attribute(ctx, notification_class, factory_name, type(factory_descriptor)(notification_factory))
    _record('delegation_adapter_installed', network_grants_inherited=False, implicit_worktrees=False)
