import hashlib
import copy
import json
import os
import shlex
import threading
import time
from pathlib import Path
from .web_adapter import web_effect_contract, CACHE_ROOT
from .delegation import DelegationAuthority
from .client import EndpointModel
from .core.store import Store
from .core.engine import AuditEngine
from .core.explanation import explain_review, format_explanation
from .core.store import fingerprint
from .core.permissions import PermissionStore, default_scope, permission_context
from .core.request_intent import text_request_contract, contract_context
from .core.actions import describe_action, isolate_known_python, PYTHON_STARTUP_REVIEW
from .session import Session, bounded_evidence, digest
from .credential_scan import inspect_reads
from .core.constraints import matched_network_grant_ids, within, check as check_scope
from .core.protocol import validate_network_grant, validate_authorized_scope, canonical_network_host
from .host_patch import (write_effect_contract, current_policy_ticket,
    policy_ticket_valid, policy_commit_guard, ensure_policy_guard_active, observer_gaps)


_runtimes={};_lock=threading.RLock()
def profile_home():
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home()).resolve()
    except ImportError:return Path(os.environ.get('HERMES_HOME',str(Path.home()/'.hermes'))).expanduser().resolve()
def get_runtime():
    home=profile_home()
    with _lock:
        if home not in _runtimes:_runtimes[home]=Runtime(home)
        return _runtimes[home]

def resolved_action_context(event, scope=None):
    """Resolve local targets and optionally classify scoped plaintext reads locally.

    This is a final-check fence, not an OS sandbox or an atomic open guarantee.
    Unknown/remote effects are retained as uncertainties by the action parser.
    """
    context=copy.deepcopy(event.get('execution_context',{}))
    context.pop('credential_inspections',None)
    context['jev_tool_call_id']=event.get('tool_call_id','')
    if context.get('context_known') is not True or context.get('path_semantics')!='local':return context
    skill_paths=[]
    if event['tool_name']=='skill_view':
        from tools.skills_tool import resolve_skill_inspection_targets
        args=event.get('args',{})
        if args.get('inspect_only') is not True:raise ValueError('Skill inspection mode is required')
        metadata=resolve_skill_inspection_targets(args.get('name'),args.get('file_path'))
        context['skill_inspection']=metadata
        skill_paths=list(dict.fromkeys([metadata['main_path'],metadata['target_path']]))
    description=describe_action({'proposed_tool_name':event['tool_name'],
        'proposed_tool_args':event.get('args',{}),'execution_context':context,'cwd':context.get('effective_cwd'),
        'host_tool_contract':(write_effect_contract(event.get('args',{}),context) if event['tool_name']=='write_file' else
            web_effect_contract(event.get('args',{}),context) if event['tool_name']=='web_extract' else {})})
    targets={};identities={}
    for effect in description.get('effects',[])+[{'path':p} for p in skill_paths]:
        if 'path' not in effect:continue
        path=Path(effect.get('lexical_path',effect['path']))
        try:
            resolved=path.resolve();targets[str(path)]=str(resolved)
            try:
                st=resolved.stat()
                identity={'exists':True,'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode}
                if not resolved.is_dir():identity.update(size=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)
            except FileNotFoundError:identity={'exists':False}
            identities[str(resolved)]=identity
        except (OSError,RuntimeError) as exc:
            identities[str(path)]={'known':False,'error':type(exc).__name__}
            context['context_known']=False
    context['resolved_effect_paths']=targets
    context['effect_path_fingerprints']=identities
    if scope is not None:
        checked=describe_action({'proposed_tool_name':event['tool_name'],
            'proposed_tool_args':event.get('args',{}),'execution_context':context,
            'cwd':context.get('effective_cwd'),
            'host_tool_contract':write_effect_contract(event.get('args',{}),context)
                if event['tool_name']=='write_file' else {}})
        context['credential_inspections']=inspect_reads(checked,scope)
    return context

class Runtime:
    def __init__(self,home):
        self.home=home;self.directory=home/'jev-guard'
        self.directory.mkdir(parents=True,exist_ok=True)
        settings=json.loads((self.directory/'settings.json').read_text(encoding='utf-8'))
        self.settings=settings
        self.permissions=PermissionStore(self.directory/'permissions.json',default_scope(home,settings,CACHE_ROOT))
        if settings.get('ask_action','block') not in ('block','approve'):raise ValueError('Invalid ask_action')
        if settings.get('unavailable_action','block') not in ('block','approve'):raise ValueError('Invalid unavailable_action')
        self.store=Store(self.directory/'policy',Path(__file__).parent/'initial-config.json')
        self.model=EndpointModel(settings['endpoint'],self.store.read()['model'],settings.get('api_key_env','JEV_API_KEY'))
        self.engine=AuditEngine(self.store,self.model)
        self.sessions={};self.lock=threading.RLock();self.editor=None
        self.delegation=DelegationAuthority(self)
    def bind(self,cli):
        sid=str(getattr(cli,'session_id','') or '')
        if not sid:raise ValueError('Native session identity is required')
        with self.lock:
            session=self.session(sid)
            session.cli=cli
        return sid
    def default_scope(self):
        return copy.deepcopy(self.permissions.read()['scope'])
    def _sync_permissions(self,session,config):
        signature=fingerprint(config)
        if session.permissions_fingerprint!=signature:
            session.scope=copy.deepcopy(config['scope'])
            session.permissions_revision=config['revision']
            session.permissions_fingerprint=signature
            session.invalidate(authorization_changed=True)
    def session(self,sid,create=True):
        if not isinstance(sid,str) or not sid:raise ValueError('Missing native session identity')
        config=self.permissions.read()
        if sid not in self.sessions and create:
            if len(self.sessions)>=128:raise ValueError('Session capacity reached; restart the guarded process')
            self.sessions[sid]=Session(sid,copy.deepcopy(config['scope']),
                permissions_revision=config['revision'],permissions_fingerprint=fingerprint(config))
        session=self.sessions.get(sid)
        if session:self._sync_permissions(session,config)
        return session
    def save_permissions(self,config,expected_revision):
        with self.lock,policy_commit_guard():
            saved=self.permissions.save(config,expected_revision)
            for session in self.sessions.values():self._sync_permissions(session,saved)
        self.log('permissions_change',{'permissions_revision':saved['revision'],
            'permissions_fingerprint':fingerprint(saved)},
            {'effective_decision':'allow','reasons':['Direct operator permission panel']})
        return saved
    def scope(self,session_id):
        with self.lock:return copy.deepcopy(self.session(session_id).scope)
    def scope_command(self,raw_args,cli):
        sid=self.bind(cli)
        parts=shlex.split(raw_args)
        operation=parts[0] if parts else 'show'
        with self.lock:
            session=self.session(sid)
            if operation=='show':
                return json.dumps({'session_id':sid,'authorization_revision':session.revision,
                    'permissions_revision':session.permissions_revision,'scope':session.scope},ensure_ascii=False,indent=2)
            scope=copy.deepcopy(session.scope)
            if operation in ('workspace','read') and len(parts)==2:
                path=Path(parts[1]).expanduser()
                if not path.is_absolute() or not path.is_dir():
                    raise ValueError('请提供本机已经存在的绝对目录路径。')
                path=str(path.resolve())
                if operation=='workspace':
                    scope=self.default_scope()
                    scope['workspace']=path
                    scope['allowed_read_roots']=[path]+scope['allowed_read_roots']
                    scope['allowed_write_roots']=[path]+scope['allowed_write_roots']
                    scope['protected_paths']=list(dict.fromkeys(
                        scope['protected_paths']+[str(Path(path)/'sources')]))
                else:
                    if path not in scope['allowed_read_roots']:
                        if len(scope['allowed_read_roots'])>=128:raise ValueError('只读授权目录已达到上限。')
                        scope['allowed_read_roots'].append(path)
                    if path not in scope['read_only_roots']:scope['read_only_roots'].append(path)
                    scope['all_permissions_revoked']=False
            elif operation=='file' and len(parts)==3:
                mode=parts[1]
                if mode not in ('r','w','rw','rx','rwx'):raise ValueError('文件权限只接受 r、w、rw、rx、rwx。')
                path=Path(parts[2]).expanduser()
                if not path.is_absolute():raise ValueError('文件授权需要绝对路径。')
                path=path.resolve()
                if path.is_dir() or not path.parent.is_dir():raise ValueError('请指定文件，且父目录必须存在。')
                if ('r' in mode or 'x' in mode) and not path.is_file():raise ValueError('读取或执行授权的文件必须存在。')
                target=str(path)
                for flag,key in (('r','allowed_read_paths'),('w','allowed_write_paths'),('x','allowed_execute_paths')):
                    values=[x for x in scope.get(key,[]) if x!=target]
                    if flag in mode:values.append(target)
                    if len(values)>128:raise ValueError('单文件授权数量已达到上限。')
                    scope[key]=values
                for key,enabled in (('read_only_paths',mode in ('r','rx')),('write_only_paths',mode=='w')):
                    values=[x for x in scope.get(key,[]) if x!=target]
                    if enabled:values.append(target)
                    scope[key]=values
                scope['all_permissions_revoked']=False
            elif operation in ('send-text','send-file') and len(parts)==4:
                url,content_type,payload=parts[1:]
                grant={'id':digest({'session':sid,'revision':session.revision+1,'args':parts}),
                    'operation':'write' if operation=='send-text' else 'transfer',
                    'url':url,'methods':['POST'],'content_type':content_type,
                    'allow_private':True,'remaining_uses':1}
                if operation=='send-text':
                    if len(payload.encode('utf-8'))>65536:raise ValueError('单次固定正文授权限制为65536字节。')
                    grant['body_sha256']=hashlib.sha256(payload.encode('utf-8')).hexdigest()
                else:
                    source=Path(payload).expanduser()
                    if not source.is_absolute() or not source.is_file():raise ValueError('发送授权需要已经存在的绝对文件路径。')
                    source=str(source.resolve())
                    grant['source_paths']=[source]
                    # An explicit send-file command authorizes reading this one source,
                    # but cannot override credential or existing write-only prohibitions.
                    if source not in scope['allowed_read_paths']:
                        if len(scope['allowed_read_paths'])>=128:raise ValueError('单文件授权数量已达到上限。')
                        scope['allowed_read_paths'].append(source)
                grant=validate_network_grant(grant)
                grants=[g for g in scope.get('network_grants',[]) if g.get('remaining_uses',0)>0]
                if len(grants)>=32:raise ValueError('待用单次发送授权已达到上限。')
                grants.append(grant);scope['network_grants']=grants
                scope['all_permissions_revoked']=False
            elif operation=='revoke' and len(parts)==1:
                # Revoke the current grants without restoring any saved defaults.
                # Re-enabling one capability must not resurrect unrelated file grants.
                scope['workspace']=None
                for access in ('read','write','execute'):
                    scope['allowed_'+access+'_roots']=[]
                    scope['allowed_'+access+'_paths']=[]
                for key in ('network_read','network_search','network_write',
                            'external_data_transfer','credential_access',
                            'source_data_modification','source_data_deletion'):
                    scope[key]='denied'
                scope['network_grants']=[];scope['allowed_network_hosts']=[]
                scope['allow_private_network']=False
                scope['all_permissions_revoked']=True
            elif operation=='network-read' and len(parts)==2:
                host=canonical_network_host(parts[1])
                scope['network_read']='allowed';scope['allowed_network_hosts']=[host]
                scope['all_permissions_revoked']=False
            elif operation=='network-off' and len(parts)==1:
                scope['network_read']='denied';scope['network_search']='denied'
                scope['network_write']='denied';scope['external_data_transfer']='denied'
                scope['allowed_network_hosts']=[];scope['network_grants']=[]
            elif operation=='search-on' and len(parts)==1:
                scope['network_search']='allowed';scope['all_permissions_revoked']=False
            else:
                return ('用法：/jev-scope show | workspace "绝对目录" | read "绝对目录" | '
                    'file r|w|rw|rx|rwx "绝对文件" | send-text URL CONTENT_TYPE "正文" | '
                    'send-file URL CONTENT_TYPE "绝对文件" | revoke | network-read 域名 | search-on | network-off')
            validate_authorized_scope(scope)
            session.scope=scope
            session.invalidate(authorization_changed=True)
            revision=session.revision
        self.log('scope_change',{'session_id':sid,'operation':operation,'authorization_revision':revision,
            'scope':scope},{'effective_decision':'allow','reasons':['Direct operator slash command']})
        return ('当前会话权限已更新；旧审批已失效。授权修订：'+str(revision)+
            '。发送授权绑定目标、POST、内容类型和正文或文件，仅可尝试一次，不允许重定向。'
            '使用 /jev-scope show 查看范围。')
    def task_command(self,raw_args,cli):
        sid=self.bind(cli)
        operation,_,value=raw_args.strip().partition(' ')
        operation=operation or 'show'
        with self.lock,policy_commit_guard():
            if sid in self.delegation.bindings:
                raise PermissionError('辅助任务不能切换用户任务边界。')
            session=self.session(sid)
            if operation=='show' and not value:
                return json.dumps({'current_task':session.task_context(),
                    'tasks':[{'task_id':task.task_id,'label':task.label,**task.coverage()}
                             for task in session.tasks.values()]},ensure_ascii=False,indent=2)
            if operation not in ('new','resume'):
                return '用法：/jev-task show | new 独立任务名称 | resume 任务ID'
            previous=session.current_task_id
            current=session.switch_task(operation,value.strip())
        self.log('task_change',{'session_id':sid,'previous_task_id':previous,**current},
            {'effective_decision':'allow','reasons':['Direct operator task boundary command']})
        return ('当前证据任务：'+current['task_id']+'（'+current['label']+'）。'
            '用户限制、权限和既有拒绝仍保留；旧待执行审批已失效。'
            '此前任务材料不用于当前任务，需重新读取或使用 /jev-task resume 恢复其证据。')
    def authority_context(self,session):
        return {'context':permission_context(session.scope)+
            '\nPermission configuration revision: '+str(session.permissions_revision)+
            '\nCurrent evidence task: '+json.dumps(session.task_context(),ensure_ascii=False)+
            ('\n'+contract_context(session.request_contract) if session.request_contract else '')}
    def pre_llm(self,**event):
        sid=event.get('session_id','')
        if not sid:return
        message=event.get('original_user_message',event.get('user_message',''))
        origin=event.get('input_origin','unknown')
        with self.lock,policy_commit_guard():
            session=self.session(sid)
            if sid in self.delegation.bindings:
                self.delegation.check(session)
                if origin!='subagent':raise PermissionError('Delegated host input origin changed')
                session.turn_id=event.get('turn_id','')
                session.delegated_goal=bounded_evidence(message,2000)
                return self.authority_context(session)
            if origin=='synthetic' and session.users and session.input_origin in ('human','host_continuation') and getattr(session.cli,'agent',None) is not None:
                session.input_origin='host_continuation'
                session.turn_id=event.get('turn_id','')
                session.continuation_material=bounded_evidence(message,2000)
                return self.authority_context(session)
            if session.direct_request_pending:
                session.direct_request_pending=False
                session.turn_id=event.get('turn_id','')
                # CLI expands @file and skill text after the direct request gate.
                # Preserve the original human request; never promote that expansion.
                if origin!='human':
                    session.input_origin=origin;session.invalidate()
                return self.authority_context(session)
            # Never upgrade scheduled/subagent/tool-origin text to a human grant.
            if origin!='human':
                session.input_origin=origin
                session.invalidate()
            elif session.turn_id!=event.get('turn_id',''):
                # Other entrypoints must provide a direct request admission first;
                # role=user alone is not evidence that composed text is user-owned.
                session.input_origin='unknown';session.invalidate()
            return self.authority_context(session)
    def log(self,stage,state,review):
        state=copy.deepcopy(state)
        for field,limit in (('user_request',8000),('previous_user_requests',16000),
                            ('proposed_tool_args',8000),('prior_observations',14000)):
            if field in state:state[field]=bounded_evidence(state[field],limit)
        review={**review,'approval_available':self.settings.get('ask_action','approve')=='approve'}
        row={'time':time.time(),'stage':stage,'state':state,'review':review,'effective_decision':review['effective_decision']}
        row['audit_id']=hashlib.sha256(json.dumps(row,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        with self.lock,(self.directory/'audit.jsonl').open('a', encoding='utf-8') as f:f.write(json.dumps(row,ensure_ascii=False,default=str)+'\n')
        return row
    def request(self,message,session_id):
        with self.lock:
            session=self.session(session_id)
            history=copy.deepcopy(session.users)
            capacity_error=None
            try:session.check_user_capacity(message)
            except ValueError as exc:capacity_error=str(exc)
            # A new direct request immediately fences in-flight old approvals,
            # including when admission of that new request is later refused.
            session.invalidate();session.input_origin='pending_review'
            session.direct_request_pending=False
            session.request_contract=None
            admission_revision=session.revision
        state={'product':'hermes_agent','stage':'user_request','user_request':message,
            'session_id':session_id,'input_origin':'human','permissions_revision':session.permissions_revision,
            'previous_user_requests':history,'authorized_scope':self.scope(session_id),'audit_context':{},
            'evidence_task':session.task_context(),
            'request_contract':text_request_contract(message)}
        if state['request_contract'] is None:
            state.pop('request_contract')
        try:
            if capacity_error:
                r={'model':self.store.read()['model'],'effective_decision':'block',
                    'error_type':'trusted_history_capacity','reasons':[capacity_error]}
            else:r=self.engine.review_request(state)
        except Exception as exc:
            r={'model':self.store.read()['model'],'effective_decision':'block',
               'error_type':'reviewer_unavailable','reasons':['Reviewer unavailable: '+type(exc).__name__]}
        row=self.log('user_request',state,r)
        admission_review=None
        if r['effective_decision']=='ask':
            if self.settings.get('ask_action','approve')=='approve':
                # A receipt approves admission only; record the outcome after the
                # revision check, without rewriting the original Jev review.
                from tools.approval import request_tool_approval, verify_tool_approval
                from tools.approval_context import (set_current_observability_context, reset_current_observability_context,
                    set_current_session_key,reset_current_session_key)
                call_id='request:'+row['audit_id'];rule_key='jev:'+call_id
                token=set_current_observability_context(session_id=session_id,tool_call_id=call_id)
                session_token=set_current_session_key(session_id)
                callback=getattr(session.cli,'_approval_callback',None) if getattr(session.cli,'_app',None) else None
                try:
                    result=request_tool_approval('jev_user_request',
                        self.display('user_request',message,r,session_id=session_id),rule_key=rule_key,
                        require_human=True,allow_session=False,allow_permanent=False,approval_callback=callback)
                    granted=result.get('approved') and verify_tool_approval(result.get('grant_id',''),
                        session_id=session_id,tool_call_id=call_id,rule_key=rule_key,consume=True)
                except Exception as exc:
                    admission_review={'effective_decision':'block','error_type':'approval_error',
                        'reasons':['Request approval failed: '+type(exc).__name__+': '+str(exc)[:240]]}
                finally:
                    reset_current_observability_context(token);reset_current_session_key(session_token)
                if admission_review is None:
                    if granted:
                        admission_review={'effective_decision':'allow',
                            'reasons':['The one-use request approval receipt was verified']}
                    else:
                        admission_review={'effective_decision':'block',
                            'error_type':'approval_invalid' if result.get('approved') else 'approval_denied',
                            'reasons':['Request approval receipt was missing, expired or invalid' if result.get('approved') else
                                'Request did not receive human approval']}
            else:
                admission_review={'effective_decision':'block','error_type':'approval_disabled',
                    'reasons':['Request requires approval, but interactive approval is disabled']}
        if (admission_review or r)['effective_decision']=='allow':
            with self.lock:
                if session.revision!=admission_revision:
                    admission_review={'effective_decision':'block','error_type':'admission_revoked',
                        'reasons':['Request or authorization changed before admission; the original review and any approval are no longer valid']}
                else:
                    session.accept_user(message)
                    session.request_contract=copy.deepcopy(state.get('request_contract'))
                    session.direct_request_hash=digest(message);session.direct_request_pending=True
                    if admission_review is not None:
                        admission_review['admission']='human_once'
        if admission_review is not None:
            # This record reports runtime admission, not a new model decision.
            r={**{key:r[key] for key in ('model','config_revision','permissions_revision') if key in r},
                'request_contract':state.get('request_contract'),**admission_review}
            row=self.log('user_request_admission',{**state,'request_audit_id':row['audit_id']},r)
        if r['effective_decision']!='allow':
            self.display('user_request_admission' if admission_review is not None else 'user_request',
                message,r,session_id=session_id)
        return row
    def requested_write_mode(self,session,event):
        args=event.get('args',{})
        mode=args.get('write_mode','default')
        if mode not in ('default','no_verify','write_only'):raise ValueError('Invalid write_mode')
        path=args.get('path','')
        cwd=event.get('execution_context',{}).get('effective_cwd')
        if not isinstance(path,str) or not isinstance(cwd,str):return mode
        target=str((Path(cwd)/path).resolve())
        if target in session.scope.get('write_only_paths',[]) or within(target,session.scope.get('write_only_roots',[])):
            return 'write_only'
        required='default'
        strength={'default':0,'no_verify':1,'write_only':2}
        for message in session.users:
            # This only narrows an action and only inspects original human input.
            # It never turns quoted text into a grant of new permissions.
            if path not in message and target not in message:continue
            if any(x in message for x in ('不要回读验证','禁止回读','不得回读','不要回读')):
                required=max((required,'no_verify'),key=lambda x:strength[x])
            if any(x in message for x in ('只写不读','仅写不读','禁止读取旧内容','不得读取旧内容','不要读取旧内容','不需要读取旧内容','不读取旧内容')):
                required=max((required,'write_only'),key=lambda x:strength[x])
        return max((mode,required),key=lambda x:strength[x])
    @staticmethod
    def denial_key(description,args):
        effects=description.get('effects',[])
        if not effects or not description.get('complete'):
            return digest({'tool':description.get('tool_name'),'args':args})
        # Keep every known effect, including reads and exact network payloads.
        # A denied composite action must not taint a different write-only action.
        # Lexical aliases are omitted only after host path resolution.
        normalized=[{k:v for k,v in effect.items() if k!='lexical_path'} for effect in effects]
        return digest(sorted(normalized,key=digest))
    @staticmethod
    def evidence_gap_key(coverage):
        return digest({key:coverage.get(key) for key in (
            'evidence_task_id','missing_task_sources','missing_task_source_count','capacity_exceeded',
            'non_authorizing_skill_gaps','host_observer_gaps','delegation_lineage')})
    def pre_tool(self,**event):
        request_contract=None
        try:
            ensure_policy_guard_active()
            if event.get('tool_name')=='skill_view' and event.get('args',{}).get('inspect_only') is not True:
                return {'action':'modify','args':{'inspect_only':True}}
            sid=event.get('session_id','');call_id=event.get('tool_call_id','')
            if not call_id:raise ValueError('Missing native tool call identity')
            with self.lock:
                session=self.session(sid,create=False)
                self.delegation.check(session)
                request_contract=copy.deepcopy(session.request_contract)
                if request_contract:
                    raise PermissionError('TEXT_ONLY_REQUEST: inline text transformation permits no tool calls')
                observer_state=observer_gaps(sid)
                if not observer_state['trusted_task_continuity']:
                    raise PermissionError('A host observer lost trusted task continuity; start a new guarded session')
                if event['tool_name']=='write_file':
                    mode=self.requested_write_mode(session,event)
                    if mode!=event.get('args',{}).get('write_mode','default'):
                        return {'action':'modify','args':{'write_mode':mode}}
            execution_context=resolved_action_context(event,self.scope(sid))
            with self.lock,policy_commit_guard():
                self.delegation.check(session)
                if session.scope.get('all_permissions_revoked') and event['tool_name'] not in ('clarify','todo_list'):
                    raise PermissionError('All execution permissions were explicitly revoked; grant scope before continuing')
                if event['tool_name']=='skill_view':
                    metadata=execution_context.get('skill_inspection')
                    if not metadata:raise ValueError('Skill target cannot be verified in this execution context')
                    root=metadata['trusted_root']
                    if sid not in self.delegation.bindings and session.scope['allowed_read_roots'] and root not in session.scope['read_only_roots']:
                        if len(session.scope['read_only_roots'])>=128:raise ValueError('Skill root capacity reached')
                        session.scope['allowed_read_roots'].append(root)
                        session.scope['read_only_roots'].append(root)
                        session.invalidate()
                scope=copy.deepcopy(session.scope);revision=session.revision
                state={'product':'hermes_agent','mode':'workspace-write','session_id':sid,
                    'turn_id':event.get('turn_id',''),'tool_call_id':call_id,
                    'user_request':session.users[-1],'previous_user_requests':copy.deepcopy(session.users[:-1]),'evidence_task':session.task_context(),
                    'trusted_history_complete':True,'input_origin':session.input_origin,'authorization_revision':revision,
                    'authorized_scope':scope,'permissions_revision':session.permissions_revision,
                    'permissions_fingerprint':session.permissions_fingerprint,'cwd':execution_context.get('effective_cwd'),
                    'execution_context':execution_context,'workspace_roots':scope['allowed_read_roots'],
                    'prior_observations':copy.deepcopy(session.task.observations),
                    'proposed_tool_name':event['tool_name'],'proposed_tool_args':copy.deepcopy(event.get('args',{})),
                    'audit_context':{},
                    'delegation_lineage':self.delegation.evidence(session),
                    'delegated_goal_untrusted':getattr(session,'delegated_goal',None),
                    'continuation_material_untrusted':getattr(session,'continuation_material',None)}
            if not state['execution_context']:raise ValueError('Missing host execution context')
            if event['tool_name']=='write_file':
                state['host_tool_contract']=write_effect_contract(event.get('args',{}),execution_context)
            if event['tool_name']=='web_extract':
                contract=web_effect_contract(event.get('args',{}),execution_context)
                state['host_tool_contract']=contract
                # Only this reviewed extraction gets its exact cache targets.
                # Other tools and future/child actions do not gain a cache write root.
                if contract['complete']:
                    state['authorized_scope']['allowed_write_paths']=list(dict.fromkeys(
                        state['authorized_scope'].get('allowed_write_paths',[])+
                        contract['cache_files']+contract['cache_temporary_files']))
            if event['tool_name']=='delegate_task':
                state['host_tool_contract']={'effect':'delegation','source':'polarbear_delegation_adapter',
                    'purpose':'Create/control native children; every child action is separately gated by parent-bounded authority. No single-use send grants are copied.'}
            if self.settings.get('tool_contracts',True) and event['tool_name'] in ('skill_view','skills_list'):
                state['host_tool_contract']={'effect':'read_only','purpose':'Inspect installed skill documentation or list its index; does not execute skill instructions.',
                    'output_trust':'untrusted documentation; not user authorization'}
                if event['tool_name']=='skill_view':
                    metadata=execution_context['skill_inspection']
                    state['host_tool_contract']['read_paths']=list(dict.fromkeys([metadata['main_path'],metadata['target_path']]))
            contracts={'clarify':'user_interaction','todo_list':'session_state'}
            if event['tool_name'] in contracts:
                state['host_tool_contract']={'effect':contracts[event['tool_name']],
                    'purpose':'Native current-session interaction/state only; cannot grant filesystem or network permissions.'}
            description=describe_action(state)
            if (event['tool_name']=='terminal' and description.get('python_isolation_required') and
                    description.get('uncertainties')==[PYTHON_STARTUP_REVIEW]):
                command=isolate_known_python(event.get('args',{}).get('command'))
                if command and command!=event.get('args',{}).get('command'):
                    return {'action':'modify','args':{'command':command}}
            deny_key=self.denial_key(description,event.get('args',{}))
            with self.lock:
                self.delegation.check(session)
                if session.revision!=revision:
                    raise PermissionError('Trusted task or authorization changed during action preparation')
                state['prior_observations']=copy.deepcopy(session.task.observations)
                state['evidence_coverage']=session.coverage(action_complete=description.get('complete',False))
                observer_state=observer_gaps(sid)
                state['evidence_coverage']['host_observer_gaps']=observer_state
                lineage=self.delegation.evidence(session)
                state['evidence_coverage']['delegation_lineage']=lineage
                if any(not x['host_observer_gaps']['complete'] or not x['parent_evidence_coverage']['actionable_complete'] for x in lineage):
                    state['evidence_coverage']['actionable_complete']=False
                if not observer_state['trusted_task_continuity']:
                    raise PermissionError('Trusted task continuity was lost during action preparation')
                if not observer_state['complete']:
                    state['evidence_coverage']['complete']=False
                    state['evidence_coverage']['actionable_complete']=False
                if self.delegation.denied(session,deny_key):
                    raise PermissionError('This effect was denied in this session; a new explicit scope grant is required before retrying')
            r=self.engine.review(state)
            ensure_policy_guard_active()
            has_effect=not description.get('complete') or any(e.get('kind') in ('write','delete','execute','network','network_search','delegation') for e in description.get('effects',[]))
            if not state['evidence_coverage']['actionable_complete'] and has_effect and r['effective_decision']=='allow':
                r['effective_decision']='ask';r.setdefault('reasons',[]).append('Relevant task evidence is incomplete; side effects require review')
            grant_ids=matched_network_grant_ids(state) if r['effective_decision']!='block' else []
            rule_key='jev:'+digest({'session':sid,'call':call_id,'revision':revision,
                'tool':event['tool_name'],'args':event.get('args',{}),'context':state['execution_context'],
                'policy':r.get('config_sha256')})
            # Persist correlation for history without retaining revoked pending grants.
            row=self.log('action',{**state,'rule_key':rule_key},r)
            with self.lock,policy_commit_guard():
                self.delegation.check(session)
                if session.revision!=revision:raise ValueError('Authorization changed during review')
                for old in [key for key,value in session.pending.items() if time.monotonic()-value['time']>300]:
                    session.pending.pop(old,None)
                if len(session.pending)>=128:raise ValueError('Too many pending operations')
                session.pending[call_id]={'tool':event['tool_name'],'args':digest(event.get('args',{})),
                    'context':digest(state['execution_context']),'revision':revision,
                    'policy':r.get('config_sha256'),'permissions_fingerprint':state['permissions_fingerprint'],
                    'permissions_revision':state['permissions_revision'],'decision':r['effective_decision'],
                    'rule_key':rule_key,'audit_id':row['audit_id'],'grant_id':None,'time':time.monotonic(),
                    'denial_key':deny_key,'network_grant_ids':grant_ids,
                    'has_effect':has_effect,'evidence_task_id':session.current_task_id,
                    'evidence_gap_key':self.evidence_gap_key(state['evidence_coverage']),
                    'host_policy_ticket':current_policy_ticket()}
            if r['effective_decision']=='allow':return {}
            message=self.display('action',state['proposed_tool_args'],r,event['tool_name'],sid)
            action='approve' if r['effective_decision']=='ask' and self.settings.get('ask_action','approve')=='approve' else 'block'
            return {'action':action,'message':message,'rule_key':rule_key,'require_human':True,
                'allow_session':False,'allow_permanent':False}
        except Exception as exc:
            r={'model':self.store.read()['model'],'effective_decision':'block',
                'error_type':('text_contract' if request_contract else
                    'authorization_denied' if isinstance(exc,PermissionError) else 'guard_precondition'),
                'request_contract':request_contract,
                'routing':{'status':'not_called'},
                'reasons':['Guard pre-action check failed: '+type(exc).__name__+': '+str(exc)[:240]]}
            self.log('action_error',{'session_id':event.get('session_id'),'tool_call_id':event.get('tool_call_id')},r)
            return {'action':'block','message':self.display('action_error',event.get('args',{}),r,event.get('tool_name'),event.get('session_id'))}
    def approval(self,**event):
        sid=event.get('session_id','');call_id=event.get('tool_call_id','')
        approval_state=dict(event)
        with self.lock,policy_commit_guard():
            session=self.session(sid,create=False) if sid else None
            pending=session.pending.get(call_id) if session else None
            if pending and event.get('rule_key')==pending['rule_key']:
                approval_state.update(action_audit_id=pending['audit_id'],proposed_tool_name=pending['tool'])
                if event.get('approved') and policy_ticket_valid(pending.get('host_policy_ticket')):
                    pending['grant_id']=event.get('grant_id')
                elif not event.get('approved'):
                    session.remember_denial(pending['denial_key'],{'call_id':call_id,'revision':session.revision})
                    pending['decision']='block'
        rule_key=str(event.get('rule_key',''))
        if rule_key.startswith('jev:'):
            if rule_key.startswith('jev:request:'):
                approval_state['request_audit_id']=rule_key[len('jev:request:'):]
            # An approval response is evidence, not proof that admission or the
            # execution gate accepted the receipt.
            self.log('approval',approval_state,{'effective_decision':'allow' if event.get('approved') else 'block',
                'reasons':[event.get('reason') or event.get('source','approval')]})
    def pre_execute(self,**event):
        sid=event.get('session_id','');call_id=event.get('tool_call_id','')
        reason=None;pending=None;consumed=[];request_contract=None
        current_scope=None;current_context=None;current_revision=None;current_permissions=None
        diagnostic_checks=[]
        try:
            ensure_policy_guard_active()
            with self.lock:
                active_session=self.session(sid,create=False) if sid else None
                request_contract=copy.deepcopy(active_session.request_contract) if active_session else None
                if request_contract:
                    raise PermissionError('TEXT_ONLY_REQUEST: inline text transformation permits no tool calls')
            # Resolve disk-backed evidence before taking the short cancellation
            # commit lock. The native tool also checks target identity on entry.
            current_context=resolved_action_context(event,self.scope(sid))
            current_policy=fingerprint(self.store.read())
            current_permissions=fingerprint(self.permissions.read())
            with self.lock,policy_commit_guard():
                session=self.session(sid,create=False) if sid else None
                self.delegation.check(session)
                if session:
                    current_scope=copy.deepcopy(session.scope)
                    current_revision=session.permissions_revision
                    current_permissions=session.permissions_fingerprint
                pending=session.pending.pop(call_id,None) if session else None
                current_coverage=session.coverage() if session else {}
                current_coverage['host_observer_gaps']=observer_gaps(sid)
                current_coverage['delegation_lineage']=self.delegation.evidence(session)
                if session and session.request_contract:
                    request_contract=copy.deepcopy(session.request_contract)
                    reason='TEXT_ONLY_REQUEST: inline text transformation permits no tool calls'
                elif not pending:reason='No matching pre-action review'
                elif not policy_ticket_valid(pending.get('host_policy_ticket')):reason='Review callback expired or was cancelled'
                elif pending['decision']=='block':reason='Action was blocked'
                elif time.monotonic()-pending['time']>300:reason='Review expired'
                elif pending['revision']!=session.revision:reason='Authorization was changed or revoked'
                elif pending['permissions_fingerprint']!=current_permissions:reason='Permission settings changed after review'
                elif pending['policy']!=current_policy:reason='Policy changed after review'
                elif pending['tool']!=event.get('tool_name') or pending['args']!=digest(event.get('args',{})):
                    reason='Tool or arguments changed after review'
                elif pending['context']!=digest(current_context):
                    reason='Execution context or file identity changed after review'
                elif self.delegation.denied(session,pending['denial_key']):reason='This effect was denied after review'
                elif not current_coverage['host_observer_gaps']['trusted_task_continuity']:reason='Trusted task observer continuity was lost'
                elif pending['has_effect'] and pending['evidence_gap_key']!=self.evidence_gap_key(current_coverage):
                    reason='Evidence coverage changed after review; the action needs a fresh review'
                elif pending['decision']=='ask':
                    from tools.approval import verify_tool_approval
                    if not pending['grant_id'] or not verify_tool_approval(pending['grant_id'],session_id=sid,
                            tool_call_id=call_id,rule_key=pending['rule_key'],consume=True,require_human=True):
                        reason='No matching live human approval receipt'
                if not reason:
                    session.track_observation(call_id)
                    grants={g['id']:g for g in session.scope.get('network_grants',[])}
                    consumed=pending.get('network_grant_ids',[])
                    if any(gid not in grants or grants[gid]['remaining_uses']!=1 for gid in consumed):
                        reason='The exact one-use network grant was already consumed or revoked'
                    else:
                        # Consume before attempting execution, even if the connection later fails.
                        for gid in consumed:grants[gid]['remaining_uses']=0
        except Exception as exc:
            reason='Execution gate failed: '+type(exc).__name__+': '+str(exc)[:160]
        if reason and current_scope is not None and current_context is not None:
            # A permission save clears pending reviews. Explain the already-blocked
            # action using the same explicit constraints and scope seen at the gate,
            # to identify revocation even if the LLM still has an earlier snapshot.
            # Diagnostics never create a grant or alter the fail-closed decision.
            try:
                diagnostic_checks=[item for item in check_scope({
                    'authorized_scope':current_scope,'proposed_tool_name':event.get('tool_name'),
                    'proposed_tool_args':event.get('args',{}),'execution_context':current_context,
                    'cwd':current_context.get('effective_cwd')}) if item['decision']=='block']
                if diagnostic_checks:
                    reason+='; '+'; '.join(item['category']+': '+item['reason'] for item in diagnostic_checks)
            except Exception as exc:
                reason+='; current restriction details unavailable ('+type(exc).__name__+')'
            reason+='; permission configuration revision at execution check: '+str(current_revision)
        gate_review={'effective_decision':'block' if reason else 'allow','scope_checks':diagnostic_checks,
            'error_type':('text_contract' if request_contract else 'execution_guard') if reason else None,
            'request_contract':request_contract,'permissions_revision':current_revision,
            'reasons':[reason] if reason else []}
        self.log('execution_gate',{'session_id':sid,'tool_call_id':call_id,
            'proposed_tool_name':event.get('tool_name'),
            'action_audit_id':pending.get('audit_id') if pending else None,
            'permissions_revision':current_revision,
            'permissions_fingerprint':current_permissions,
            'reviewed_permissions_revision':pending.get('permissions_revision') if pending else None,
            'reviewed_permissions_fingerprint':pending.get('permissions_fingerprint') if pending else None,
            'grant_id':pending.get('grant_id') if pending else None,
            'network_grant_ids':consumed if not reason else [],
            'consumed_network_grant_ids':consumed if not reason else []},
            gate_review)
        if reason:
            message='Jev local execution guard blocked this tool before execution.'
            if event.get('tool_name') in ('web_search','web_extract'):
                message+=' No request was submitted to a search or webpage provider for this tool call.'
            return {'action':'block','message':message+'\n'+format_explanation(explain_review(gate_review,'execution_gate'))}
        return {}
    def post_tool(self,**event):
        ensure_policy_guard_active()
        sid=event.get('session_id','')
        observation=dict(event)
        args=event.get('args',{})
        if event.get('tool_name')=='read_file' and isinstance(args.get('path'),str):
            cwd=event.get('execution_context',{}).get('effective_cwd')
            path=Path(args['path'])
            if path.is_absolute() or isinstance(cwd,str):
                target=str((Path(cwd)/path if not path.is_absolute() else path).resolve())
                observation['_jev_source_key']=digest({'read_path':target})
                skill_roots=[str(self.home/'skills')]+list(self.settings.get('skill_read_roots',[]))
                if within(target,skill_roots):observation['_jev_evidence_role']='installed_skill_document'
        elif event.get('tool_name') in ('skill_view','skills_list'):
            observation['_jev_evidence_role']='installed_skill_document'
        elif event.get('tool_name')=='web_search':
            result=event.get('result')
            try:result=json.loads(result) if isinstance(result,str) else result
            except (ValueError,TypeError):result=None
            search=result.get('host_search',{}) if isinstance(result,dict) else {}
            if (isinstance(result,dict) and set(result)=={'success','error','host_search','host_cache'}
                    and result.get('success') is False and isinstance(result.get('error'),str)
                    and result['error'].strip() and isinstance(search,dict)
                    and search.get('evidence_kind')=='provider_failure_receipt'
                    and search.get('query')==args.get('query')
                    and search.get('requested_limit')==args.get('limit',5)):
                # This marker is written by the gated profile adapter, not the
                # provider. Retain its error as untrusted evidence without
                # treating an error-only receipt as missing business content.
                # Every next action still undergoes scope and Jev review.
                observation['_jev_evidence_role']='host_operation_receipt'
        elif event.get('tool_name')=='write_file' and event.get('status')=='ok':
            result=event.get('result')
            try:result=json.loads(result) if isinstance(result,str) else result
            except (ValueError,TypeError):result=None
            operations=result.get('host_internal_operations',{}) if isinstance(result,dict) else {}
            if (operations.get('record_kind')=='observed_adapter_stages' and
                    operations.get('declaration',{}).get('source')=='polarbear_host_adapter'):
                observation['_jev_evidence_role']='host_operation_receipt'
        elif event.get('tool_name')=='terminal' and event.get('status')=='ok':
            described=describe_action({'proposed_tool_name':'terminal',
                'proposed_tool_args':event.get('args',{}),
                'execution_context':event.get('execution_context',{})})
            if described.get('complete') and all(e['kind'] in {'read','write'} for e in described['effects']):
                # The full command is already in the action audit. A long,
                # completely described command is not a missing tool result.
                # Its actual output remains untrusted and is still bounded in full.
                observation['_jev_args_summary']={'reviewed_command_sha256':digest(event.get('args',{})),
                    'action_audit_lookup':event.get('tool_call_id','')}
        bounded={**event,'result':bounded_evidence(event.get('result'),2000),
            'args':bounded_evidence(event.get('args',{}),2000)}
        line=json.dumps(bounded,ensure_ascii=False,default=str)+'\n'
        with self.lock,policy_commit_guard():
            session=self.session(sid,False) if sid else None
            pending=session.pending.pop(event.get('tool_call_id',''),None) if session else None
            if session and event.get('status') in ('ok','error'):
                limit=max(256,min(8000,int(self.settings.get('observation_chars',2000))))
                budget=max(1000,min(12000,int(self.settings.get('observation_total_chars',6000))))
                session.observe(observation,limit,budget,
                    task_id=pending.get('evidence_task_id') if pending else None)
        # File I/O must not hold the callback cancellation lock. A logging
        # failure/late observer is recorded by the host adapter as a gap.
        with self.lock,(self.directory/'executions.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(line)
    def display(self,stage,content,review,tool=None,session_id=None):
        routes=[x['id'] for x in review.get('routing',{}).get('leaves',[])]
        categories=list(dict.fromkeys(c for a in review.get('audits',[]) for c in a['result'].get('categories',[])))
        explanation=explain_review({**review,
            'approval_available':self.settings.get('ask_action','approve')=='approve'},stage)
        text='\n'.join(['Jev 用户请求审核结果，助手尚未响应。' if stage in ('user_request','user_request_admission') else
            'Jev 动作前置检查结果，工具尚未执行。' if stage == 'action_error' else
            'Jev 工具动作审核结果，工具尚未执行。',
            '模型：'+review.get('model','jev-v3.2-2b'),
            format_explanation(explanation),
            '分类路径（不直接决定授权）：'+(', '.join(routes) or review.get('routing',{}).get('status','未调用')),
            '材料类别：'+(', '.join(categories[:5]) or '未确定'),
            *(['工具：'+tool] if tool else []),'审核内容：',
            content if isinstance(content,str) else json.dumps(content,ensure_ascii=False,indent=2)])
        text=''.join(c for c in text if c in '\n\t' or ord(c)>=32 and ord(c)!=127)
        try:
            from rich.panel import Panel
            from rich.text import Text
            session=self.sessions.get(session_id)
            if session and session.cli:session.cli._console_print(Panel(Text(text,style='bold red'),title='Jev Guard',border_style='red'))
            else:
                from rich import print as rich_print
                rich_print(Panel(Text(text,style='bold red'),title='Jev Guard',border_style='red'))
        except Exception:
            try:print(text,flush=True)
            except Exception:pass
        return text
    def open_editor(self):
        from .editor import start_editor
        if self.editor is None:self.editor=start_editor(self)
        return self.editor
