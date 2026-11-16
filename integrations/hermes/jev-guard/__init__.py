"""Native Hermes plugin: tools are guarded here; CLI requests use jev-chat."""
import argparse
import os
import time
import webbrowser
def get_runtime():
    from .runtime import get_runtime as load_runtime
    return load_runtime()

def register(ctx):
    from .delegation import install as install_delegation, notification_type
    message_type = notification_type()
    def pre_tool(**event):
        try:return get_runtime().pre_tool(**event)
        except Exception:return {'action':'block','message':'Jev Guard is unavailable or unconfigured; tool not executed.'}
    def post_tool(**event):return get_runtime().post_tool(**event)
    def pre_execute(**event):
        try:return get_runtime().pre_execute(**event)
        except Exception:return {'action':'block','message':'Jev final authorization check failed; tool not executed.'}
    def approval(**event):return get_runtime().approval(**event)
    def pre_llm(**event):return get_runtime().pre_llm(**event)
    def scope_command(raw_args=''):
        cli=getattr(ctx._manager,'_cli_ref',None)
        if cli is None:return '请在 jev-chat 交互会话中设置权限；当前入口没有可核验的会话身份。'
        try:return get_runtime().scope_command(raw_args,cli)
        except (ValueError,OSError) as exc:return '权限未变更：'+str(exc)
    def task_command(raw_args=''):
        cli=getattr(ctx._manager,'_cli_ref',None)
        if cli is None:return '请在 jev-chat 交互会话中管理任务证据。'
        try:return get_runtime().task_command(raw_args,cli)
        except (ValueError,PermissionError) as exc:return '任务未切换：'+str(exc)
    def safety_policy(raw_args=''):
        if raw_args.strip():return 'Usage: /safety-policy'
        url=get_runtime().open_editor()
        try:webbrowser.open(url)
        except Exception:pass
        return 'Jev safety policy editor: '+url+'\nSave a revision to apply it to subsequent reviews.'
    ctx.register_hook('pre_tool_call',pre_tool);ctx.register_hook('post_tool_call',post_tool)
    ctx.register_hook('pre_tool_execution',pre_execute)
    ctx.register_hook('post_approval_decision',approval)
    ctx.register_hook('pre_llm_call',pre_llm)
    from .host_patch import install
    install(ctx,policy_callbacks={'pre_tool_call':pre_tool,'pre_tool_execution':pre_execute,
        'post_tool_call':post_tool,'pre_llm_call':pre_llm,'post_approval_decision':approval})
    from .web_adapter import install as install_web
    install_web(ctx)
    install_delegation(ctx)
    ctx.register_command('jev-scope',scope_command,description='Set or revoke the current session authorization',
        args_hint='show | workspace path | read path | file r/w/rw/rx/rwx path | send-text URL TYPE body | send-file URL TYPE path | revoke | network-read host | search-on | network-off')
    ctx.register_command('jev-task',task_command,description='Start or resume an explicit evidence task without changing permissions',
        args_hint='show | new task-name | resume task-id')
    ctx.register_command('safety-policy',safety_policy,description='Open the editable Jev rule tree')
    def setup(parser):
        # Hermes interprets a Namespace.oneshot before dispatching plugin handlers.
        # Keep a distinct destination so the request gate cannot be bypassed.
        parser.add_argument('-q','--query');parser.add_argument('-Q','--once',dest='guard_once',action='store_true')
        parser.add_argument('--resume');parser.add_argument('--model');parser.add_argument('--provider')
        parser.add_argument('--base-url');parser.add_argument('--toolsets');parser.add_argument('--max-turns',type=int,default=35)
    def handler(args):
        import cli
        import inspect
        original=cli.HermesCLI
        class GuardedCLI(original):
            def chat(self,message,images=None,voice_input=False):
                try:runtime=get_runtime();session_id=runtime.bind(self)
                except Exception:
                    from rich.panel import Panel
                    from rich.text import Text
                    self._console_print(Panel(Text('Jev intercepted a user request — assistant model not called.\n'
                        'Decision: block\nReason: Reviewer unavailable or unconfigured.\nIntercepted content:\n'+str(message)),
                        title='Jev Guard',border_style='red'))
                    return 'Jev intercepted this request; configure the reviewer with jev configure.'
                if isinstance(message,message_type) and not images:
                    try:runtime.delegation.consume_notification(message,self)
                    except PermissionError as exc:
                        return runtime.display('user_request',str(message),{'effective_decision':'block','reasons':[str(exc)]})
                    # Retain the native synthetic-message type. It is evidence
                    # for the existing human task, never a new admitted request.
                    return super().chat(message,images=images,voice_input=voice_input)
                if type(message) is not str or images:
                    return runtime.display('user_request',str(message),{'effective_decision':'block','reasons':['Text-only request gate']})
                row=runtime.request(message,session_id)
                if row['effective_decision']!='allow':
                    self._last_turn_interrupted=False;self._prompt_start_time=None;self._last_turn_finished_at=time.time()
                    # Legacy SessionDB permits a neutral resumable marker. New
                    # gateway stores own all writes and synthesize refusing
                    # methods via __getattr__; hasattr/callable cannot detect
                    # that contract. Keep those rejections in the guard audit.
                    session_db = getattr(self, '_session_db', None)
                    direct_writer = session_db is not None and callable(inspect.getattr_static(session_db, 'append_message', None))
                    if self.agent is None and session_db and direct_writer and not session_db.get_session(self.session_id):
                        marker='Jev intercepted an earlier user request before model inference. Audit: '+row['audit_id']
                        session_db.create_session(self.session_id,source='cli',model=self.model)
                        session_db.append_message(self.session_id,'assistant',content=marker)
                        self.conversation_history.append({'role':'assistant','content':marker})
                    return 'Jev intercepted this request; see audit '+row['audit_id']
                return super().chat(message,images=images,voice_input=voice_input)
        # Query triggers one-shot on legacy Hermes; newer hosts accept oneshot.
        options=dict(query=args.query,resume=args.resume,model=args.model,provider=args.provider,
            base_url=args.base_url,toolsets=args.toolsets,max_turns=args.max_turns)
        if 'oneshot' in inspect.signature(cli.main).parameters:
            options['oneshot']=args.guard_once
        elif args.guard_once and not args.query:
            raise SystemExit('--once requires --query on this Hermes release')
        cli.HermesCLI=GuardedCLI
        try:return cli.main(**options)
        finally:cli.HermesCLI=original
    ctx.register_cli_command('jev-chat','Hermes CLI with Jev pre-model and pre-tool review',setup,handler)
