import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .core.execution_policy import EFFECT_KINDS
from .core.explanation import explain_review

def _link_audit_history(rows):
    """Derive display-only links from recorded identities, never from live grants."""
    actions = {}
    for row in rows:
        state = row.get('state', {})
        identity = (state.get('session_id'), state.get('tool_call_id'))
        if row['stage'] == 'action':
            if all(identity):
                actions.setdefault(identity, []).append(row)
            continue
        if state.get('action_audit_id') or state.get('request_audit_id'):
            continue
        if row['stage'] not in ('approval', 'execution_gate', 'action_error'):
            continue
        rule_key = state.get('rule_key', '')
        if row['stage'] == 'approval' and rule_key.startswith('jev:request:'):
            row['related_audit_id'] = rule_key[len('jev:request:'):]
            continue
        candidates = actions.get(identity, []) if all(identity) else []
        basis = '会话和工具调用标识（当前读取范围内唯一匹配）'
        if rule_key:
            exact = [item for item in candidates if item['state'].get('rule_key') == rule_key]
            # Old audits have no key. Fall back only when this call has no keyed
            # reviews; a recorded mismatch must not become a guessed parent.
            if exact or any(item['state'].get('rule_key') for item in candidates):
                candidates = exact
                basis = '会话、工具调用和审批关联键'
        if len(candidates) == 1:
            row['related_audit_id'] = candidates[0]['audit_id']
            row['audit_link_note'] = '按' + basis + '关联历史；关联不代表批准有效或工具已经执行。'
        elif candidates:
            row['audit_link_note'] = '同一调用存在多条候选审核记录，无法唯一确定关联审核，未自动关联。'
        else:
            row['audit_link_note'] = '当前可读取的历史中没有可唯一关联的审核记录。'


def start_editor(runtime):
    token=secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def trusted(self,write=False):
            hosts={'127.0.0.1:'+str(self.server.server_port),'localhost:'+str(self.server.server_port)}
            origin=self.headers.get('Origin')
            return self.headers.get('Host') in hosts and (not origin or origin in {'http://'+x for x in hosts}) and (not write or secrets.compare_digest(self.headers.get('X-Router-Token',''),token))
        def reply(self,status,value,html=False):
            wire=value.encode() if html else json.dumps(value,ensure_ascii=False).encode()
            self.send_response(status);self.send_header('Content-Type','text/html; charset=utf-8' if html else 'application/json')
            self.send_header('Content-Length',str(len(wire)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers();self.wfile.write(wire)
        def do_GET(self):
            if not self.trusted():return self.reply(403,{'error':'Invalid origin/host'})
            path=urlsplit(self.path).path
            if path=='/':return self.reply(200,(Path(__file__).parent/'panel.html').read_text(encoding='utf-8'),True)
            if path=='/api/config':return self.reply(200,{'config':runtime.store.read(),'csrf':token,'execution_rule_effects':EFFECT_KINDS})
            if path=='/api/permissions':return self.reply(200,{'permissions':runtime.permissions.read(),'csrf':token})
            if path=='/api/health':
                try:return self.reply(200,runtime.model.request('/health'))
                except Exception:return self.reply(503,{'error':'Model unavailable'})
            if path=='/api/actions':
                p=runtime.directory/'audit.jsonl';rows=[]
                if p.exists():
                    with p.open('rb') as f:
                        size=f.seek(0,2);f.seek(max(0,size-1500000));lines=f.read().splitlines()
                    if size>1500000:lines=lines[1:]
                    for line in lines:
                        row=json.loads(line)
                        if row['stage'] in ('action','action_error','approval','execution_gate','user_request','user_request_admission'):
                            rows.append({**row,'task_id':row.get('state',{}).get('session_id') or 'local-session',
                                'action_id':row['audit_id'],'review_seconds':row['review'].get('review_seconds',0),
                                'explanation':explain_review(row['review'],row['stage'])})
                _link_audit_history(rows)
                return self.reply(200,rows[-60:])
            self.reply(404,{'error':'Not found'})
        def do_POST(self):
            if not self.trusted(True):return self.reply(403,{'error':'Operator token required'})
            try:
                size=int(self.headers.get('Content-Length',0))
                if not 0<size<1000000:raise ValueError('Request size out of bounds')
                data=json.loads(self.rfile.read(size))
                if self.path=='/api/config':return self.reply(200,{'config':runtime.store.save(data['config'],data['expected_revision'])})
                if self.path=='/api/permissions':return self.reply(200,{'permissions':runtime.save_permissions(data['permissions'],data['expected_revision'])})
                if self.path=='/api/preview':
                    permissions=runtime.permissions.read()
                    context={key:data.get(key,'') for key in ('governing_policy','policy_text')}
                    if any(not isinstance(value,str) or len(value)>8000 for value in context.values()):
                        raise ValueError('Preview policy context must be bounded text')
                    state={'user_request':data['message'],'proposed_tool_name':data['tool'],
                        'proposed_tool_args':data['args'],'authorized_scope':permissions['scope'],
                        'permissions_revision':permissions['revision'],'cwd':str(Path.cwd()),'audit_context':context}
                    review={**runtime.engine.review(state),
                            'approval_available':runtime.settings.get('ask_action','approve')=='approve'}
                    return self.reply(200,{**review,'explanation':explain_review(review)})
                self.reply(404,{'error':'Not found'})
            except RuntimeError as exc:self.reply(409,{'error':str(exc)})
            except (ValueError,KeyError,TypeError) as exc:self.reply(400,{'error':str(exc)})
            except Exception:self.reply(503,{'error':'Review unavailable'})
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    # Bind the background server to this explicit runtime; it never re-resolves a profile.
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return 'http://127.0.0.1:'+str(server.server_port)+'/'
