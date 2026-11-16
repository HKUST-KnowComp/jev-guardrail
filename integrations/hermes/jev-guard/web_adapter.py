"""Profile-scoped web adapters with explicit, bounded disk effects."""
import asyncio
import copy
import codecs
import hashlib
import inspect
import json
import os
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit
from pathlib import Path
from .host_patch import PROFILE_HOME, _profile_active, _record
from .core.protocol import search_request

CACHE_ROOT = PROFILE_HOME / 'cache/web/jev-guard'
MAX_STORED_CHARS = 2_000_000
MAX_DIRECT_BYTES = 4_000_000


def _urls(args):
    values = args.get('urls')
    if not isinstance(values, list) or not 1 <= len(values) <= 5 or any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError('web_extract requires one to five explicit URLs')
    from tools.url_safety import normalize_url_for_request
    return [normalize_url_for_request(v.strip()) for v in values]


def _prefer_direct(url):
    # Routing preference only. The native gate, SSRF and website policies must
    # already allow this URL; a .cn suffix never grants permission.
    return (urlsplit(url).hostname or '').lower().rstrip('.').endswith('.cn')


class _PageText(HTMLParser):
    """Extract server-supplied text without executing scripts or fetching assets."""
    _hidden = frozenset({'script', 'style', 'noscript', 'svg', 'template'})
    _blocks = frozenset({'p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3', 'h4',
                         'article', 'section', 'header', 'footer', 'nav', 'main'})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.title = [], []
        self.hidden = 0
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self._hidden:
            self.hidden += 1
        if tag == 'title':
            self.in_title = True
        if not self.hidden and tag in self._blocks:
            self.parts.append('\n')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in self._hidden and self.hidden:
            self.hidden -= 1
        if tag == 'title':
            self.in_title = False
        if not self.hidden and tag in self._blocks:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            (self.title if self.in_title else self.parts).append(data)

    def text(self):
        lines = [re.sub(r'[ \t\f\v]+', ' ', line).strip()
                 for line in ''.join(self.parts).splitlines()]
        return re.sub(r'\n{3,}', '\n\n', '\n'.join(lines)).strip()


async def _direct_extract(url, *, use_environment=False):
    import httpx
    from tools.url_safety import create_ssrf_safe_async_client
    # A new client per URL shares no cookies. Direct connections retain Hermes'
    # connect-time DNS/IP validation and normal TLS certificate verification.
    async with asyncio.timeout(25):
        async with create_ssrf_safe_async_client(
                trust_env=use_environment, follow_redirects=False,
                timeout=httpx.Timeout(12.0, connect=7.0),
                headers={'User-Agent': 'Hermes-Polarbear-WebReader',
                         'Accept': 'text/html, application/xhtml+xml, text/plain'}) as client:
            async with client.stream('GET', url) as response:
                status = response.status_code
                if 300 <= status < 400:
                    raise ValueError('HTTP redirect was not followed; its target needs a separately reviewed tool call')
                response.raise_for_status()
                media = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
                if media not in ('text/html', 'application/xhtml+xml', 'text/plain'):
                    raise ValueError('Direct extraction supports HTML or plain text only: ' + media)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_DIRECT_BYTES:
                        raise ValueError('Direct response exceeds the 4 MB body limit')
                    body.extend(chunk)
                declared = re.search(rb'charset\s*=\s*["\']?\s*([A-Za-z0-9._-]+)', bytes(body[:8192]), re.I)
                encoding = response.charset_encoding or (declared.group(1).decode('ascii') if declared else 'utf-8')
                if encoding.lower().replace('_', '-') in ('gb2312', 'gbk', 'gb-2312'):
                    encoding = 'gb18030'
                codecs.lookup(encoding)
                decoded = bytes(body).decode(encoding)
    title = ''
    if media != 'text/plain':
        parser = _PageText()
        parser.feed(decoded)
        parser.close()
        title = ' '.join(''.join(parser.title).split())
        decoded = parser.text()
    if not decoded.strip():
        raise ValueError('The direct response contained no extractable text')
    return {'url': url, 'title': title, 'content': decoded, 'error': None,
            'fetch_transport': 'configured_environment' if use_environment else 'direct', 'http_status': status,
            'response_bytes': len(body), 'response_body_complete': True,
            'content_format': 'plain_text', 'javascript_executed': False,
            'redirects_followed': False, 'complete': False}



async def _read_origin(url, ids):
    import httpx
    try:
        return await _direct_extract(url)
    except httpx.ConnectTimeout:
        # A connect timeout precedes the HTTP GET. Retry at most once, only
        # through networking already configured by the operator; do not start
        # a proxy, change environment variables, or contact an extraction API.
        if not any(os.environ.get(key) for key in (
                'HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')):
            raise
        from tools.url_safety import _resolved_http_connect_ips
        parsed = urlsplit(url)
        await asyncio.to_thread(_resolved_http_connect_ips, parsed.hostname,
            parsed.port or (443 if parsed.scheme == 'https' else 80), parsed.scheme)
        _record('web_extract_network_retry', **ids, url=url,
            failed_route='direct', reason='connect_timeout', route='configured_environment')
        try:
            result = await _direct_extract(url, use_environment=True)
        except Exception as exc:
            result = {'url':url, 'title':'', 'content':'',
                'error':'Origin webpage read failed: '+type(exc).__name__+': '+str(exc)[:300],
                'fetch_transport':'configured_environment'}
        result['direct_connect_timeout'] = True
        return result


def web_effect_contract(args, context=None):
    context = context or {}
    effects, files, temporary, uncertainties = [], [], [], []
    try:
        urls = _urls(args)
        sid, call = context.get('session_id'), context.get('jev_tool_call_id')
        if not sid or not call:
            raise ValueError('Missing native web call identity')
        for index, url in enumerate(urls):
            key = hashlib.sha256(json.dumps([sid, call, index, url], ensure_ascii=False).encode()).hexdigest()
            path = str(CACHE_ROOT / (key + '.md'))
            tmp = str(CACHE_ROOT / (key + '.part'))
            files.append(path); temporary.append(tmp)
            effects.extend([{'kind':'network', 'url':url, 'operation':'read', 'method':'GET' if _prefer_direct(url) else None,
                'transfer':False, 'transfer_mode':'none', 'source_paths':[]},
                {'kind':'write', 'path':path}, {'kind':'write', 'path':tmp}])
    except (ValueError, TypeError) as exc:
        uncertainties.append(str(exc))
    return {'source':'polarbear_web_adapter', 'effect':'web_extract', 'effects':effects,
        'complete':not uncertainties, 'uncertainties':uncertainties, 'cache_files':files,
        'cache_temporary_files':temporary, 'cache_writes_conditional_on_truncation':True,
        'shared_disk_cache_used':False, 'cache_index_used':False,
        'network_semantics':'.cn URLs GET the original site, direct first; on connection timeout only, one retry may use existing proxy environment. No redirects, scripts or asset requests. Other URLs use provider extraction with unknown downstream method.',
        'record_kind':'declared_implementation_contract'}


def _cache_dir_fd(*, create=False):
    # Walk from / using O_NOFOLLOW for EVERY component, not only the leaf.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in CACHE_ROOT.parts[1:]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd); raise


def _gate(name, args, kw):
    from tools.tool_execution_context import _EXECUTION_SCOPE, tool_args_digest
    active = _EXECUTION_SCOPE.get()
    if not _profile_active() or not active:
        raise PermissionError('Web adapter requires the owning profile native execution gate')
    # Preserve the host-owned handoff state appended by newer Hermes versions.
    tool, digest, identity, context = active[:4]
    if tool != name or digest != tool_args_digest(args) or context.get('profile_key') != str(PROFILE_HOME):
        raise PermissionError('Web call identity or reviewed arguments changed')
    if context.get('backend') != 'local' or context.get('context_known') is not True:
        raise PermissionError('Web cache adapter currently requires the local backend')
    if str(kw.get('session_id') or '') != str(identity[1]):
        raise PermissionError('Web session identity mismatch')
    return {**context, 'jev_tool_call_id':identity[3]}, {
        'session_id':identity[1], 'turn_id':identity[2], 'tool_call_id':identity[3]}


def _store(content, path, temporary, ids):
    if Path(path).parent != CACHE_ROOT or Path(temporary).parent != CACHE_ROOT:
        raise PermissionError('Cache target escaped its declared directory')
    kept = content[:MAX_STORED_CHARS]
    data = kept.encode('utf-8')
    fd = _cache_dir_fd()
    file_fd = None
    try:
        # Unique call-derived names prevent cross-session reuse. Never read a cache.
        file_fd = os.open(Path(temporary).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        _record('web_cache_write_started', **ids, path=path, temporary_path=temporary)
        with os.fdopen(file_fd, 'wb') as stream:
            file_fd = None
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(Path(temporary).name, Path(path).name, src_dir_fd=fd, dst_dir_fd=fd)
        result = {'path':path, 'temporary_path':temporary, 'bytes_written':len(data),
            'sha256':hashlib.sha256(data).hexdigest(), 'stored_chars':len(kept),
            'source_chars':len(content), 'complete':len(kept)==len(content),
            'record_kind':'observed_cache_write'}
        _record('web_cache_write_completed', **ids, **result)
        return result
    finally:
        if file_fd is not None: os.close(file_fd)
        os.close(fd)


async def extract(args, **kw):
    context, ids = _gate('web_extract', args, kw)
    contract = web_effect_contract(args, context)
    if not contract['complete']: raise PermissionError('; '.join(contract['uncertainties']))
    from tools import web_tools as web
    from tools.web_tools_extract import _validate_extract_urls, _result_entry, _merge_in_order, _resolve_extract_provider
    from tools.web_tools_rescue import _rescue_eligible, _rescue_extract
    from tools.web_tools_truncate import _effective_char_limit, convert_base64_images_to_links
    from tools.website_policy import check_website_access
    from tools.interrupt import is_interrupted
    if is_interrupted(): return json.dumps({'error':'Interrupted'})
    urls = _urls(args)
    normalized, indices, fixed, blocked = _validate_extract_urls(urls)
    if blocked: return blocked
    safe, positions = [], []
    for index, url in zip(indices, normalized):
        if not await web.async_is_safe_url(url):
            fixed[index] = _result_entry(url, 'Blocked: private/internal network address')
        else:
            # Policy-check errors fail closed, rather than bypassing the check.
            denial = check_website_access(url)
            if denial:
                fixed[index] = {**_result_entry(url, str(denial)), 'blocked_by_policy':True}
            else: safe.append(url); positions.append(index)
    # Direct reads use exactly the same reviewed URL set and cache contract.
    # Never fall back to a remote provider after a direct failure.
    provider_urls, provider_positions = [], []
    for position, url in zip(positions, safe):
        if not _prefer_direct(url):
            provider_urls.append(url); provider_positions.append(position)
            continue
        _record('web_direct_extract_started', **ids, url=url, method='GET',
            proxy_used=False, redirects_followed=False, shared_disk_cache_used=False)
        try:
            row = await _read_origin(url, ids)
        except Exception as exc:
            row = {**_result_entry(url, 'Origin webpage read failed: '+type(exc).__name__+': '+str(exc)[:300]),
                'fetch_transport':'direct'}
        fixed[position] = row
        _record('web_direct_extract_returned', **ids, url=url,
            success=not bool(row.get('error')), http_status=row.get('http_status'),
            response_bytes=row.get('response_bytes'), fetch_transport=row.get('fetch_transport'), error=row.get('error'))
    safe, positions = provider_urls, provider_positions
    results = []
    if safe:
        web._ensure_web_plugins_loaded()
        provider, error = _resolve_extract_provider(web._get_extract_backend())
        if error: return error
        _record('web_provider_extract_started', **ids, urls=safe, provider=provider.name,
            shared_disk_cache_used=False, downstream_http_method=None)
        try:
            if inspect.iscoroutinefunction(provider.extract):
                results = await provider.extract(safe, format='markdown')
            else:
                results = await asyncio.to_thread(provider.extract, safe, format='markdown')
        except Exception as exc:
            if not _rescue_eligible(provider): raise
            failed = [_result_entry(url, str(exc)) for url in safe]
            results = await asyncio.to_thread(_rescue_extract, provider.name, safe, failed)
        else:
            if results and all(row.get('error') for row in results) and _rescue_eligible(provider):
                results = await asyncio.to_thread(_rescue_extract, provider.name, safe, results)
        _record('web_provider_extract_returned', **ids, provider=provider.name, result_count=len(results))
    rows = _merge_in_order(len(urls), fixed, positions, safe, results)
    limit = _effective_char_limit(args.get('char_limit'))
    returned, writes = [], []
    for index, row in enumerate(rows):
        text = convert_base64_images_to_links(row.get('raw_content') or row.get('content') or '')
        error = row.get('error')
        # Providers may return excerpts without a truncation flag. Receiving all
        # returned text does not prove that the original page was fully observed.
        upstream_complete = (row.get('complete') is True and not row.get('truncated')
            and not row.get('has_more') and not row.get('omitted_chars'))
        truncated = not error and len(text) > limit
        cache = None
        if truncated:
            try:
                cache = _store(text, contract['cache_files'][index], contract['cache_temporary_files'][index], ids)
                writes.append(cache)
            except OSError as exc:
                cache = {'error':type(exc).__name__ + ': ' + str(exc), 'complete':False}
                _record('web_cache_write_failed', **ids, path=contract['cache_files'][index], error_type=type(exc).__name__)
            footer = ('\n[TRUNCATED] Read the stored page with read_file: ' + cache['path'] +
                (' (stored copy is also truncated)' if not cache['complete'] else '')) if cache and 'path' in cache else '\n[TRUNCATED] Full text could not be stored.'
            room = max(0, limit-len(footer)-32)
            head = room*3//4; tail = room-head
            text = text[:head] + '\n[... middle omitted ...]\n' + (text[-tail:] if tail else '') + footer
        returned.append({'url':urls[index], 'title':row.get('title',''), 'content':text,
            'error':error, 'truncated':bool(truncated), 'complete':not error and not truncated and upstream_complete,
            'provider_text_complete':not error and not truncated,
            'original_page_completeness':'provider_attested' if upstream_complete else 'unknown',
            **({key:row[key] for key in ('fetch_transport','http_status','response_bytes',
                'response_body_complete','content_format','javascript_executed','redirects_followed','direct_connect_timeout')
                if key in row}),
            **({'stored_text':cache} if cache else {}),
            **({'blocked_by_policy':True} if row.get('blocked_by_policy') else {})})
    return json.dumps({'results':returned, 'host_internal_operations':{
        'record_kind':'observed_adapter_stages', 'cache_writes':writes,
        'shared_disk_cache_used':False, 'cache_index_used':False, 'declaration':contract}}, ensure_ascii=False)


async def search(args, **kw):
    _, ids = _gate('web_search', args, kw)
    from tools import web_tools as web
    from agent.web_search_registry import get_provider, get_active_search_provider
    from tools.web_tools_rescue import _rescue_eligible, _rescue_search
    from tools.tool_backend_helpers import selection_exists
    from tools.interrupt import is_interrupted
    if is_interrupted(): return json.dumps({'error':'Interrupted'})
    query, limit = search_request(args)
    web._ensure_web_plugins_loaded()
    backend = web._get_search_backend()
    provider = get_provider(backend) if backend else None
    if provider is None or not provider.supports_search():
        if provider is None and backend and selection_exists('web'):
            return json.dumps({'success':False,'error':web._strict_selection_error('search',backend)})
        provider = get_active_search_provider()
    if provider is None: return json.dumps({'success':False,'error':'No web search provider configured'})
    _record('web_provider_search_started', **ids, provider=provider.name, query=query,
        limit=limit, shared_disk_cache_used=False)
    search_call = provider.search
    if provider.name == 'exa':
        from plugins.web._common import provider_env, use_keyless
        if use_keyless('exa', provider_env('EXA_API_KEY')):
            from .exa_keyless import search as exa_search
            search_call = lambda query, limit: exa_search(query, limit, ids)
    try:
        result = await asyncio.to_thread(search_call, query, limit)
    except Exception as exc:
        if not _rescue_eligible(provider): raise
        result = await asyncio.to_thread(_rescue_search, provider.name, str(exc), query, limit)
    else:
        if not isinstance(result, dict) or type(result.get('success')) is not bool:
            raise ValueError('Search provider returned an invalid result envelope')
        if not result['success'] and _rescue_eligible(provider):
            result = await asyncio.to_thread(_rescue_search, provider.name, str(result.get('error','')), query, limit)
    if not isinstance(result, dict) or type(result.get('success')) is not bool:
        raise ValueError('Search provider returned an invalid result envelope')
    _record('web_provider_search_returned', **ids, provider=provider.name, success=result['success'])
    # Only an error-only envelope is a receipt. Failed responses containing any
    # additional payload remain task material; never discard partial results.
    failure_receipt = (set(result) == {'success', 'error'} and result['success'] is False
        and isinstance(result['error'], str) and bool(result['error'].strip()))
    return json.dumps({**result,
        'host_search':{'query':query, 'requested_limit':limit, 'dispatched_provider':provider.name,
            'evidence_kind':'provider_failure_receipt' if failure_receipt else 'provider_search_results',
            'separate_page_reads':[],
            'original_page_completeness':'unknown'},
        'host_cache':{'shared_disk_cache_used':False,'cache_writes':[]}},ensure_ascii=False)


def install(ctx):
    if not _profile_active() or str(ctx._manager.scope_key) != str(PROFILE_HOME):
        raise RuntimeError('Web adapter is restricted to the owning profile')
    fd = _cache_dir_fd(create=True); os.close(fd)
    from tools import web_tools as web
    from tools.registry import registry
    for name, handler, original_schema in (('web_extract',extract,web.WEB_EXTRACT_SCHEMA),('web_search',search,web.WEB_SEARCH_SCHEMA)):
        entry = registry.get_entry(name,scope=str(PROFILE_HOME))
        if entry is None: raise RuntimeError('Native web tool unavailable: '+name)
        schema = copy.deepcopy(original_schema)
        schema['description'] += (' 当前 profile 对.cn网页优先直连原站GET，仅连接超时时可沿用已配置网络重试一次，不调用第三方提取API、不跟随重定向、不执行脚本或请求附属资源；仅在正文截断时写入已声明的专用缓存，明确标注截断和完整性。' if name=='web_extract' else ' 当前 profile 不读写共享搜索磁盘缓存。')
        handle = ctx.register_tool(name=name,toolset=entry.toolset,schema=schema,handler=handler,
            check_fn=entry.check_fn,requires_env=entry.requires_env,is_async=True,
            description=schema['description'],emoji=entry.emoji,override=True)
        if handle is None or registry.get_entry(name,scope=str(PROFILE_HOME)).handler is not handler:
            raise RuntimeError('Profile web registration failed: '+name)
        registry.get_entry(name,scope=str(PROFILE_HOME)).max_result_size_chars=entry.max_result_size_chars
