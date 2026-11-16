"""Exa keyless search compatibility, called only by the owning profile's gated adapter."""
import hashlib
import json
import re
from urllib.parse import urlsplit

from .host_patch import _profile_active, _record

MAX_RESPONSE_BYTES = 2_000_000


def _event_payloads(body):
    """SSE data fields have an optional single space and may span lines."""
    data = []
    # SSE framing recognizes CR/LF, not NEL or Unicode separators inside JSON.
    for line in re.split(r'\r\n|\r|\n', body.lstrip('\ufeff')):
        if not line:
            if data:
                yield '\n'.join(data)
                data = []
            continue
        field, _, value = line.partition(':')
        if field == 'data':
            data.append(value[1:] if value.startswith(' ') else value)
    if data:
        yield '\n'.join(data)


def _tool_texts(body):
    from plugins.web.keyless_mcp import KeylessMCPError
    stripped = body.lstrip('\ufeff').strip()
    frames = [stripped] if stripped.startswith('{') else _event_payloads(body)
    for frame in frames:
        try:
            payload = json.loads(frame)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get('jsonrpc') != '2.0':
            continue
        # Ignore notifications and other requests in the same event stream.
        if type(payload.get('id')) is not int or payload['id'] != 1:
            continue
        if 'error' in payload:
            error = payload['error']
            raise KeylessMCPError(str(error.get('message') or error) if isinstance(error, dict) else str(error))
        result = payload.get('result')
        if not isinstance(result, dict) or not isinstance(result.get('content'), list):
            raise KeylessMCPError('Exa MCP result has no content list')
        content = result['content']
        texts = [item['text'] for item in content if isinstance(item, dict)
                 and item.get('type') == 'text' and isinstance(item.get('text'), str)]
        if result.get('isError'):
            raise KeylessMCPError('\n'.join(texts) or 'Exa MCP tool call failed')
        if content and not texts:
            raise KeylessMCPError('Exa MCP result contains no supported text content')
        return texts
    raise KeylessMCPError('No matching JSON-RPC tools/call response in Exa MCP body')


def _search_rows(texts, limit):
    """Keep all text blocks and both legacy Highlights and current Text fields."""
    from plugins.web._common import web_hit
    from plugins.web.keyless_mcp import KeylessMCPError
    rows = []
    title, url, description, in_text = '', '', [], False

    def flush():
        if url:
            parsed = urlsplit(url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                raise KeylessMCPError('Exa search returned an invalid result URL')
            rows.append(web_hit(url, title, '\n'.join(description).strip(), len(rows) + 1))

    for text in texts:
        for raw in text.splitlines():
            line = raw.strip()
            label, separator, value = line.partition(':')
            if separator and label == 'Title':
                flush()
                title, url, description, in_text = value.strip(), '', [], False
            elif separator and label == 'URL':
                url, in_text = value.strip(), False
            elif separator and label in ('Highlights', 'Text', 'Content', 'Summary'):
                in_text = True
                if value.strip():
                    description.append(value.strip())
            elif separator and label in ('Published', 'Published Date', 'Author'):
                in_text = False
            elif line == '---':
                flush()
                title, url, description, in_text = '', '', [], False
            elif in_text and line:
                description.append(line)
        flush()
        title, url, description, in_text = '', '', [], False
    if not rows and any(text.strip() for text in texts):
        if not all(not text.strip() or re.fullmatch(r'No (?:search )?results(?: found)?[.!]?', text.strip(), re.I) for text in texts):
            raise KeylessMCPError('Unrecognized Exa search text format: ' + repr('\n'.join(texts)[:160]))
    return rows[:limit]


def _exa_search(query, limit, ids):
    import requests
    from plugins.web import keyless_mcp as native
    from plugins.web._common import search_ok, search_fail
    payload = {'jsonrpc':'2.0', 'id':1, 'method':'tools/call',
               'params':{'name':'web_search_exa', 'arguments':{'query':query, 'numResults':limit}}}
    headers = {'Content-Type':'application/json', 'Accept':'application/json, text/event-stream',
               'User-Agent':'hermes-agent'}
    try:
        # Keep the host's existing connection configuration; no proxy is started
        # or configured here. One request, no redirect or format-error retry.
        with requests.post(native.EXA_MCP_URL, json=payload, headers=headers,
                           timeout=native._TIMEOUT_SECONDS, stream=True, allow_redirects=False) as response:
            body = bytearray()
            for chunk in response.iter_content(65536):
                if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise native.KeylessMCPError('Exa MCP response exceeds the 2 MB limit')
                body.extend(chunk)
            text = bytes(body).decode('utf-8-sig')
            content_type = response.headers.get('Content-Type', '')
            media = content_type.split(';', 1)[0].strip().lower()
            lines = re.split(r'\r\n|\r|\n', text)
            # requests defaults text/* without charset to Latin-1. Record only
            # framing metadata so a decoder regression is visible without
            # putting untrusted page contents into host-owned event metadata.
            try:
                native_lines = len(bytes(body).decode(response.encoding or 'utf-8', errors='replace').splitlines())
            except LookupError:
                native_lines = None
            _record('exa_keyless_response', **ids, http_status=response.status_code,
                    content_type=media, response_bytes=len(body),
                    content_type_header=content_type, requests_encoding=response.encoding,
                    native_decoded_line_count=native_lines, utf8_crlf_line_count=len(lines),
                    response_sha256=hashlib.sha256(body).hexdigest(),
                    sse_data_without_space=sum(line.startswith('data:') and not line.startswith('data: ') for line in lines),
                    sse_data_with_space=sum(line.startswith('data: ') for line in lines))
            if not 200 <= response.status_code < 300:
                raise native.KeylessMCPError('HTTP ' + str(response.status_code))
            if media not in ('application/json', 'text/event-stream'):
                raise native.KeylessMCPError('Unexpected Exa MCP content type: ' + media)
            texts = _tool_texts(text)
            rows = _search_rows(texts, limit)
            _record('exa_keyless_parsed', **ids, text_blocks=len(texts), result_count=len(rows),
                    result_description_chars=[len(row['description']) for row in rows])
            return search_ok(rows)
    except (requests.RequestException, UnicodeError, native.KeylessMCPError) as exc:
        return search_fail(native._fail_msg('exa', 'search', exc))


def search(query, limit, ids):
    """Reuse the native vendor order and throttling policy without global patches."""
    if not _profile_active():
        raise PermissionError('Exa compatibility is restricted to the owning profile')
    from plugins.web import keyless_mcp as native
    from plugins.web._common import search_fail
    call = lambda vendor: (_exa_search(query, limit, ids) if vendor == 'exa'
                           else native._KEYLESS_SEARCHERS[vendor](query, limit))
    throttled = lambda result: not result.get('success') and native._is_rate_limitish(result.get('error', ''))
    order, vendor, result, exhausted = native._walk_ring('exa', 'search', call, throttled)
    if not order:
        return search_fail(native._ALL_PAID_MSG)
    if exhausted:
        result['error'] = result.get('error', '') + ' (all keyless vendors throttled: ' + ', '.join(order) + ')'
    elif result.get('success') and vendor != 'exa':
        result.setdefault('data', {})['served_by'] = vendor
    return result
