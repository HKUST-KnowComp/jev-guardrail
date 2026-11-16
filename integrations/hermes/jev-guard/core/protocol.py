"""Shared validation of the reviewer wire response; never repairs predictions."""
import math


def _finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, ValueError):
        return False


def _distribution(value, labels, *, normalized):
    if not isinstance(value, dict) or set(value) != set(labels):
        raise ValueError('Invalid probability label set')
    if any(not _finite_number(v) or not 0 <= v <= 1
           for v in value.values()):
        raise ValueError('Invalid probabilities: finite numbers in [0, 1] required')
    if normalized and labels and abs(math.fsum(value.values()) - 1.0) > 1e-4:
        raise ValueError('Unnormalized probabilities')


def validate_prediction(response, options, mode, safety, expected_model):
    if not isinstance(response, dict):
        raise ValueError('Prediction response must be an object')
    if mode not in ('single', 'multi', 'score') or type(safety) is not bool:
        raise ValueError('Invalid prediction request mode')
    if not isinstance(options, (list, tuple)) or any(not isinstance(x, str) or not x for x in options):
        raise ValueError('Prediction options must be nonempty strings')
    if len(set(options)) != len(options) or not options and not safety:
        raise ValueError('Duplicate or empty unsupervised options')
    if response.get('model') != expected_model or response.get('mode') != mode:
        raise ValueError('Model version/protocol mismatch')
    _distribution(response.get('probabilities'), options, normalized=mode != 'multi')
    supplied_safety = response.get('safety') is not None or response.get('safety_probs') is not None
    if safety or supplied_safety:
        if response.get('safety') not in ('safe', 'unsafe'):
            raise ValueError('Missing safety prediction')
        _distribution(response.get('safety_probs'), ('safe', 'unsafe'), normalized=True)
    if response.get('truncated') is not False:
        raise ValueError('Complete input required')
    score = response.get('score')
    if score is not None and (not _finite_number(score)):
        raise ValueError('Invalid score')
    return response


# These values are created by the trusted session command handler, never by
# interpreting a request, document, tool response, or model-generated text.
def _absolute_scope_path(value):
    import posixpath
    import re
    if (not isinstance(value, str) or not value or '\x00' in value
            or not (value.startswith('/') or re.fullmatch(r'[A-Za-z]:[/\\].*', value))):
        raise ValueError('Authorization paths must be absolute nonempty strings')
    return posixpath.normpath(value.replace('\\', '/'))


def canonical_network_host(value):
    """One exact DNS name or IP, shared by the panel, scope command and gate."""
    import ipaddress
    import re
    if (not isinstance(value, str) or not value or len(value) > 253
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)
            or any(ch in value for ch in '/\\@?#%*')):
        raise ValueError('网页域名须为单个域名或IP地址，不含协议、端口、路径或通配符。')
    host = value.lower().rstrip('.')
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('无效的网页域名。') from exc
    if (len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                              for label in host.split('.'))):
        raise ValueError('网页域名须为单个完整域名或IP地址，不含端口。')
    return host


def search_request(args):
    """Validate the exact query and limit before reviewing or dispatching it."""
    query = args.get('query')
    if not isinstance(query, str) or not query.strip() or len(query.encode('utf-8')) > 32768:
        raise ValueError('Search query must be bounded nonempty text')
    limit = args.get('limit', 5)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Search limit must be an integer from 1 to 100')
    return query, limit


def canonical_network_url(value):
    """Normalize only URL syntax; no DNS lookup or network access is performed."""
    from urllib.parse import urlsplit, urlunsplit
    if (not isinstance(value, str) or not value or len(value) > 8192
            or '\\' in value or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)):
        raise ValueError('A bounded absolute HTTP(S) URL is required')
    parts = urlsplit(value)
    host = canonical_network_host(parts.hostname or '')
    if (parts.scheme not in ('http', 'https') or not host or parts.username is not None
            or parts.password is not None or parts.fragment):
        raise ValueError('URL credentials, fragments, or unsupported schemes are not permitted')
    port = parts.port
    if port == 0:
        raise ValueError('Invalid network port')
    authority = '[' + host + ']' if ':' in host else host
    if port is not None and port != (443 if parts.scheme == 'https' else 80):
        authority += ':' + str(port)
    return urlunsplit((parts.scheme, authority, parts.path or '/', parts.query, ''))


def validate_network_grant(value):
    """Return one normalized, exact, single-use host-owned network grant."""
    import re
    if not isinstance(value, dict):
        raise ValueError('Network grant must be an object')
    allowed = {'id', 'operation', 'url', 'methods', 'content_type', 'body_sha256',
               'source_paths', 'allow_private', 'remaining_uses'}
    if set(value) - allowed:
        raise ValueError('Unknown network grant fields')
    identifier = value.get('id')
    if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', identifier):
        raise ValueError('Network grant needs a bounded unique id')
    operation = value.get('operation')
    if operation not in ('write', 'transfer'):
        raise ValueError('Network grant operation must be write or transfer')
    methods = value.get('methods')
    if (not isinstance(methods, list) or not methods or len(methods) > 8
            or any(not isinstance(method, str) or not re.fullmatch(r'[A-Z]{1,16}', method)
                   for method in methods) or len(set(methods)) != len(methods)):
        raise ValueError('Network grant needs distinct explicit HTTP methods')
    content_type = value.get('content_type')
    if (not isinstance(content_type, str) or len(content_type) > 512
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in content_type)):
        raise ValueError('Network grant needs an explicit valid Content-Type')
    private = value.get('allow_private', False)
    remaining = value.get('remaining_uses', 1)
    if type(private) is not bool or type(remaining) is not int or remaining not in (0, 1):
        raise ValueError('Network grants must be single use with an explicit private-network flag')
    sources = value.get('source_paths', [])
    if not isinstance(sources, list) or len(sources) > 32:
        raise ValueError('Network grant source paths must be a bounded list')
    sources = [_absolute_scope_path(path) for path in sources]
    if len(set(sources)) != len(sources):
        raise ValueError('Duplicate network grant source paths')
    body_hash = value.get('body_sha256')
    if operation == 'write':
        if sources or not isinstance(body_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', body_hash):
            raise ValueError('A text send must bind its exact body SHA256 and cannot include files')
    elif not sources or body_hash is not None:
        raise ValueError('A file send must bind exact source paths and cannot include inline data')
    return {'id': identifier, 'operation': operation, 'url': canonical_network_url(value.get('url')),
            'methods': list(methods), 'content_type': content_type.strip(),
            'body_sha256': body_hash, 'source_paths': sources,
            'allow_private': private, 'remaining_uses': remaining}


def validate_authorized_scope(scope):
    """Validate the permission-bearing subset without inventing any grants."""
    if not isinstance(scope, dict):
        raise ValueError('Authorization scope must be an object')
    path_keys = ('allowed_read_roots', 'allowed_write_roots', 'allowed_execute_roots',
                 'allowed_read_paths', 'allowed_write_paths', 'allowed_execute_paths',
                 'read_only_roots', 'write_only_roots', 'read_only_paths', 'write_only_paths',
                 'credential_paths', 'protected_paths')
    for key in path_keys:
        if key not in scope:
            continue
        values = scope[key]
        if not isinstance(values, list) or len(values) > 256:
            raise ValueError(key + ' must be a bounded path list')
        for path in values:
            _absolute_scope_path(path)
    for key in ('network', 'network_read', 'network_write', 'network_search',
                'external_data_transfer', 'credential_access'):
        if key in scope and scope[key] not in ('allowed', 'denied', 'approval_required'):
            raise ValueError('Invalid permission value: ' + key)
    for key in ('allow_private_network', 'all_permissions_revoked'):
        if key in scope and type(scope[key]) is not bool:
            raise ValueError(key + ' must be boolean')
    terms = scope.get('blocked_search_terms', [])
    if (not isinstance(terms, list) or len(terms) > 128 or
            any(not isinstance(term, str) or not term.strip() or len(term) > 256 for term in terms)):
        raise ValueError('Blocked search terms must be a bounded list of nonempty strings')
    hosts = scope.get('allowed_network_hosts', [])
    if not isinstance(hosts, list) or len(hosts) > 256 or any(not isinstance(h, str) or not h for h in hosts):
        raise ValueError('Allowed network hosts must be a bounded list')
    for host in hosts:
        canonical_network_host(host)
    grants = scope.get('network_grants', [])
    if not isinstance(grants, list) or len(grants) > 128:
        raise ValueError('Network grants must be a bounded list')
    validated = [validate_network_grant(grant) for grant in grants]
    ids = [grant['id'] for grant in validated]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate network grant ids')
    return scope
