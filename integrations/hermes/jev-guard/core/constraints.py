"""Explicit host-owned action constraints, independent of model predictions."""
import ipaddress
import posixpath
import unicodedata
from urllib.parse import urlsplit
from .actions import absolute, normalize as _norm, describe_action
from .protocol import canonical_network_url, canonical_network_host, validate_authorized_scope, validate_network_grant


def within(path, roots):
    path = _norm(path)
    return any(isinstance(r, str) and (path == _norm(r) or path.startswith(_norm(r).rstrip('/') + '/'))
               for r in roots)


def _paths(value):
    return [value] if isinstance(value, str) else [x for x in value if isinstance(x, str)] if isinstance(value, (list, tuple)) else []


def _reason(decision, category, message, *permission_keys):
    result = {'decision': decision, 'category': category, 'reason': message}
    if permission_keys:
        result['permission_keys'] = list(dict.fromkeys(permission_keys))
    return result


def _intersects(target, roots, exact, *, recursive=False):
    return (within(target, roots) or target in exact or recursive and
            any(within(path, [target]) for path in roots + exact))


def file_checks(path, cwd, scope, write=False, *, delete=False, recursive=False, execute=False):
    target = absolute(path, cwd)
    reasons = []
    name = posixpath.basename(target)
    templates = {'.env.example', '.env.sample', '.env.template', '.env.dist'}
    explicit_credentials = [absolute(p, cwd) for p in _paths(scope.get('credential_paths', []))]
    contextual_auth = name == 'auth.json' and posixpath.basename(posixpath.dirname(target)) in {
        'settings', 'client', 'service', 'credentials', 'auth', '.config', '.hermes'}
    credential = (within(target, explicit_credentials)
                  or recursive and any(within(p, [target]) for p in explicit_credentials)
                  or name == '.env' or name.startswith('.env.') and name not in templates
                  or name in {'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'credentials.json'}
                  or contextual_auth
                  or any(part in {'.aws', '.ssh', '.gnupg'} for part in target.split('/')))
    if credential and scope.get('credential_access') == 'denied':
        reasons.append(_reason('block', 'CREDENTIAL_ACCESS', 'Credential access is explicitly denied: ' + path, 'credential_access', 'credential_paths'))
    if write or delete:
        read_only = [absolute(p, cwd) for p in _paths(scope.get('read_only_roots', []))]
        read_only_paths = [absolute(p, cwd) for p in _paths(scope.get('read_only_paths', []))]
        if _intersects(target, read_only, read_only_paths, recursive=delete or recursive):
            reasons.append(_reason('block', 'READ_ONLY_SCOPE', 'Explicitly read-only target cannot be modified: ' + path, 'read_only_roots', 'read_only_paths'))
        protected = [absolute(p, cwd) for p in _paths(scope.get('protected_paths', [absolute('sources', cwd)]))]
        modification_denied = scope.get('source_data_modification', scope.get('source_data_deletion')) == 'denied'
        deletion_denied = delete and scope.get('source_data_deletion') == 'denied'
        if (modification_denied or deletion_denied) and (within(target, protected) or (delete or recursive) and any(within(p, [target]) for p in protected)):
            keys = ['protected_paths']
            if modification_denied:
                keys.append('source_data_modification' if 'source_data_modification' in scope else 'source_data_deletion')
            if deletion_denied:
                keys.append('source_data_deletion')
            reasons.append(_reason('block', 'DESTRUCTIVE_STATE', 'Explicitly protected source cannot be modified: ' + path, *keys))
    elif not execute:
        write_only = [absolute(p, cwd) for p in _paths(scope.get('write_only_roots', []))]
        write_only_paths = [absolute(p, cwd) for p in _paths(scope.get('write_only_paths', []))]
        if _intersects(target, write_only, write_only_paths, recursive=recursive):
            reasons.append(_reason('block', 'WRITE_ONLY_SCOPE', 'Explicitly write-only target cannot be read: ' + path, 'write_only_roots', 'write_only_paths'))
    operation = 'execute' if execute else 'write' if write or delete else 'read'
    roots_key, paths_key = 'allowed_' + operation + '_roots', 'allowed_' + operation + '_paths'
    roots = [absolute(p, cwd) for p in _paths(scope.get(roots_key))]
    exact = [absolute(p, cwd) for p in _paths(scope.get(paths_key))]
    if not roots and not exact and (roots_key in scope or paths_key in scope):
        reasons.append(_reason('block', 'SCOPE_REVOKED', 'File ' + operation + ' has no explicitly allowed targets: ' + path, roots_key, paths_key))
    elif roots_key not in scope and paths_key not in scope:
        reasons.append(_reason('ask', 'SCOPE_UNSPECIFIED', 'File ' + operation + ' scope has not been supplied: ' + path, roots_key, paths_key))
    elif target not in ('/dev/null', '/dev/stdout', '/dev/stderr') and not within(target, roots) and target not in exact:
        reasons.append(_reason('ask', 'OUTSIDE_WORKSPACE', 'File ' + operation + ' target crosses explicitly allowed targets: ' + path, roots_key, paths_key))
    return reasons


def _network_operation(effect):
    method = effect.get('method')
    # Only describe_action's fixed native read-tool branch emits this marker.
    # The tool's downstream HTTP method is not exposed; never invent GET.
    if (method is None and effect.get('operation') == 'read'
            and effect.get('transfer') is False and effect.get('transfer_mode') == 'none'):
        return 'read', 'none'
    if not isinstance(method, str) or not method:
        return 'unknown', 'unknown'
    mode = effect.get('transfer_mode', 'unknown' if effect.get('transfer') else 'none')
    if mode not in ('none', 'inline', 'file'):
        return 'unknown', 'unknown'
    if mode == 'file':
        return 'transfer', mode
    if mode == 'inline' or method.upper() not in ('GET', 'HEAD', 'OPTIONS'):
        return 'write', mode
    return 'read', mode


def _private_host(host):
    private = host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')) or '.' not in host
    try:
        return private or not ipaddress.ip_address(host).is_global
    except ValueError:
        # Numeric/non-canonical IP spellings are not treated as public DNS names.
        return private or all(c in '0123456789abcdefABCDEFxX.:' for c in host)


def _resolved_sources(effect, context):
    values = effect.get('source_paths')
    if not isinstance(values, list) or not values or len(values) > 32:
        return None
    resolved = context.get('resolved_effect_paths', {})
    if not isinstance(resolved, dict):
        return None
    sources = []
    for value in values:
        if not isinstance(value, str) or not value.startswith('/') or '\x00' in value:
            return None
        path = resolved.get(_norm(value), value)
        if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
            return None
        sources.append(_norm(path))
    return sorted(set(sources))


def _matching_network_grant(effect, scope, context, used):
    operation, mode = _network_operation(effect)
    if operation not in ('write', 'transfer') or effect.get('redirects_followed') is not False:
        return None
    try:
        url = canonical_network_url(effect.get('url'))
    except (ValueError, TypeError):
        return None
    content_type = effect.get('content_type')
    if not isinstance(content_type, str):
        return None
    for raw in scope.get('network_grants', []):
        grant = validate_network_grant(raw)
        if (grant['id'] in used or grant['remaining_uses'] != 1 or grant['operation'] != operation
                or grant['url'] != url or effect['method'].upper() not in grant['methods']
                or content_type.strip() != grant['content_type']):
            continue
        if operation == 'write':
            if mode not in ('none', 'inline') or effect.get('source_paths') not in (None, []):
                continue
            if effect.get('body_sha256') != grant['body_sha256']:
                continue
        else:
            if mode != 'file' or effect.get('body_sha256') is not None:
                continue
            if _resolved_sources(effect, context) != sorted(grant['source_paths']):
                continue
        if _private_host(urlsplit(url).hostname or '') and not grant['allow_private']:
            continue
        return grant
    return None


def _network_checks(effect, scope, context, used):
    reasons = []
    operation, mode = _network_operation(effect)
    try:
        url = canonical_network_url(effect.get('url'))
    except (ValueError, TypeError):
        permission = scope.get('network_read' if operation == 'read' else 'network_write',
                               scope.get('network', 'approval_required'))
        decision = 'block' if operation != 'read' or permission == 'denied' else 'ask'
        return [_reason(decision, 'NETWORK_DESTINATION', 'Network URL is unresolved or unsupported')]
    host = urlsplit(url).hostname or ''
    grant = _matching_network_grant(effect, scope, context, used)
    if grant is not None:
        # This is an explicit narrow exception made by the human scope command,
        # never a relaxation inferred from a document or a previous model answer.
        used.add(grant['id'])
        return reasons
    if operation == 'unknown':
        reasons.append(_reason('ask', 'NETWORK_PAYLOAD_UNRESOLVED', 'Network payload effects are not fully known'))
    writing = operation != 'read'
    permission_key = 'network_write' if writing else 'network_read'
    if permission_key not in scope:
        permission_key = 'network'
    permission = scope.get(permission_key, 'approval_required')
    if permission == 'denied':
        reasons.append(_reason('block', 'NETWORK_DENIED', 'Network ' + ('write' if writing else 'read') + ' is explicitly denied; no matching single-use grant', permission_key, 'network_grants'))
    elif writing:
        reasons.append(_reason('block', 'NETWORK_GRANT_REQUIRED', 'Network writes require an exact unused single-use grant', 'network_grants'))
    elif permission != 'allowed':
        reasons.append(_reason('ask', 'NETWORK_APPROVAL', 'Network operation requires explicit authorization', permission_key))
    if mode != 'none' and scope.get('external_data_transfer', 'denied') == 'denied':
        reasons.append(_reason('block', 'EXTERNAL_TRANSFER', 'External data transfer is denied without a matching single-use grant', 'external_data_transfer', 'network_grants'))
    allowed_hosts = [canonical_network_host(h) for h in _paths(scope.get('allowed_network_hosts', []))]
    if allowed_hosts and host not in allowed_hosts:
        reasons.append(_reason('ask', 'NETWORK_HOST_SCOPE', 'Network host is outside explicitly allowed hosts: ' + host, 'allowed_network_hosts'))
    if _private_host(host) and not (scope.get('allow_private_network') is True and host in allowed_hosts):
        reasons.append(_reason('ask', 'PRIVATE_NETWORK', 'Local or private network access requires separate explicit authorization', 'allow_private_network', 'allowed_network_hosts'))
    return reasons


def matched_network_grant_ids(state):
    """Identify grants to consume at the final gate; this never consumes them.

    Every write/send effect must match its own unused grant. No partial result
    is returned if even one such effect remains unresolved or out of scope.
    The caller must still enforce check(), approval bindings and file identities.
    """
    scope = state.get('authorized_scope', {})
    validate_authorized_scope(scope)
    description = describe_action(state)
    context = state.get('execution_context', {})
    if not isinstance(context, dict):
        raise ValueError('Invalid network execution context')
    used = set()
    for effect in description['effects']:
        if effect['kind'] != 'network':
            continue
        operation, _ = _network_operation(effect)
        if operation == 'read':
            continue
        if scope.get('all_permissions_revoked') is True:
            raise ValueError('All permissions were revoked')
        grant = _matching_network_grant(effect, scope, context, used)
        if grant is None:
            raise ValueError('Network write or transfer lacks an exact unused single-use grant')
        used.add(grant['id'])
    if used and not description.get('complete'):
        raise ValueError('Exact single-use sends require a completely described action')
    return sorted(used)


def check(state):
    scope = state.get('authorized_scope', {})
    args = state.get('proposed_tool_args', {})
    if not isinstance(scope, dict) or not isinstance(args, dict):
        return [_reason('block', 'INVALID_ACTION', 'Scope and tool arguments must be objects')]
    try:
        validate_authorized_scope(scope)
    except (ValueError, TypeError) as exc:
        return [_reason('block', 'INVALID_SCOPE', str(exc))]
    description = describe_action(state)
    cwd = description['cwd']
    context = state.get('execution_context', {})
    if not isinstance(context, dict):
        return [_reason('block', 'INVALID_ACTION', 'Execution context must be an object')]
    reasons = []
    used_network_grants = set()
    if scope.get('credential_access') == 'denied':
        for record in context.get('credential_inspections', []):
            if (record.get('source') == 'polarbear_local_inspection'
                    and record.get('classification') == 'plaintext_credential_record'):
                reasons.append(_reason('block', 'CREDENTIAL_ACCESS',
                    'Local inspection identified a credential record; values were not sent to the model: ' + record['path'], 'credential_access'))
    if scope.get('all_permissions_revoked') is True and any(
            effect['kind'] not in ('user_interaction', 'session_state') for effect in description['effects']):
        reasons.append(_reason('block', 'SCOPE_REVOKED', 'All action permissions are explicitly revoked', 'all_permissions_revoked'))
    for effect in description['effects']:
        kind = effect['kind']
        if kind in ('read', 'write', 'delete', 'execute'):
            reasons.extend(file_checks(effect['path'], cwd, scope, kind in ('write', 'delete'),
                                       delete=kind == 'delete', recursive=effect.get('recursive', False),
                                       execute=kind == 'execute'))
            lexical = effect.get('lexical_path')
            if lexical and lexical != effect['path']:
                # Explicit restrictions protect a named symlink as well as its
                # resolved destination. Grants never follow lexical containment.
                reasons.extend(r for r in file_checks(lexical, cwd, scope, kind in ('write', 'delete'),
                    delete=kind == 'delete', recursive=effect.get('recursive', False), execute=kind == 'execute')
                    if r['category'] in ('CREDENTIAL_ACCESS', 'READ_ONLY_SCOPE', 'WRITE_ONLY_SCOPE', 'DESTRUCTIVE_STATE'))
        elif kind == 'network':
            reasons.extend(_network_checks(effect, scope, context, used_network_grants))
        elif kind == 'network_search':
            query = unicodedata.normalize('NFKC', str(effect.get('query', ''))).casefold()
            if any(unicodedata.normalize('NFKC', term).casefold() in query
                   for term in scope.get('blocked_search_terms', [])):
                reasons.append(_reason('block', 'SEARCH_TERM_DENIED',
                    'Search query contains a term explicitly prohibited by the operator permission settings', 'blocked_search_terms'))
            permission = scope.get('network_search', 'approval_required')
            if permission == 'denied':
                reasons.append(_reason('block', 'NETWORK_SEARCH_DENIED', 'Submission to the host search service is explicitly denied', 'network_search'))
            elif permission != 'allowed':
                reasons.append(_reason('ask', 'NETWORK_SEARCH_APPROVAL', 'Submission to the host search service requires explicit authorization', 'network_search'))
    if state.get('proposed_tool_name') == 'skill_view':
        if 'allowed_read_roots' not in scope and 'allowed_read_paths' not in scope:
            reasons.append(_reason('ask', 'SCOPE_UNSPECIFIED', 'Skill document read scope has not been supplied', 'allowed_read_roots', 'allowed_read_paths'))
        elif not _paths(scope.get('allowed_read_roots')) and not _paths(scope.get('allowed_read_paths')):
            reasons.append(_reason('block', 'SCOPE_REVOKED', 'Skill document read access is explicitly revoked', 'allowed_read_roots', 'allowed_read_paths'))
    if used_network_grants and not description.get('complete'):
        reasons.append(_reason('block', 'NETWORK_GRANT_UNRESOLVED',
            'Exact single-use sends cannot authorize additional unresolved command effects'))
    for uncertainty in description['uncertainties']:
        reasons.append(_reason('ask', 'UNRESOLVED_ACTION', uncertainty))
    unique = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return unique
