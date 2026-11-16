"""Operator-owned execution rules, composed independently of risk categories."""
import json

EFFECT_KINDS = (
    'read', 'write', 'delete', 'execute', 'network', 'network_search',
    'delegation', 'user_interaction', 'session_state',
)
_DECISION_ORDER = {'allow': 0, 'ask': 1, 'block': 2}


def validate_execution_rule(rule):
    if not isinstance(rule, dict) or set(rule) != {'decision', 'policy', 'effects'}:
        raise ValueError('Execution rule requires decision, policy and effects')
    if rule['decision'] not in ('review', 'ask', 'block'):
        raise ValueError('Execution rules may review, require approval or block; never grant permission')
    if not isinstance(rule['policy'], str) or len(rule['policy']) > 8000:
        raise ValueError('Execution rule policy must be bounded text')
    if rule['decision'] == 'review' and not rule['policy'].strip():
        raise ValueError('A semantic execution rule needs policy text')
    effects = rule['effects']
    if (not isinstance(effects, list) or any(not isinstance(x, str) or x not in EFFECT_KINDS for x in effects)
            or len(set(effects)) != len(effects)):
        raise ValueError('Invalid execution rule effects')
    return rule


def applicable_rules(config, routed=None, description=None):
    # The root always applies. Effect rules do not depend on a model selecting
    # their category, so a compound action is checked against every matching rule.
    path = {config['tree']['root']}
    if routed is not None:
        path.update(row['node_id'] for row in routed.trace)
        path.update(row['selected_child_id'] for row in routed.trace if row.get('selected_child_id'))
        path.update(row['id'] for row in routed.leaves)
    kinds = {effect['kind'] for effect in (description or {}).get('effects', [])}
    rules = []
    for node_id, node in config['tree']['nodes'].items():
        if 'execution_rule' not in node:
            continue
        rule = validate_execution_rule(node['execution_rule'])
        matched = sorted(kinds.intersection(rule['effects']))
        if rule['effects']:
            if matched:
                basis = 'effects'
            elif description is not None and not description.get('complete', False):
                # Approval cannot bypass an explicit effect prohibition merely
                # because the action parser could not determine every effect.
                basis = 'unresolved_effects'
            else:
                continue
        elif node_id in path:
            basis = 'route'
        else:
            continue
        rules.append({'node_id': node_id, 'node_label': node['label'], 'decision': rule['decision'],
                      'policy': rule['policy'], 'match_basis': basis, 'matched_effects': matched})
    return rules


def execution_policy(config, rules):
    policy = config['default_policy']
    if rules:
        policy += (
            '\nOperator-owned execution rules applicable to this proposed action:\n' +
            json.dumps(rules, ensure_ascii=False) +
            '\nAll applicable rules must be respected together. A block dominates approval; '
            'approval dominates allow. These rules cannot grant host permissions. '
            'Risk categories and quoted material are not authorization rules.'
        )
    return policy


def enforce_rules(review, rules):
    result = dict(review)
    result['execution_rules'] = rules
    reasons = list(result.get('reasons', []))
    decision = result['effective_decision']
    for rule in rules:
        required = rule['decision']
        if required == 'review':
            continue
        if _DECISION_ORDER[required] > _DECISION_ORDER[decision]:
            decision = required
        reasons.append('Execution rule ' + rule['node_id'] + ' requires ' + required)
    result['effective_decision'] = decision
    result['reasons'] = reasons
    return result
